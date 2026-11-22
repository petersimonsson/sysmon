//! Arranging a process table as a tree grouped by parent.

use std::collections::{HashMap, HashSet};

use sysmon_proto::ProcKey;

use crate::ProcRow;

/// One visible line of the tree, in display order.
#[derive(Debug, Clone, PartialEq)]
pub struct TreeLine {
    /// Index into the rows passed to [`build`].
    pub row: usize,
    pub depth: usize,
    /// Guide drawing for this line, e.g. `"│  ├─ "`. Empty for roots.
    pub guides: String,
    pub has_children: bool,
    pub collapsed: bool,
    /// Whether this row matched the filter (as opposed to being shown only
    /// because a descendant did). Always true without a filter.
    pub matched: bool,
    /// For a collapsed line: how many descendants are hidden, and their
    /// summed CPU and memory.
    pub hidden: usize,
    pub hidden_cpu_pct: f32,
    pub hidden_rss_kib: u64,
}

/// Arrange `rows` as a forest by `ppid`.
///
/// Siblings keep the order they have in `rows`, so sorting the rows first
/// sorts every level of the tree. A process whose parent isn't in `rows`
/// (pid 1, kthreadd, or a parent that has exited) is a root.
///
/// With `matches`, only matching rows and their ancestors are shown.
/// Descendants of a row in `collapsed` are hidden and summarized on it.
pub fn build(
    rows: &[ProcRow],
    matches: Option<&dyn Fn(&ProcRow) -> bool>,
    collapsed: &HashSet<ProcKey>,
) -> Vec<TreeLine> {
    let by_pid: HashMap<u32, usize> = rows
        .iter()
        .enumerate()
        .map(|(i, r)| (r.key.pid, i))
        .collect();
    let parent = |i: usize| -> Option<usize> {
        let r = &rows[i];
        by_pid.get(&r.ppid).copied().filter(|&p| p != i)
    };

    // Which rows are shown: all, or the matches plus their ancestors.
    let matched: Vec<bool> = rows.iter().map(|r| matches.is_none_or(|m| m(r))).collect();
    let mut shown = matched.clone();
    if matches.is_some() {
        for i in (0..rows.len()).filter(|&i| matched[i]) {
            let mut seen = 0;
            let mut cur = parent(i);
            while let Some(p) = cur {
                if shown[p] || seen > rows.len() {
                    break;
                }
                shown[p] = true;
                seen += 1;
                cur = parent(p);
            }
        }
    }

    let mut children: Vec<Vec<usize>> = vec![Vec::new(); rows.len()];
    let mut roots = Vec::new();
    for i in (0..rows.len()).filter(|&i| shown[i]) {
        match parent(i) {
            Some(p) if shown[p] => children[p].push(i),
            _ => roots.push(i),
        }
    }

    // Iterative depth-first walk (process trees can be deep).
    // Stack entries: (row, depth, guides for this line, guides for its children).
    let mut out = Vec::with_capacity(rows.len());
    let mut visited = vec![false; rows.len()];
    let mut stack: Vec<(usize, usize, String, String)> = Vec::new();
    // Roots in order, then anything left unvisited (only possible if the
    // parent links contain a cycle) so no row is ever dropped.
    let mut starts = roots.into_iter().chain(0..rows.len());
    loop {
        let next = stack.pop().or_else(|| {
            starts
                .by_ref()
                .find(|&r| shown[r] && !visited[r])
                .map(|r| (r, 0, String::new(), String::new()))
        });
        let Some((i, depth, guides, child_prefix)) = next else {
            break;
        };
        if std::mem::replace(&mut visited[i], true) {
            continue;
        }
        let kids = &children[i];
        let is_collapsed = !kids.is_empty() && collapsed.contains(&rows[i].key);
        let mut line = TreeLine {
            row: i,
            depth,
            guides,
            has_children: !kids.is_empty(),
            collapsed: is_collapsed,
            matched: matched[i],
            hidden: 0,
            hidden_cpu_pct: 0.0,
            hidden_rss_kib: 0,
        };
        if is_collapsed {
            let mut pending: Vec<usize> = kids.clone();
            while let Some(d) = pending.pop() {
                if std::mem::replace(&mut visited[d], true) {
                    continue;
                }
                line.hidden += 1;
                line.hidden_cpu_pct += rows[d].cpu_pct;
                line.hidden_rss_kib += rows[d].rss_kib;
                pending.extend(&children[d]);
            }
        } else {
            for (n, &k) in kids.iter().enumerate().rev() {
                let last = n + 1 == kids.len();
                stack.push((
                    k,
                    depth + 1,
                    format!("{child_prefix}{}", if last { "└─ " } else { "├─ " }),
                    format!("{child_prefix}{}", if last { "   " } else { "│  " }),
                ));
            }
        }
        out.push(line);
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    fn row(pid: u32, ppid: u32, cpu: f32) -> ProcRow {
        ProcRow {
            key: ProcKey { pid, starttime: 0 },
            ppid,
            state: 'S',
            cpu_pct: cpu,
            rss_kib: 10,
            threads: 1,
            comm: format!("p{pid}"),
            cmdline: None,
            uid: None,
            user: None,
            stale: false,
        }
    }

    fn render(rows: &[ProcRow], lines: &[TreeLine]) -> Vec<String> {
        lines
            .iter()
            .map(|l| format!("{}{}", l.guides, rows[l.row].comm))
            .collect()
    }

    //  1 ─┬─ 10 ─┬─ 100
    //     │      └─ 101
    //     └─ 11
    //  2 ─── 20
    //  50 (parent 999 not present)
    fn sample() -> Vec<ProcRow> {
        vec![
            row(1, 0, 0.0),
            row(10, 1, 1.0),
            row(100, 10, 2.0),
            row(101, 10, 3.0),
            row(11, 1, 4.0),
            row(2, 0, 0.0),
            row(20, 2, 5.0),
            row(50, 999, 6.0),
        ]
    }

    #[test]
    fn nests_children_with_guides_in_row_order() {
        let rows = sample();
        let lines = build(&rows, None, &HashSet::new());
        assert_eq!(
            render(&rows, &lines),
            [
                "p1",
                "├─ p10",
                "│  ├─ p100",
                "│  └─ p101",
                "└─ p11",
                "p2",
                "└─ p20",
                "p50",
            ]
        );
        assert_eq!(lines[2].depth, 2);
        assert!(lines[0].has_children && !lines[2].has_children);
    }

    #[test]
    fn collapsed_subtree_is_summarized() {
        let rows = sample();
        let collapsed = HashSet::from([ProcKey {
            pid: 10,
            starttime: 0,
        }]);
        let lines = build(&rows, None, &collapsed);
        assert_eq!(
            render(&rows, &lines),
            ["p1", "├─ p10", "└─ p11", "p2", "└─ p20", "p50"]
        );
        let p10 = &lines[1];
        assert!(p10.collapsed);
        assert_eq!(
            (p10.hidden, p10.hidden_cpu_pct, p10.hidden_rss_kib),
            (2, 5.0, 20)
        );
    }

    #[test]
    fn filter_keeps_ancestors_of_matches() {
        let rows = sample();
        let only_101 = |r: &ProcRow| r.key.pid == 101;
        let lines = build(&rows, Some(&only_101), &HashSet::new());
        assert_eq!(render(&rows, &lines), ["p1", "└─ p10", "   └─ p101"]);
        let matched: Vec<bool> = lines.iter().map(|l| l.matched).collect();
        assert_eq!(matched, [false, false, true]);
    }

    #[test]
    fn survives_cycles() {
        // Can't happen with real data, but must not hang or drop rows.
        let rows = vec![row(1, 2, 0.0), row(2, 1, 0.0), row(3, 3, 0.0)];
        let lines = build(&rows, None, &HashSet::new());
        let order: Vec<usize> = lines.iter().map(|l| l.row).collect();
        assert_eq!(order, [2, 0, 1]);
    }
}

//! The processes picked for the graph, each with a stable colour.

use gpui_kit::{Hsla, hsla};
use sysmon_model::SeriesTarget;
use sysmon_proto::ProcKey;

/// Most lines in one graph; beyond this colours stop being distinguishable.
pub const MAX_SERIES: usize = 8;

/// Line colour for a palette slot. Mid lightness and high saturation read on
/// both light and dark backgrounds.
pub fn color(slot: usize) -> Hsla {
    const HUES: [f32; MAX_SERIES] = [210., 25., 140., 330., 50., 265., 175., 0.];
    hsla(HUES[slot % MAX_SERIES] / 360., 0.75, 0.55, 1.0)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Picked {
    pub target: SeriesTarget,
    /// Palette slot; kept while the item stays selected.
    pub slot: usize,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Full;

#[derive(Debug, Default, Clone)]
pub struct Selection {
    items: Vec<Picked>,
    /// Last row toggled, for Shift+click ranges.
    pub anchor: Option<ProcKey>,
}

impl Selection {
    pub fn is_empty(&self) -> bool {
        self.items.is_empty()
    }

    pub fn len(&self) -> usize {
        self.items.len()
    }

    pub fn iter(&self) -> impl Iterator<Item = &Picked> {
        self.items.iter()
    }

    /// The pick for a process, whichever kind of target it was picked as.
    pub fn get(&self, key: ProcKey) -> Option<&Picked> {
        self.items.iter().find(|p| p.target.key() == key)
    }

    /// Add `target` unless its process is already picked. Returns whether
    /// anything changed.
    pub fn add(&mut self, target: SeriesTarget) -> Result<bool, Full> {
        if self.get(target.key()).is_some() {
            return Ok(false);
        }
        if self.items.len() >= MAX_SERIES {
            return Err(Full);
        }
        // The lowest free slot, so others keep their colours.
        let slot = (0..MAX_SERIES)
            .find(|s| self.items.iter().all(|p| p.slot != *s))
            .unwrap_or(0);
        self.items.push(Picked { target, slot });
        Ok(true)
    }

    pub fn remove(&mut self, key: ProcKey) -> bool {
        let before = self.items.len();
        self.items.retain(|p| p.target.key() != key);
        before != self.items.len()
    }

    /// Remove the process if picked, otherwise add it.
    pub fn toggle(&mut self, target: SeriesTarget) -> Result<(), Full> {
        self.anchor = Some(target.key());
        if !self.remove(target.key()) {
            self.add(target)?;
        }
        Ok(())
    }

    /// Add every target (a Shift+click range); stops when full.
    pub fn add_all(&mut self, targets: impl IntoIterator<Item = SeriesTarget>) -> Result<(), Full> {
        for t in targets {
            self.add(t)?;
        }
        Ok(())
    }

    pub fn clear(&mut self) {
        self.items.clear();
        self.anchor = None;
    }
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob would shadow `#[test]`.
    use super::{MAX_SERIES, Selection};
    use sysmon_model::SeriesTarget;
    use sysmon_proto::ProcKey;

    fn p(pid: u32) -> SeriesTarget {
        SeriesTarget::Process(ProcKey { pid, starttime: 0 })
    }

    #[test]
    fn colours_stay_with_their_process() {
        let mut s = Selection::default();
        s.toggle(p(1)).unwrap();
        s.toggle(p(2)).unwrap();
        s.toggle(p(3)).unwrap();
        s.toggle(p(2)).unwrap(); // remove
        assert_eq!(s.get(p(3).key()).unwrap().slot, 2);
        s.toggle(p(4)).unwrap();
        assert_eq!(s.get(p(4).key()).unwrap().slot, 1, "reuses the freed slot");
    }

    #[test]
    fn a_process_is_picked_once_whatever_the_target_kind() {
        let mut s = Selection::default();
        s.add(p(1)).unwrap();
        let subtree = SeriesTarget::Subtree(p(1).key());
        assert_eq!(s.add(subtree), Ok(false));
        s.toggle(subtree).unwrap();
        assert!(s.is_empty(), "toggling by key removes it");
    }

    #[test]
    fn capped() {
        let mut s = Selection::default();
        assert!(s.add_all((0..20).map(p)).is_err());
        assert_eq!(s.len(), MAX_SERIES);
    }
}

//! Collects the license notices of every crate linked into `sysmon-ui`, so
//! the About dialog (and `--licenses`) can show them as their licenses
//! require for binary distribution.
//!
//! `cargo metadata` gives the resolved dependency graph for the target.
//! Starting from `sysmon-ui`, only normal (not dev or build) dependencies are
//! followed, and proc-macro crates are skipped along with their own
//! dependencies, since none of that code ends up in the binary. For each
//! remaining crate, files named like LICENSE*, LICENCE*, COPYING*, NOTICE*,
//! COPYRIGHT* or UNLICENSE* anywhere in the package (which also catches
//! bundled third-party code, e.g. a vendored C library or icon set) are
//! embedded, deduplicated and zstd-compressed.
//!
//! A few crates publish no license file. For those the standard text of the
//! license they declare is used instead, marked as such: Apache-2.0 when the
//! license allows it (it needs no copyright line), otherwise MIT with the
//! authors from the crate's manifest.

use std::collections::{BTreeMap, HashMap, HashSet, VecDeque};
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::process::Command;

use serde_json::Value;

/// Files larger than this aren't license texts.
const MAX_FILE: u64 = 512 * 1024;
const MAX_DEPTH: usize = 4;
const SKIP_DIRS: &[&str] = &[
    "target",
    ".git",
    "tests",
    "test",
    "benches",
    "examples",
    "node_modules",
];
const SKIP_EXTS: &[&str] = &[
    "rs", "c", "h", "cc", "cpp", "hpp", "py", "js", "ts", "toml", "json", "yml", "yaml", "sh",
    "html", "css", "svg", "png", "jpg", "gz", "zst",
];

struct Crate {
    name: String,
    version: String,
    license: String,
    repository: String,
    /// (path within the package, index into the texts)
    files: Vec<(String, usize)>,
}

fn main() {
    let manifest_dir = PathBuf::from(std::env::var("CARGO_MANIFEST_DIR").unwrap());
    let workspace_lock = manifest_dir.join("../../Cargo.lock");
    println!("cargo:rerun-if-changed={}", workspace_lock.display());
    println!("cargo:rerun-if-changed=build.rs");
    let apache_path = manifest_dir.join("../../LICENSE-APACHE");
    println!("cargo:rerun-if-changed={}", apache_path.display());
    let apache_text = std::fs::read_to_string(&apache_path).expect("reading LICENSE-APACHE");

    let target = std::env::var("TARGET").unwrap();
    let cargo = std::env::var("CARGO").unwrap_or_else(|_| "cargo".into());
    let output = Command::new(cargo)
        .args(["metadata", "--format-version", "1", "--offline", "--locked"])
        .args(["--filter-platform", &target, "--manifest-path"])
        .arg(manifest_dir.join("Cargo.toml"))
        .output()
        .expect("running cargo metadata");
    if !output.status.success() {
        panic!(
            "cargo metadata failed; license notices can't be collected:\n{}",
            String::from_utf8_lossy(&output.stderr)
        );
    }
    let meta: Value = serde_json::from_slice(&output.stdout).expect("parsing cargo metadata");

    let packages: HashMap<&str, &Value> = meta["packages"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| (p["id"].as_str().unwrap(), p))
        .collect();
    let nodes: HashMap<&str, &Value> = meta["resolve"]["nodes"]
        .as_array()
        .unwrap()
        .iter()
        .map(|n| (n["id"].as_str().unwrap(), n))
        .collect();
    let root = packages
        .values()
        .find(|p| p["name"] == "sysmon-ui" && p["source"].is_null())
        .expect("sysmon-ui in metadata")["id"]
        .as_str()
        .unwrap();

    let is_proc_macro = |p: &Value| {
        p["targets"].as_array().unwrap().iter().any(|t| {
            t["kind"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k == "proc-macro")
        })
    };

    // Walk normal dependencies from sysmon-ui.
    let mut linked: BTreeMap<(String, String), &Value> = BTreeMap::new();
    let mut seen: HashSet<&str> = HashSet::new();
    let mut queue: VecDeque<&str> = VecDeque::from([root]);
    while let Some(id) = queue.pop_front() {
        if !seen.insert(id) {
            continue;
        }
        let pkg = packages[id];
        if id != root {
            if is_proc_macro(pkg) {
                continue;
            }
            // Our own workspace crates are covered by our own license.
            if !pkg["source"].is_null() {
                let key = (
                    pkg["name"].as_str().unwrap().to_string(),
                    pkg["version"].as_str().unwrap().to_string(),
                );
                linked.insert(key, pkg);
            }
        }
        for dep in nodes[id]["deps"].as_array().unwrap() {
            let normal = dep["dep_kinds"]
                .as_array()
                .unwrap()
                .iter()
                .any(|k| k["kind"].is_null());
            if normal {
                queue.push_back(dep["pkg"].as_str().unwrap());
            }
        }
    }

    // Collect and deduplicate texts.
    let mut texts: Vec<String> = Vec::new();
    let mut text_index: HashMap<String, usize> = HashMap::new();
    let mut crates = Vec::new();
    for pkg in linked.values() {
        let dir = Path::new(pkg["manifest_path"].as_str().unwrap())
            .parent()
            .unwrap()
            .to_path_buf();
        let mut found = Vec::new();
        find_license_files(&dir, &dir, 0, &mut found);
        found.sort();
        let mut intern = |text: String| {
            let next = texts.len();
            let idx = *text_index.entry(text.clone()).or_insert(next);
            if idx == next {
                texts.push(text);
            }
            idx
        };
        let mut files: Vec<(String, usize)> = found
            .into_iter()
            .filter_map(|(rel, path)| {
                let text = std::fs::read_to_string(&path).ok()?.replace("\r\n", "\n");
                (!text.trim().is_empty()).then(|| (rel, intern(text)))
            })
            .collect();
        if files.is_empty() {
            let license = pkg["license"].as_str().unwrap_or("");
            let authors: Vec<&str> = pkg["authors"]
                .as_array()
                .map(|a| a.iter().filter_map(|v| v.as_str()).collect())
                .unwrap_or_default();
            if license.contains("Apache-2.0") {
                files.push((
                    "standard Apache-2.0 text; the package includes no license file".into(),
                    intern(apache_text.clone()),
                ));
            } else if license.contains("MIT") {
                let holder = if authors.is_empty() {
                    format!("the {} authors", pkg["name"].as_str().unwrap())
                } else {
                    authors.join(", ")
                };
                files.push((
                    "standard MIT text; the package includes no license file".into(),
                    intern(MIT_TEMPLATE.replace("{holder}", &holder)),
                ));
            }
        }
        crates.push(Crate {
            name: pkg["name"].as_str().unwrap().into(),
            version: pkg["version"].as_str().unwrap().into(),
            license: pkg["license"].as_str().unwrap_or("(not stated)").into(),
            repository: pkg["repository"].as_str().unwrap_or("").into(),
            files,
        });
    }

    // Texts go into one compressed blob; the index is Rust source.
    let mut blob = Vec::new();
    let mut ranges = Vec::new();
    for t in &texts {
        ranges.push((blob.len(), t.len()));
        blob.extend_from_slice(t.as_bytes());
    }
    let compressed = zstd::bulk::compress(&blob, 19).expect("compressing notices");

    let out_dir = PathBuf::from(std::env::var("OUT_DIR").unwrap());
    std::fs::write(out_dir.join("notices.zst"), &compressed).unwrap();

    let mut src = String::new();
    writeln!(src, "pub const UNCOMPRESSED_LEN: usize = {};", blob.len()).unwrap();
    writeln!(
        src,
        "pub static TEXT_RANGES: &[(usize, usize)] = &{ranges:?};"
    )
    .unwrap();
    writeln!(src, "pub static CRATES: &[CrateNotice] = &[").unwrap();
    for c in &crates {
        let files: Vec<String> = c
            .files
            .iter()
            .map(|(f, i)| format!("({f:?}, {i})"))
            .collect();
        writeln!(
            src,
            "    CrateNotice {{ name: {:?}, version: {:?}, license: {:?}, repository: {:?}, files: &[{}] }},",
            c.name,
            c.version,
            c.license,
            c.repository,
            files.join(", ")
        )
        .unwrap();
    }
    writeln!(src, "];").unwrap();
    std::fs::write(out_dir.join("notices.rs"), src).unwrap();
}

const MIT_TEMPLATE: &str = "MIT License

Copyright (c) {holder}

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the \"Software\"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
";

fn find_license_files(root: &Path, dir: &Path, depth: usize, out: &mut Vec<(String, PathBuf)>) {
    let Ok(entries) = std::fs::read_dir(dir) else {
        return;
    };
    for entry in entries.flatten() {
        let path = entry.path();
        let name = entry.file_name().to_string_lossy().to_string();
        let Ok(meta) = entry.metadata() else {
            continue;
        };
        if meta.is_dir() {
            if depth < MAX_DEPTH && !SKIP_DIRS.contains(&name.as_str()) {
                find_license_files(root, &path, depth + 1, out);
            }
            continue;
        }
        let lower = name.to_lowercase();
        let ext = Path::new(&lower)
            .extension()
            .and_then(|e| e.to_str())
            .unwrap_or("");
        let licenseish = [
            "license",
            "licence",
            "copying",
            "notice",
            "copyright",
            "unlicense",
        ]
        .iter()
        .any(|p| lower.starts_with(p));
        if licenseish && !SKIP_EXTS.contains(&ext) && meta.len() <= MAX_FILE {
            let rel = path
                .strip_prefix(root)
                .unwrap_or(&path)
                .display()
                .to_string();
            out.push((rel, path));
        }
    }
}

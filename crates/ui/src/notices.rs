//! License notices: sysmon's own licenses and those of every third-party
//! crate linked into this binary (collected by `build.rs`).

use std::sync::OnceLock;

pub const NAME: &str = "sysmon";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");
pub const LICENSE: &str = "MIT OR Apache-2.0";
pub const LICENSE_MIT: &str = include_str!("../../../LICENSE-MIT");
pub const LICENSE_APACHE: &str = include_str!("../../../LICENSE-APACHE");

/// A third-party crate in this binary.
#[derive(Debug)]
pub struct CrateNotice {
    pub name: &'static str,
    pub version: &'static str,
    /// SPDX expression from its manifest.
    pub license: &'static str,
    pub repository: &'static str,
    /// (file name within the package, index into [`text`])
    pub files: &'static [(&'static str, usize)],
}

mod generated {
    use super::CrateNotice;
    include!(concat!(env!("OUT_DIR"), "/notices.rs"));
}

pub use generated::CRATES;

static BLOB: &[u8] = include_bytes!(concat!(env!("OUT_DIR"), "/notices.zst"));

fn texts() -> &'static str {
    static TEXTS: OnceLock<String> = OnceLock::new();
    TEXTS.get_or_init(|| {
        let raw = zstd::bulk::decompress(BLOB, generated::UNCOMPRESSED_LEN)
            .expect("embedded license notices are corrupt");
        String::from_utf8(raw).expect("embedded license notices are not UTF-8")
    })
}

/// One license or notice file's text.
pub fn text(index: usize) -> &'static str {
    let (start, len) = generated::TEXT_RANGES[index];
    &texts()[start..start + len]
}

/// Everything, as one plain-text document suitable for shipping next to the
/// binary (`THIRD_PARTY_LICENSES.txt`): sysmon's licenses, a list of the
/// third-party crates, then each distinct license text once with the crates
/// it applies to.
pub fn full_text() -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "{NAME} {VERSION}\n\nLicensed under {LICENSE}.\n\n{}\n\n{}\n",
        rule("MIT License (LICENSE-MIT)"),
        LICENSE_MIT.trim_end()
    ));
    out.push_str(&format!(
        "\n{}\n\n{}\n",
        rule("Apache License 2.0 (LICENSE-APACHE)"),
        LICENSE_APACHE.trim_end()
    ));

    out.push_str(&format!(
        "\n\nTHIRD-PARTY SOFTWARE\n\n{NAME} includes the following {} crates. Their license \
         texts follow the list.\n\n",
        CRATES.len()
    ));
    for c in CRATES {
        out.push_str(&format!("- {} {} ({})", c.name, c.version, c.license));
        if !c.repository.is_empty() {
            out.push_str(&format!(" {}", c.repository));
        }
        out.push('\n');
    }

    // Each text once, in order of first use, with who uses it.
    let mut order: Vec<usize> = Vec::new();
    let mut users: std::collections::HashMap<usize, Vec<String>> = Default::default();
    for c in CRATES {
        for (file, idx) in c.files {
            if !users.contains_key(idx) {
                order.push(*idx);
            }
            users
                .entry(*idx)
                .or_default()
                .push(format!("{} {} ({file})", c.name, c.version));
        }
    }
    for (n, idx) in order.iter().enumerate() {
        out.push_str(&format!(
            "\n{}\n\nUsed by:\n",
            rule(&format!("License text {} of {}", n + 1, order.len()))
        ));
        for u in &users[idx] {
            out.push_str(&format!("  {u}\n"));
        }
        out.push_str(&format!("\n{}\n", text(*idx).trim_end()));
    }
    out
}

fn rule(title: &str) -> String {
    format!("==== {title} ====")
}

#[cfg(test)]
mod tests {
    // Explicit imports: the gpui glob elsewhere would shadow `#[test]`.
    use super::{CRATES, full_text, text};

    #[test]
    fn notices_cover_the_linked_crates() {
        let names: Vec<&str> = CRATES.iter().map(|c| c.name).collect();
        for expected in [
            "gpui-kit",
            "jiff",
            "zstd-sys",
            "serde",
            "flume",
            "gpui-kit-assets",
        ] {
            assert!(names.contains(&expected), "{expected} missing");
        }
        // Workspace crates, proc macros and build-only tools aren't listed.
        for absent in ["sysmon-model", "serde_derive", "cc", "pkg-config"] {
            assert!(!names.contains(&absent), "{absent} shouldn't be listed");
        }
    }

    #[test]
    fn texts_decompress_and_include_bundled_licenses() {
        let assets = CRATES.iter().find(|c| c.name == "gpui-kit-assets").unwrap();
        assert!(
            assets.files.iter().any(|(f, _)| f.contains("LUCIDE")),
            "the icon set's license is picked up: {:?}",
            assets.files
        );
        let zstd = CRATES.iter().find(|c| c.name == "zstd-sys").unwrap();
        assert!(
            zstd.files
                .iter()
                .any(|(_, i)| text(*i).contains("Facebook"))
        );
        let all = full_text();
        assert!(all.contains("Permission is hereby granted"));
        assert!(all.contains("Apache License"));
        assert!(all.contains("\n- jiff 1."));
        // Every crate's license texts are in the document.
        for c in CRATES {
            for (_, idx) in c.files {
                assert!(all.contains(text(*idx).trim_end()));
            }
        }
    }
}

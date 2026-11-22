//! License notices: sysmon's own licenses and those of every third-party
//! crate linked into this binary (collected by `build.rs` through
//! `sysmon-notices`).

pub use sysmon_notices::{CrateNotice, LICENSE, LICENSE_APACHE, LICENSE_MIT};

pub const NAME: &str = "sysmon";
pub const VERSION: &str = env!("CARGO_PKG_VERSION");

pub static NOTICES: sysmon_notices::Notices = sysmon_notices::embed!();
pub static CRATES: &[CrateNotice] = NOTICES.crates;

/// One license or notice file's text.
pub fn text(index: usize) -> &'static str {
    NOTICES.text(index)
}

/// Everything, as one plain-text document (`--licenses`, Save all notices…).
pub fn full_text() -> String {
    NOTICES.full_text()
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

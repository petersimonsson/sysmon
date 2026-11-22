//! License notices for sysmon's binaries.
//!
//! The licenses of most crates a binary is built from (MIT, BSD, ISC, Zlib,
//! Apache-2.0, …) require their copyright notices and license texts to be
//! shipped with it. A binary's build script calls
//! `sysmon_notices_build::generate`, which collects them for exactly the
//! crates linked into that binary; the binary then embeds them with
//! [`embed!`]:
//!
//! ```ignore
//! // build.rs
//! fn main() { sysmon_notices_build::generate("sysmon-agent"); }
//!
//! // main.rs
//! static NOTICES: sysmon_notices::Notices = sysmon_notices::embed!();
//! print!("{}", NOTICES.full_text());
//! ```

use std::collections::HashMap;
use std::sync::OnceLock;

/// The license sysmon itself is under.
pub const LICENSE: &str = "MIT OR Apache-2.0";
pub const LICENSE_MIT: &str = include_str!("../../../LICENSE-MIT");
pub const LICENSE_APACHE: &str = include_str!("../../../LICENSE-APACHE");

/// A third-party crate linked into the binary.
#[derive(Debug)]
pub struct CrateNotice {
    pub name: &'static str,
    pub version: &'static str,
    /// SPDX expression from its manifest.
    pub license: &'static str,
    pub repository: &'static str,
    /// (file name within the package, text index for [`Notices::text`])
    pub files: &'static [(&'static str, usize)],
}

/// The notices embedded in one binary.
pub struct Notices {
    /// The binary's package name and version.
    pub product: &'static str,
    pub version: &'static str,
    pub crates: &'static [CrateNotice],
    text_ranges: &'static [(usize, usize)],
    blob: &'static [u8],
    uncompressed_len: usize,
    texts: OnceLock<String>,
}

impl Notices {
    #[doc(hidden)]
    pub const fn __new(
        product: &'static str,
        version: &'static str,
        crates: &'static [CrateNotice],
        text_ranges: &'static [(usize, usize)],
        blob: &'static [u8],
        uncompressed_len: usize,
    ) -> Self {
        Self {
            product,
            version,
            crates,
            text_ranges,
            blob,
            uncompressed_len,
            texts: OnceLock::new(),
        }
    }

    /// One license or notice file's text. Decompresses everything on first use.
    pub fn text(&self, index: usize) -> &str {
        let all = self.texts.get_or_init(|| {
            let raw = zstd::bulk::decompress(self.blob, self.uncompressed_len)
                .expect("embedded license notices are corrupt");
            String::from_utf8(raw).expect("embedded license notices are not UTF-8")
        });
        let (start, len) = self.text_ranges[index];
        &all[start..start + len]
    }

    /// Everything, as one plain-text document suitable for shipping next to
    /// the binary (`THIRD_PARTY_LICENSES.txt`): sysmon's licenses, a list of
    /// the third-party crates, then each distinct license text once with the
    /// crates it applies to.
    pub fn full_text(&self) -> String {
        let mut out = format!(
            "{} {}, part of sysmon\n\nLicensed under {LICENSE}.\n\n{}\n\n{}\n\n{}\n\n{}\n",
            self.product,
            self.version,
            rule("MIT License (LICENSE-MIT)"),
            LICENSE_MIT.trim_end(),
            rule("Apache License 2.0 (LICENSE-APACHE)"),
            LICENSE_APACHE.trim_end()
        );
        out.push_str(&format!(
            "\n\nTHIRD-PARTY SOFTWARE\n\n{} includes the following {} crates. Their license \
             texts follow the list.\n\n",
            self.product,
            self.crates.len()
        ));
        for c in self.crates {
            out.push_str(&format!("- {} {} ({})", c.name, c.version, c.license));
            if !c.repository.is_empty() {
                out.push_str(&format!(" {}", c.repository));
            }
            out.push('\n');
        }

        // Each text once, in order of first use, with who uses it.
        let mut order: Vec<usize> = Vec::new();
        let mut users: HashMap<usize, Vec<String>> = HashMap::new();
        for c in self.crates {
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
            out.push_str(&format!("\n{}\n", self.text(*idx).trim_end()));
        }
        out
    }

    /// Write [`Self::full_text`] to stdout. A closed pipe (`--licenses | head`)
    /// is treated as success.
    pub fn print(&self) -> std::io::Result<()> {
        use std::io::Write as _;
        match std::io::stdout().write_all(self.full_text().as_bytes()) {
            Err(e) if e.kind() != std::io::ErrorKind::BrokenPipe => Err(e),
            _ => Ok(()),
        }
    }
}

fn rule(title: &str) -> String {
    format!("==== {title} ====")
}

/// The notices collected by this crate's build script (which must call
/// `sysmon_notices_build::generate`), as a [`Notices`] value for a `static`.
#[macro_export]
macro_rules! embed {
    () => {{
        mod __sysmon_notices {
            #[allow(unused_imports)]
            use $crate::CrateNotice;
            include!(concat!(env!("OUT_DIR"), "/notices.rs"));
        }
        $crate::Notices::__new(
            env!("CARGO_PKG_NAME"),
            env!("CARGO_PKG_VERSION"),
            __sysmon_notices::CRATES,
            __sysmon_notices::TEXT_RANGES,
            include_bytes!(concat!(env!("OUT_DIR"), "/notices.zst")),
            __sysmon_notices::UNCOMPRESSED_LEN,
        )
    }};
}

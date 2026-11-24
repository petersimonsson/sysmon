//! sysmon-ui's settings file, `$XDG_CONFIG_HOME/sysmon/config.toml`:
//!
//! ```toml
//! [ui]
//! theme = "system"   # "system", "light" or "dark"
//! ```
//!
//! A missing file or key means the default. The app writes only the keys it
//! changes, so comments and anything else in the file are kept.

use std::path::{Path, PathBuf};

use toml_edit::{DocumentMut, Item, Table, value};

/// Light or dark, or as the system is.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub enum ThemePref {
    #[default]
    System,
    Light,
    Dark,
}

impl ThemePref {
    fn as_str(self) -> &'static str {
        match self {
            Self::System => "system",
            Self::Light => "light",
            Self::Dark => "dark",
        }
    }

    fn parse(s: &str) -> Option<Self> {
        match s {
            "system" => Some(Self::System),
            "light" => Some(Self::Light),
            "dark" => Some(Self::Dark),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct Config {
    pub theme: ThemePref,
}

/// `$XDG_CONFIG_HOME/sysmon/config.toml`, else `~/.config/sysmon/config.toml`.
pub fn default_path() -> PathBuf {
    std::env::var_os("XDG_CONFIG_HOME")
        .map(PathBuf::from)
        .or_else(|| std::env::var_os("HOME").map(|h| PathBuf::from(h).join(".config")))
        .unwrap_or_else(|| PathBuf::from("."))
        .join("sysmon")
        .join("config.toml")
}

/// The settings at `path`, and whether the file may be written back. A
/// missing file gives the defaults. One that can't be read or parsed does
/// too, with a warning, and is never overwritten: that would lose what's in
/// it. An unknown value is warned about and left at its default.
pub fn load(path: &Path) -> (Config, bool) {
    let text = match std::fs::read_to_string(path) {
        Ok(t) => t,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return (Config::default(), true),
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "can't read the config; using defaults");
            return (Config::default(), false);
        }
    };
    let doc: DocumentMut = match text.parse() {
        Ok(d) => d,
        Err(e) => {
            tracing::warn!(path = %path.display(), error = %e, "can't parse the config; using defaults and leaving it alone");
            return (Config::default(), false);
        }
    };
    let mut config = Config::default();
    if let Some(theme) = doc.get("ui").and_then(|ui| ui.get("theme")) {
        match theme.as_str().and_then(ThemePref::parse) {
            Some(t) => config.theme = t,
            None => tracing::warn!(
                path = %path.display(),
                "ui.theme should be \"system\", \"light\" or \"dark\"; using \"system\""
            ),
        }
    }
    (config, true)
}

/// Set `ui.theme` in the file at `path`, creating it (and its directory) if
/// needed and keeping everything else in it. Written to a temporary file
/// first and renamed into place, so a crash can't leave half a file.
pub fn save_theme(path: &Path, theme: ThemePref) -> std::io::Result<()> {
    let mut doc: DocumentMut = match std::fs::read_to_string(path) {
        Ok(t) => t
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => DocumentMut::new(),
        Err(e) => return Err(e),
    };
    let ui = doc
        .entry("ui")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "`ui` in the config isn't a table",
            )
        })?;
    ui.insert("theme", value(theme.as_str()));
    if let Some(dir) = path.parent() {
        std::fs::create_dir_all(dir)?;
    }
    let tmp = path.with_extension("toml.tmp");
    std::fs::write(&tmp, doc.to_string())?;
    std::fs::rename(&tmp, path)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(name: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sysmon-config-{}-{name}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        dir.join("sub").join("config.toml")
    }

    #[test]
    fn missing_file_is_the_defaults_and_saving_creates_it() {
        let path = tmp("missing");
        assert_eq!(load(&path), (Config::default(), true));
        save_theme(&path, ThemePref::Dark).unwrap();
        assert_eq!(load(&path).0.theme, ThemePref::Dark);
        assert!(!path.with_extension("toml.tmp").exists());
        save_theme(&path, ThemePref::System).unwrap();
        assert_eq!(load(&path).0.theme, ThemePref::System);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn saving_keeps_comments_and_other_keys() {
        let path = tmp("keep");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before =
            "# my settings\n[ui]\ntheme = \"light\" # bright\nfuture = 3\n\n[other]\nx = true\n";
        std::fs::write(&path, before).unwrap();
        assert_eq!(load(&path).0.theme, ThemePref::Light);
        save_theme(&path, ThemePref::Dark).unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("# my settings"), "{after}");
        assert!(after.contains("future = 3"), "{after}");
        assert!(after.contains("[other]\nx = true"), "{after}");
        assert_eq!(load(&path).0.theme, ThemePref::Dark);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn a_broken_file_gives_the_defaults_and_is_left_alone() {
        let path = tmp("broken");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, "[ui\ntheme = ").unwrap();
        assert_eq!(load(&path), (Config::default(), false));
        assert!(save_theme(&path, ThemePref::Dark).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[ui\ntheme = ");

        // A value it doesn't know is only that key.
        std::fs::write(&path, "[ui]\ntheme = \"purple\"\n").unwrap();
        assert_eq!(load(&path), (Config::default(), true));
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}

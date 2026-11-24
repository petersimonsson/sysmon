//! sysmon-ui's settings file, `$XDG_CONFIG_HOME/sysmon/config.toml`:
//!
//! ```toml
//! [ui]
//! theme = "system"   # "system", "light" or "dark"
//!
//! [keys]                         # see crate::keymap
//! toggle_graph = "x"             # replaces the default key(s)
//! cursor_down = ["down", "j"]
//! toggle_tree = []               # no key
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
    /// `[keys]`: an action's name and the keys for it, in file order.
    pub keys: Vec<(String, Vec<String>)>,
    /// What was wrong in the file, as lines to show; each was skipped.
    pub problems: Vec<String>,
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
            None => config.problems.push(
                "[ui] theme should be \"system\", \"light\" or \"dark\"; using \"system\"".into(),
            ),
        }
    }
    match doc.get("keys") {
        None => {}
        Some(keys) => match keys.as_table_like() {
            Some(table) => {
                for (name, item) in table.iter() {
                    match key_list(item) {
                        Some(list) => config.keys.push((name.to_string(), list)),
                        None => config.problems.push(format!(
                            "[keys] {name} should be a key (\"x\") or a list of keys ([\"x\", \"ctrl-x\"])"
                        )),
                    }
                }
            }
            None => config.problems.push("[keys] should be a table".into()),
        },
    }
    for p in &config.problems {
        tracing::warn!(path = %path.display(), "{p}");
    }
    (config, true)
}

/// A `[keys]` value: one key, or a list of them (empty for none).
fn key_list(item: &Item) -> Option<Vec<String>> {
    if let Some(s) = item.as_str() {
        return Some(vec![s.to_string()]);
    }
    item.as_array()?
        .iter()
        .map(|v| v.as_str().map(str::to_string))
        .collect()
}

/// Set `ui.theme` in the file at `path`, creating it (and its directory) if
/// needed and keeping everything else in it. Written to a temporary file
/// first and renamed into place, so a crash can't leave half a file.
pub fn save_theme(path: &Path, theme: ThemePref) -> std::io::Result<()> {
    let mut doc = read_doc(path)?;
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
    write_doc(path, &doc)
}

/// Write `[keys]` entries to the file at `path`, keeping everything else
/// in it (comments, other settings, entries for actions not given). Each
/// entry is an action's name and its keys, or `None` to remove the action's
/// entry (it's back to its defaults). An empty `[keys]` is removed.
pub fn save_keys(path: &Path, entries: &[(String, Option<Vec<String>>)]) -> std::io::Result<()> {
    let mut doc = read_doc(path)?;
    let keys = doc
        .entry("keys")
        .or_insert_with(|| Item::Table(Table::new()))
        .as_table_like_mut()
        .ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "`keys` in the config isn't a table",
            )
        })?;
    for (name, list) in entries {
        match list {
            Some(list) => {
                let array: toml_edit::Array = list.iter().map(String::as_str).collect();
                // Keep the comment after an entry being changed.
                match keys.get_mut(name).and_then(Item::as_value_mut) {
                    Some(old) => {
                        let decor = old.decor().clone();
                        *old = toml_edit::Value::Array(array);
                        *old.decor_mut() = decor;
                    }
                    None => {
                        keys.insert(name, value(array));
                    }
                }
            }
            None => {
                keys.remove(name);
            }
        }
    }
    if keys.is_empty() {
        doc.remove("keys");
    }
    write_doc(path, &doc)
}

/// The file at `path` to edit; an empty one if there's none yet. One that
/// can't be parsed is an error, so it's never overwritten.
fn read_doc(path: &Path) -> std::io::Result<DocumentMut> {
    match std::fs::read_to_string(path) {
        Ok(t) => t
            .parse()
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(DocumentMut::new()),
        Err(e) => Err(e),
    }
}

/// Write `doc` to `path` (and its directory), through a temporary file
/// renamed into place, so a crash can't leave half a file.
fn write_doc(path: &Path, doc: &DocumentMut) -> std::io::Result<()> {
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

    #[test]
    fn saving_keys_changes_only_the_entries_given() {
        let path = tmp("save-keys");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let before = "# mine\n[ui]\ntheme = \"dark\"\n\n[keys]\n\
                      toggle_graph = \"x\" # my x\ntoggel_tree = \"t\"\nquit = \"ctrl-w\"\n";
        std::fs::write(&path, before).unwrap();
        save_keys(
            &path,
            &[
                (
                    "toggle_graph".into(),
                    Some(vec!["y".into(), "ctrl-y".into()]),
                ),
                ("quit".into(), None),
                ("about".into(), Some(vec![])),
            ],
        )
        .unwrap();
        let after = std::fs::read_to_string(&path).unwrap();
        assert!(after.contains("# mine"), "{after}");
        assert!(after.contains("theme = \"dark\""), "{after}");
        assert!(
            after.contains("toggle_graph = [\"y\", \"ctrl-y\"] # my x"),
            "{after}"
        );
        assert!(
            after.contains("toggel_tree = \"t\""),
            "unknown entries stay: {after}"
        );
        assert!(!after.contains("quit"), "back to its defaults: {after}");
        assert!(after.contains("about = []"), "{after}");
        let (config, _) = load(&path);
        assert_eq!(config.keys.len(), 3);

        // Nothing left: no [keys] at all.
        save_keys(
            &path,
            &[
                ("toggle_graph".into(), None),
                ("toggel_tree".into(), None),
                ("about".into(), None),
            ],
        )
        .unwrap();
        assert!(!std::fs::read_to_string(&path).unwrap().contains("[keys]"));

        // A file it can't parse is left alone.
        std::fs::write(&path, "[keys\n").unwrap();
        assert!(save_keys(&path, &[("about".into(), None)]).is_err());
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "[keys\n");
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

    #[test]
    fn keys_are_read_in_file_order() {
        let path = tmp("keys");
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        let text = "[keys]\ntoggle_graph = \"x\"\ncursor_down = [\"down\", \"j\"]\n\
                    toggle_tree = []\nclear_graph = 3\n";
        std::fs::write(&path, text).unwrap();
        let (config, _) = load(&path);
        let keys: Vec<(&str, Vec<&str>)> = config
            .keys
            .iter()
            .map(|(n, ks)| (n.as_str(), ks.iter().map(String::as_str).collect()))
            .collect();
        assert_eq!(
            keys,
            [
                ("toggle_graph", vec!["x"]),
                ("cursor_down", vec!["down", "j"]),
                ("toggle_tree", vec![]),
            ]
        );
        assert_eq!(
            config.problems.len(),
            1,
            "clear_graph = 3: {:?}",
            config.problems
        );
        // The app doesn't write [keys], but saving the theme keeps them.
        save_theme(&path, ThemePref::Dark).unwrap();
        assert_eq!(load(&path).0.keys, config.keys);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }

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
        let (config, writable) = load(&path);
        assert!(writable);
        assert_eq!(config.theme, ThemePref::System);
        assert_eq!(config.problems.len(), 1, "{:?}", config.problems);
        let _ = std::fs::remove_dir_all(path.parent().unwrap().parent().unwrap());
    }
}

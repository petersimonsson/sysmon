//! The Lucide icons sysmon draws, from gpui-kit's bundled catalog.
//!
//! Only the icons listed in [`icon_set!`] are embedded, plus gpui-kit's
//! default set, which its own components (the filter's clear button,
//! menus, dialogs) use. [`icon`] checks in debug builds that an icon is
//! listed, so a missing one fails the tests instead of drawing nothing.

use std::borrow::Cow;

use gpui_kit::component::{Icon, Sizable as _};
use gpui_kit::*;

pub use gpui_kit::assets::IconName;

macro_rules! icon_set {
    ($($icon:ident),* $(,)?) => {
        gpui_kit::assets::icon_assets!(pub Icons, [$($icon),*]);
        /// Every icon embedded by [`Icons`].
        #[cfg(test)]
        pub const ALL: &[IconName] = &[$(IconName::$icon),*];
    };
}

icon_set!(
    // Directions: receive / read, transmit / write.
    ArrowDown,
    ArrowUp,
    // Log priorities and a silent host.
    CircleAlert,
    TriangleAlert,
    WifiOff,
    // Replay.
    Play,
    Pause,
    RotateCcw,
    // Close and remove, and add.
    X,
    Plus,
    // Bottom panel tabs.
    ChartLine,
    ScrollText,
    Info,
    // Toolbars.
    RadioTower,
    FileClock,
    FolderOpen,
    ListTree,
    Cpu,
    CornerDownRight,
    ChevronsUpDown,
    ChevronsDownUp,
    Search,
    ChevronDown,
    ChevronRight,
    ArrowDownToLine,
    Eraser,
    PanelBottomClose,
    // Details, banners, dialogs.
    CircleX,
    Link2Off,
    Download,
);

/// sysmon's icons, then gpui-kit's own.
pub struct AppAssets;

impl AssetSource for AppAssets {
    fn load(&self, path: &str) -> Result<Option<Cow<'static, [u8]>>> {
        if let Some(bytes) = Icons.load(path)? {
            return Ok(Some(bytes));
        }
        gpui_kit::assets::Assets.load(path)
    }

    fn list(&self, path: &str) -> Result<Vec<SharedString>> {
        let mut paths = gpui_kit::assets::Assets.list(path)?;
        paths.extend(Icons.list(path)?);
        paths.sort();
        paths.dedup();
        Ok(paths)
    }
}

/// An icon at the size of the text around it (`xsmall`, for `text_xs`).
pub fn icon(name: IconName) -> Icon {
    debug_assert!(
        AppAssets.load(&name.path()).ok().flatten().is_some(),
        "{} isn't embedded: add it to icon_set! in icons.rs",
        name.path()
    );
    Icon::new(name).xsmall()
}

#[cfg(test)]
mod tests {
    use super::{ALL, AppAssets};
    use gpui_kit::AssetSource as _;

    #[test]
    fn every_listed_icon_loads() {
        for name in ALL {
            let path = name.path();
            assert!(
                AppAssets.load(&path).unwrap().is_some(),
                "{path} doesn't load"
            );
        }
    }

    /// gpui-kit's own components still find their icons.
    #[test]
    fn the_default_set_is_kept() {
        assert!(AppAssets.load("icons/search.svg").unwrap().is_some());
        assert!(AppAssets.load("icons/chevron-down.svg").unwrap().is_some());
    }
}

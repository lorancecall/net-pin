//! The optional memory feature (off unless chosen at install or with `net-pin feature memory on`):
//! memory hogs and their launchers (`scan`), app families, cleanup scripts, memory samples and leak
//! report, kernel pool, on-demand families (the service's `daemon`, switching, follow-the-app),
//! duplicate tray-settings entries. The CLI exposes it as `net-pin ram <command>`.
pub mod cleanup;
pub mod daemon;
pub mod deny;
pub mod dwmwatch;
pub mod events;
pub mod family;
pub mod fileinfo;
pub mod follow;
pub mod gpu;
pub mod inventory;
pub mod leak;
pub mod net;
pub mod observe;
pub mod ondemand;
pub mod paths;
pub mod pipe;
pub mod pool;
pub mod prefs;
pub mod procs;
pub mod scan;
pub mod single;
pub mod sources;
pub mod switch;
pub mod trayicons;
pub mod userside;

/// Starting other programs: console tools never get a window (the tray has no console).
pub mod cmd {
    use std::ffi::OsStr;
    use std::os::windows::process::CommandExt;
    use std::process::Command;

    /// A console tool whose output is read: never shows a window.
    pub fn hidden(exe: impl AsRef<OsStr>) -> Command {
        let mut c = Command::new(exe);
        c.creation_flags(0x0800_0000); // CREATE_NO_WINDOW
        c
    }
}

//! Living beside Keel, which has the same engine as its network feature. Only one of them may
//! manage the network:
//!
//! - Keel's net feature waits while `C:\Program Files\net-pin\netpin.ps1` exists (Keel
//!   checks for that file), so net-pin keeps a `netpin.ps1` there (it forwards to `net-pin.exe`).
//! - net-pin changes nothing while the `Keel` service is installed with its net feature on
//!   (`%ProgramData%\keel\service.toml`, `net` missing = on), or while Keel's recorded network
//!   changes are still in place (`%ProgramData%\keel\net-state.json`): recording on top of them
//!   would take Keel's values for the originals. Both files are readable by users.
use std::path::PathBuf;

pub const SERVICE: &str = "Keel";

fn keel_data() -> PathBuf {
    let base = std::env::var_os("ProgramData").map(PathBuf::from).unwrap_or_else(|| PathBuf::from(r"C:\ProgramData"));
    base.join("keel")
}

fn service_registered() -> bool {
    winreg::RegKey::predef(winreg::enums::HKEY_LOCAL_MACHINE)
        .open_subkey(format!(r"SYSTEM\CurrentControlSet\Services\{SERVICE}")).is_ok()
}

/// `service.toml`'s `net` switch (missing file or key = on, Keel's default).
pub fn net_switch(service_toml: Option<&str>) -> bool {
    service_toml.and_then(|s| toml::from_str::<toml::Table>(s).ok())
        .and_then(|t| t.get("net").and_then(toml::Value::as_bool)).unwrap_or(true)
}

/// The rule, pure: why net-pin must wait, if it must.
pub fn decide(registered: bool, net_on: bool, keel_state: bool) -> Option<String> {
    if !registered { return None; }
    if net_on {
        return Some("Keel's network feature is on, so net-pin changes nothing: in an admin console run \
                     `keel feature net off`, then `keel net undo`".into());
    }
    keel_state.then(|| "Keel's network changes are still in place, so net-pin changes nothing: \
                        run `keel net undo` in an admin console".into())
}

/// Why net-pin must not change the network now (None = go ahead).
pub fn conflict() -> Option<String> {
    let d = keel_data();
    decide(service_registered(), net_switch(std::fs::read_to_string(d.join("service.toml")).ok().as_deref()),
           d.join("net-state.json").exists())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn waits_only_for_an_active_keel() {
        assert_eq!(decide(false, true, true), None, "no Keel service: its leftovers do not matter");
        assert!(decide(true, true, false).unwrap().contains("feature net off"));
        assert!(decide(true, false, true).unwrap().contains("keel net undo"));
        assert_eq!(decide(true, false, false), None);
    }

    #[test]
    fn reads_the_net_switch() {
        assert!(net_switch(None));
        assert!(net_switch(Some("ram = true\negpu = false\n")));
        assert!(!net_switch(Some("ram = true\nnet = false\n")));
        assert!(net_switch(Some("not toml [")));
    }
}

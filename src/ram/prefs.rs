//! The user's memory-sample options, `%LOCALAPPDATA%\net-pin\memory.toml` (`net-pin ram history`).
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
#[serde(default)]
pub struct Prefs {
    /// Keep a week of sample sessions across restarts. Off: this session and the one before.
    pub keep_memory_history: bool,
    /// Sample every minute instead of every 5 minutes.
    pub fast_samples: bool,
}

impl Prefs {
    pub fn path() -> std::path::PathBuf { crate::paths::user_data_dir().join("memory.toml") }

    pub fn load() -> Self {
        std::fs::read_to_string(Self::path()).ok().and_then(|s| toml::from_str(&s).ok()).unwrap_or_default()
    }

    pub fn save(&self) -> anyhow::Result<()> {
        std::fs::create_dir_all(crate::paths::user_data_dir())?;
        std::fs::write(Self::path(), toml::to_string_pretty(self)?)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn missing_fields_default() {
        let p: super::Prefs = toml::from_str("fast_samples = true").unwrap();
        assert!(p.fast_samples && !p.keep_memory_history);
    }
}

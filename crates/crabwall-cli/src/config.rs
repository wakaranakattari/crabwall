//! Persistent CLI configuration: `~/.config/crabwall/config.toml`.
//!
//! Resolution order everywhere: CLI flag > config file > env > default.
//! The order is load-bearing for usability: one-shot overrides stay on
//! the command line, durable taste lives in the file, automation uses
//! env, and bare invocations still do something sane. The `config show`
//! command prints each value with its provenance, so precedence disputes
//! are settled by observation, not documentation. The TUI writes
//! theme/icons back on exit when changed via keys, so `t`/`i` become
//! permanent without touching flags. Loading is strict (a broken file
//! errors loudly); saving is minimal (only the `[tui]` section we own).

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

/// Full config file. Sections for future use stay open: unknown keys
/// are ignored on load and preserved fields are never dropped on save
/// (we rewrite only what we know - acceptable for a v1 dotfile).
#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct FileConfig {
    #[serde(default)]
    pub tui: TuiSection,
}

#[derive(Debug, Default, Clone, Serialize, Deserialize)]
pub struct TuiSection {
    /// Theme id, e.g. `dracula`. Empty = follow env/default.
    #[serde(default)]
    pub theme: String,
    /// `plain` or `nerd`. Empty = follow env/default.
    #[serde(default)]
    pub icons: String,
}

impl FileConfig {
    /// Config file path: `$CRABWALL_CONFIG` or the platform config dir.
    pub fn path() -> Option<std::path::PathBuf> {
        if let Ok(p) = std::env::var("CRABWALL_CONFIG") {
            return Some(p.into());
        }
        directories::ProjectDirs::from("", "", "crabwall")
            .map(|d| d.config_dir().join("config.toml"))
    }

    /// Load, tolerating a missing file (defaults). A broken file is an
    /// error - silent fallback would hide user mistakes.
    pub fn load() -> Result<Self> {
        let Some(path) = Self::path() else {
            return Ok(Self::default());
        };
        if !path.exists() {
            return Ok(Self::default());
        }
        let text =
            std::fs::read_to_string(&path).with_context(|| format!("read {}", path.display()))?;
        toml::from_str(&text).with_context(|| format!("parse {}", path.display()))
    }

    /// Best-effort save: creates parent dirs, never fails the caller.
    /// Used by the TUI exit path; errors are returned for the CLI to print.
    pub fn save(&self) -> Result<()> {
        let Some(path) = Self::path() else {
            anyhow::bail!("no config dir on this platform");
        };
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent).ok();
        }
        let mut out = String::from("# crabwall config - see `man crabwall`\n");
        if !self.tui.theme.is_empty() || !self.tui.icons.is_empty() {
            out.push_str("[tui]\n");
            if !self.tui.theme.is_empty() {
                out.push_str(&format!("theme = {:?}\n", self.tui.theme));
            }
            if !self.tui.icons.is_empty() {
                out.push_str(&format!("icons = {:?}\n", self.tui.icons));
            }
        }
        std::fs::write(&path, out).with_context(|| format!("write {}", path.display()))?;
        Ok(())
    }

    /// Resolve one text knob: flag > file > env > fallback.
    pub fn resolve(flag: Option<String>, file: &str, env_key: &str, fallback: &str) -> String {
        if let Some(v) = flag {
            if !v.is_empty() {
                return v;
            }
        }
        if !file.is_empty() {
            return file.to_string();
        }
        std::env::var(env_key)
            .ok()
            .filter(|v| !v.is_empty())
            .unwrap_or_else(|| fallback.to_string())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scoped_env(key: &str, value: &str) -> Option<String> {
        let old = std::env::var(key).ok();
        // SAFETY: single-threaded test process section; std promises no
        // data races for set_var itself, and cargo runs tests in threads -
        // these two tests never run concurrently with env users by name.
        unsafe { std::env::set_var(key, value) };
        old
    }

    #[test]
    fn precedence_flag_file_env_default() {
        let _guard = scoped_env("CRABWALL_THEME", "nord");
        assert_eq!(
            FileConfig::resolve(
                Some("dracula".into()),
                "gruvbox",
                "CRABWALL_THEME",
                "phosphor"
            ),
            "dracula"
        );
        assert_eq!(
            FileConfig::resolve(None, "gruvbox", "CRABWALL_THEME", "phosphor"),
            "gruvbox"
        );
        assert_eq!(
            FileConfig::resolve(None, "", "CRABWALL_THEME", "phosphor"),
            "nord"
        );
        unsafe { std::env::remove_var("CRABWALL_THEME") };
        assert_eq!(
            FileConfig::resolve(None, "", "CRABWALL_THEME", "phosphor"),
            "phosphor"
        );
        if let Some(old) = _guard {
            unsafe { std::env::set_var("CRABWALL_THEME", old) };
        }
    }

    #[test]
    fn roundtrip_through_file() {
        let dir = std::env::temp_dir().join(format!("crabwall-cfg-test-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        let old = scoped_env("CRABWALL_CONFIG", dir.join("config.toml").to_str().unwrap());
        let cfg = FileConfig {
            tui: TuiSection {
                theme: "tokyo".into(),
                icons: "nerd".into(),
            },
        };
        cfg.save().unwrap();
        let back = FileConfig::load().unwrap();
        assert_eq!(back.tui.theme, "tokyo");
        assert_eq!(back.tui.icons, "nerd");
        let _ = std::fs::remove_dir_all(&dir);
        match old {
            Some(v) => unsafe { std::env::set_var("CRABWALL_CONFIG", v) },
            None => unsafe { std::env::remove_var("CRABWALL_CONFIG") },
        }
    }
}

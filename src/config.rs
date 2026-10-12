use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::fs;
use std::path::PathBuf;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AppConfig {
    pub device_name: String,
    pub download_dir: PathBuf,
    pub port: u16,
}

impl Default for AppConfig {
    fn default() -> Self {
        let download_dir = dirs::download_dir().unwrap_or_else(|| {
            dirs::home_dir()
                .map(|h| h.join("Downloads"))
                .unwrap_or_else(|| PathBuf::from("Downloads"))
        });

        Self {
            device_name: "Linux Quick Share".to_string(),
            download_dir,
            port: 8765,
        }
    }
}

impl AppConfig {
    pub fn config_file_path() -> PathBuf {
        let config_dir = dirs::config_dir()
            .unwrap_or_else(|| PathBuf::from(".config"))
            .join("quickshare");
        let _ = fs::create_dir_all(&config_dir);
        config_dir.join("settings.json")
    }

    pub fn load() -> Self {
        let path = Self::config_file_path();
        if path.exists() {
            if let Ok(contents) = fs::read_to_string(&path) {
                if let Ok(cfg) = serde_json::from_str::<AppConfig>(&contents) {
                    return cfg;
                }
            }
        }
        let default_cfg = Self::default();
        let _ = default_cfg.save();
        default_cfg
    }

    pub fn save(&self) -> Result<()> {
        let path = Self::config_file_path();
        if let Some(parent) = path.parent() {
            fs::create_dir_all(parent)?;
        }
        let json = serde_json::to_string_pretty(self)?;
        fs::write(path, json)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_app_config_load_and_save() {
        let cfg = AppConfig::load();
        assert!(!cfg.device_name.is_empty());
        assert!(cfg.port > 0);
        assert!(AppConfig::config_file_path().exists());
    }
}

// Configuration and domain types

use serde::{Deserialize, Serialize};

use crate::error::Error;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "lowercase")]
pub enum BackendConfig {
    Luks {
        image_path: String,
    },
    Gocryptfs {
        encrypted_path: String,
    },
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Secret {
    pub name: String,
    pub mount_path: String,
    #[serde(flatten)]
    pub backend: BackendConfig,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Config {
    pub secrets: Vec<Secret>,
}

impl Config {
    pub fn load() -> Result<Self, Error> {
        let config_path = Self::config_path();
        let contents = std::fs::read_to_string(&config_path)
            .map_err(|_| Error::ConfigNotFound)?;
        let config: Config = toml::from_str(&contents)
            .map_err(|e| Error::ConfigParse(e.to_string()))?;
        Ok(config)
    }

    pub fn save(&self) -> Result<(), Error> {
        let config_path = Self::config_path();
        if let Some(parent) = config_path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        let contents = toml::to_string_pretty(self)
            .map_err(|e| Error::ConfigParse(e.to_string()))?;
        std::fs::write(&config_path, contents)?;
        Ok(())
    }

    pub fn get(&self, name: &str) -> Result<&Secret, Error> {
        self.secrets
            .iter()
            .find(|s| s.name == name)
            .ok_or_else(|| Error::SecretNotFound(name.to_string()))
    }

    pub fn add(&mut self, secret: Secret) -> Result<(), Error> {
        if self.secrets.iter().any(|s| s.name == secret.name) {
            return Err(Error::SecretExists(secret.name));
        }
        self.secrets.push(secret);
        self.save()
    }

    pub fn remove(&mut self, name: &str) -> Result<(), Error> {
        let idx = self.secrets
            .iter()
            .position(|s| s.name == name)
            .ok_or_else(|| Error::SecretNotFound(name.to_string()))?;
        self.secrets.remove(idx);
        self.save()
    }

    pub fn config_path() -> std::path::PathBuf {
        let config_dir = std::env::var("XDG_CONFIG_HOME")
            .map(std::path::PathBuf::from)
            .unwrap_or_else(|_| {
                let home = std::env::var("HOME").expect("HOME not set");
                std::path::PathBuf::from(home).join(".config")
            });
        config_dir.join("secrets").join("config.toml")
    }
}

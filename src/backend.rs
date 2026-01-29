// Encryption backends - trait + implementations

use std::path::Path;
use std::process::{Command, Stdio};

use colored::Colorize;

use crate::config::{BackendConfig, Secret};
use crate::error::Error;

/// Print a dimmed status message (for progress steps)
fn status(msg: &str) {
    println!("  {}", msg.dimmed());
}

/// Print a success message with checkmark
fn success(msg: &str) {
    println!("\n{} {}", "✓".green(), msg.green());
}

/// Print an info line (normal text, indented)
fn info(msg: &str) {
    println!("  {}", msg);
}

// Key file search paths
const KEY_SEARCH_PATHS: &[&str] = &[
    "/run/media/{user}/*/keys",
    "/run/media/{user}/*",
    "/media/*",
];

pub trait EncryptionBackend {
    fn open(&self, secret: &Secret) -> Result<(), Error>;
    fn close(&self, secret: &Secret) -> Result<(), Error>;
    fn is_open(&self, secret: &Secret) -> Result<bool, Error>;
}

/// Returns the appropriate backend for a secret
pub fn backend_for(secret: &Secret) -> &'static dyn EncryptionBackend {
    match &secret.backend {
        BackendConfig::Luks { .. } => &LuksBackend,
        BackendConfig::Gocryptfs { .. } => &GocryptfsBackend,
    }
}

/// Build the list of key search paths, including optional test path from env
fn get_key_search_paths() -> Vec<String> {
    let user = std::env::var("USER").unwrap_or_default();
    let mut paths: Vec<String> = KEY_SEARCH_PATHS
        .iter()
        .map(|p| p.replace("{user}", &user))
        .collect();
    
    // Add test path from environment variable if set
    if let Ok(test_path) = std::env::var("SECRETS_TEST_KEY_PATH") {
        paths.push(test_path);
    }
    
    paths
}

/// Find existing directories that match key search paths
/// Returns a list of directories where keys could be stored
pub fn find_key_directories() -> Vec<String> {
    let mut dirs = Vec::new();
    
    for pattern in get_key_search_paths() {
        if let Ok(paths) = glob::glob(&pattern) {
            for path in paths.flatten() {
                if path.is_dir() {
                    dirs.push(path.to_string_lossy().to_string());
                }
            }
        }
    }
    
    dirs
}

/// Find a key file by searching known paths
pub fn find_key_file(key_name: &str) -> Result<String, Error> {
    for pattern in get_key_search_paths() {
        let full_pattern = format!("{}/{}", pattern, key_name);
        
        if let Ok(paths) = glob::glob(&full_pattern) {
            for path in paths.flatten() {
                if path.is_file() {
                    return Ok(path.to_string_lossy().to_string());
                }
            }
        }
    }
    
    Err(Error::KeyNotFound(key_name.to_string()))
}

// --- LUKS ---

pub struct LuksBackend;

impl EncryptionBackend for LuksBackend {
    fn open(&self, secret: &Secret) -> Result<(), Error> {
        let BackendConfig::Luks { image_path } = &secret.backend else {
            unreachable!()
        };
        let mapper = &secret.name;

        // Check if already open
        if self.is_open(secret)? {
            return Err(Error::AlreadyOpen(secret.name.clone()));
        }

        // Check if mount point is already in use
        if Path::new(&secret.mount_path).exists() {
            if let Ok(entries) = std::fs::read_dir(&secret.mount_path) {
                if entries.count() > 0 {
                    eprintln!("  {}: Mount point is not empty: {}", "Warning".yellow(), secret.mount_path);
                    eprintln!("  There may be another volume mounted or files present.");
                    return Err(Error::MountFailed("Mount point is not empty".to_string()));
                }
            }
        }

        // Find key file
        let key_file_name = format!("{}.key.gpg", mapper);
        let key_file = find_key_file(&key_file_name)?;
        info(&format!("Found key file at: {}", key_file));

        // Acquire sudo credentials before GPG prompt
        let sudo_status = Command::new("sudo").arg("-v").status()?;
        if !sudo_status.success() {
            return Err(Error::MountFailed("Failed to acquire sudo credentials".to_string()));
        }

        status(&format!("Decrypting {}...", secret.name));

        // gpg --decrypt | sudo cryptsetup open
        let gpg = Command::new("gpg")
            .arg("--decrypt")
            .arg(&key_file)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let gpg_stdout = gpg.stdout.ok_or_else(|| {
            Error::MountFailed("Failed to capture gpg output".to_string())
        })?;

        let cryptsetup = Command::new("sudo")
            .args(["cryptsetup", "open", image_path, mapper, "--key-file", "-"])
            .stdin(gpg_stdout)
            .status()?;

        if !cryptsetup.success() {
            return Err(Error::MountFailed("cryptsetup open failed".to_string()));
        }

        // Create mount point and mount
        status(&format!("Mounting {}...", secret.name));
        Command::new("sudo")
            .args(["mkdir", "-p", &secret.mount_path])
            .status()?;

        let mount = Command::new("sudo")
            .args(["mount", &format!("/dev/mapper/{}", mapper), &secret.mount_path])
            .status()?;

        if !mount.success() {
            return Err(Error::MountFailed("mount failed".to_string()));
        }

        // Change ownership to current user
        let user = std::env::var("USER").unwrap_or_default();
        Command::new("sudo")
            .args(["chown", &format!("{}:{}", user, user), &secret.mount_path])
            .status()?;

        success(&format!("{} opened and mounted at {}", secret.name, secret.mount_path));
        Ok(())
    }

    fn close(&self, secret: &Secret) -> Result<(), Error> {
        let mapper = &secret.name;

        if !self.is_open(secret)? {
            return Err(Error::NotOpen(secret.name.clone()));
        }

        // Unmount
        let umount = Command::new("sudo")
            .args(["umount", &secret.mount_path])
            .status()?;

        if !umount.success() {
            return Err(Error::UnmountFailed(format!(
                "Failed to unmount {}. Directory may be busy.", secret.mount_path
            )));
        }
        status(&format!("Unmounted {}", secret.name));

        // Close LUKS container
        let close = Command::new("sudo")
            .args(["cryptsetup", "close", mapper])
            .status()?;

        if !close.success() {
            return Err(Error::UnmountFailed("Failed to close LUKS container".to_string()));
        }
        status("Closed LUKS container");

        success(&format!("{} closed and encrypted", secret.name));
        Ok(())
    }

    fn is_open(&self, secret: &Secret) -> Result<bool, Error> {
        let mapper = &secret.name;
        Ok(Path::new(&format!("/dev/mapper/{}", mapper)).exists())
    }
}

// --- gocryptfs ---

pub struct GocryptfsBackend;

impl EncryptionBackend for GocryptfsBackend {
    fn open(&self, secret: &Secret) -> Result<(), Error> {
        let BackendConfig::Gocryptfs { encrypted_path } = &secret.backend else {
            unreachable!()
        };

        if self.is_open(secret)? {
            return Err(Error::AlreadyOpen(secret.name.clone()));
        }

        if !Path::new(encrypted_path).is_dir() {
            return Err(Error::MountFailed(format!(
                "Encrypted directory not found: {}", encrypted_path
            )));
        }

        // Check if mount point is already in use
        if Path::new(&secret.mount_path).exists() {
            if let Ok(entries) = std::fs::read_dir(&secret.mount_path) {
                if entries.count() > 0 {
                    eprintln!("  {}: Mount point is not empty: {}", "Warning".yellow(), secret.mount_path);
                    eprintln!("  There may be another volume mounted or files present.");
                    return Err(Error::MountFailed("Mount point is not empty".to_string()));
                }
            }
        }

        // Find key file
        let key_file_name = format!("{}.key.gpg", secret.name);
        let key_file = find_key_file(&key_file_name)?;
        info(&format!("Found key file at: {}", key_file));

        // Create mount point
        std::fs::create_dir_all(&secret.mount_path)?;

        status(&format!("Decrypting {}...", secret.name));

        // gpg --decrypt | gocryptfs -passfile /dev/stdin
        let gpg = Command::new("gpg")
            .arg("--decrypt")
            .arg(&key_file)
            .stdout(Stdio::piped())
            .stderr(Stdio::inherit())
            .spawn()?;

        let gpg_stdout = gpg.stdout.ok_or_else(|| {
            Error::MountFailed("Failed to capture gpg output".to_string())
        })?;

        status(&format!("Mounting {}...", secret.name));
        let mount_status = Command::new("gocryptfs")
            .args(["-passfile", "/dev/stdin", encrypted_path, &secret.mount_path])
            .stdin(gpg_stdout)
            .status()?;

        if !mount_status.success() {
            return Err(Error::MountFailed("gocryptfs mount failed".to_string()));
        }

        success(&format!("{} opened and mounted at {}", secret.name, secret.mount_path));
        Ok(())
    }

    fn close(&self, secret: &Secret) -> Result<(), Error> {
        if !self.is_open(secret)? {
            return Err(Error::NotOpen(secret.name.clone()));
        }

        let unmount_status = Command::new("fusermount")
            .args(["-u", &secret.mount_path])
            .status()?;

        if !unmount_status.success() {
            return Err(Error::UnmountFailed(format!(
                "Failed to unmount {}. Directory may be busy.", secret.mount_path
            )));
        }

        success(&format!("{} closed and encrypted", secret.name));
        Ok(())
    }

    fn is_open(&self, secret: &Secret) -> Result<bool, Error> {
        let status = Command::new("mountpoint")
            .args(["-q", &secret.mount_path])
            .status()?;
        Ok(status.success())
    }
}

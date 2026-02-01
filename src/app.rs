use std::fs::OpenOptions;
use std::io::Write;
use std::os::unix::fs::OpenOptionsExt;
use std::process::Command as ProcessCommand;

use colored::Colorize;
use inquire::{Select, Text};

use crate::backend;
use crate::command::{Command, KeyCommand};
use crate::config::{BackendConfig, Config, Secret};
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

pub struct App {
    config: Config,
}

impl App {
    pub fn new(config: Config) -> Self {
        Self { config }
    }

    pub fn run(&mut self, cmd: Command) -> Result<(), Error> {
        match cmd {
            Command::Init => self.init(),
            Command::Add { name, mount, backend_type, path } => {
                self.add(&name, &mount, &backend_type, &path)
            }
            Command::Remove { name } => self.remove(&name),
            Command::Create { name, mount, backend_type, path, size } => {
                self.create(name, mount, backend_type, path, size)
            }
            Command::List => self.list(),
            Command::Open { name } => self.open(name.as_deref()),
            Command::Close { name } => self.close(name.as_deref()),
            Command::Delete { name } => self.delete(&name),
            Command::Move { name, target_dir } => self.move_secret(&name, &target_dir),
            Command::Key { action } => self.key(action),
        }
    }

    fn init(&mut self) -> Result<(), Error> {
        let config_path = Config::config_path();
        
        if config_path.exists() {
            eprintln!("{}: Config file already exists at {}", "Warning".yellow(), config_path.display().to_string().cyan());
            let overwrite = inquire::Confirm::new("Overwrite existing config?")
                .with_default(false)
                .prompt()
                .map_err(|e| Error::MountFailed(e.to_string()))?;
            
            if !overwrite {
                println!("Init cancelled.");
                return Ok(());
            }
        }

        let empty_config = Config { secrets: vec![] };
        empty_config.save()?;

        println!("\n{}", "Welcome to Secrets!".green().bold());
        println!("\nConfig file created at: {}", config_path.display().to_string().cyan());
        println!("\n{}", "Quick Start:".bold());
        println!("  {} - Create a new encrypted volume", "secrets create".cyan());
        println!("  {} - Add an existing encrypted volume", "secrets add".cyan());
        println!("  {} - List all secrets", "secrets list".cyan());
        println!("  {} - Mount a secret", "secrets open <name>".cyan());
        println!("  {} - Unmount a secret", "secrets close <name>".cyan());
        println!("\nRun {} for more commands.", "secrets --help".cyan());

        Ok(())
    }

    fn add(
        &mut self,
        name: &str,
        mount_path: &str,
        backend_type: &str,
        path: &str,
    ) -> Result<(), Error> {
        let backend = match backend_type {
            "luks" => BackendConfig::Luks { image_path: path.to_string() },
            "gocryptfs" => BackendConfig::Gocryptfs { encrypted_path: path.to_string() },
            _ => return Err(Error::MountFailed(format!("Unknown backend type: {}", backend_type))),
        };

        let secret = Secret {
            name: name.to_string(),
            mount_path: mount_path.to_string(),
            backend,
        };

        self.config.add(secret)?;
        success(&format!("Added secret '{}'", name));
        Ok(())
    }

    fn remove(&mut self, name: &str) -> Result<(), Error> {
        self.config.remove(name)?;
        success(&format!("Removed secret '{}'", name));
        Ok(())
    }

    fn create(
        &mut self,
        name: Option<String>,
        mount: Option<String>,
        backend_type: Option<String>,
        path: Option<String>,
        size: Option<u32>,
    ) -> Result<(), Error> {
        let name = match name {
            Some(n) => n,
            None => self.prompt("Secret name")?,
        };

        let backend_type = match backend_type {
            Some(t) => t,
            None => self.prompt_choice("Backend type", &["luks", "gocryptfs"])?,
        };

        let mount = match mount {
            Some(m) => m,
            None => self.prompt(&format!("Mount path (e.g., /mnt/{})", name))?,
        };

        let dir = match path {
            Some(p) => p,
            None => self.prompt_with_default("Directory for encrypted data", "/mnt/storage")?,
        };

        // Derive full path from directory and name
        let path = if backend_type == "luks" {
            format!("{}/{}.img", dir, name)
        } else {
            format!("{}/{}-encrypted", dir, name)
        };

        // Prompt for key output directory
        let key_dir = self.prompt_key_directory(&dir)?;
        let key_output_path = format!("{}/{}.key.gpg", key_dir, name);

        let size = if backend_type == "luks" {
            match size {
                Some(s) => s,
                None => self.prompt_with_default("Image size in MB", "100")?
                    .parse()
                    .map_err(|_| Error::MountFailed("Invalid size".to_string()))?,
            }
        } else {
            0
        };

        match backend_type.as_str() {
            "luks" => self.create_luks(&name, &mount, &path, &key_output_path, size)?,
            "gocryptfs" => self.create_gocryptfs(&name, &mount, &path, &key_output_path)?,
            _ => return Err(Error::MountFailed(format!("Unknown backend type: {}", backend_type))),
        }

        Ok(())
    }

    fn prompt(&self, message: &str) -> Result<String, Error> {
        Text::new(message)
            .prompt()
            .map(|s| Self::clean_path(&s))
            .map_err(|e| Error::MountFailed(e.to_string()))
    }

    fn prompt_with_default(&self, message: &str, default: &str) -> Result<String, Error> {
        Text::new(message)
            .with_default(default)
            .prompt()
            .map(|s| Self::clean_path(&s))
            .map_err(|e| Error::MountFailed(e.to_string()))
    }

    fn clean_path(input: &str) -> String {
        let trimmed = input.trim();
        if (trimmed.starts_with('"') && trimmed.ends_with('"')) 
            || (trimmed.starts_with('\'') && trimmed.ends_with('\'')) {
            trimmed[1..trimmed.len()-1].to_string()
        } else {
            trimmed.to_string()
        }
    }

    fn prompt_choice(&self, message: &str, choices: &[&str]) -> Result<String, Error> {
        Select::new(message, choices.to_vec())
            .prompt()
            .map(|s| s.to_string())
            .map_err(|e| Error::MountFailed(e.to_string()))
    }

    fn write_key_file(path: &str, data: &[u8]) -> Result<(), Error> {
        let mut file = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(true)
            .mode(0o600)
            .open(path)?;
        file.write_all(data)?;
        Ok(())
    }

    fn encrypt_key_with_gpg(key_path: &str, output_path: &str) -> Result<(), Error> {
        let gpg = ProcessCommand::new("gpg")
            .args([
                "--symmetric",
                "--s2k-mode", "3",
                "--s2k-count", "65011712",
                "--s2k-digest-algo", "SHA512",
                "--s2k-cipher-algo", "AES256",
                "--output", output_path,
                key_path,
            ])
            .status()?;
        if !gpg.success() {
            std::fs::remove_file(key_path)?;
            return Err(Error::MountFailed("Failed to encrypt key".to_string()));
        }
        Ok(())
    }

    fn prompt_key_directory(&self, default_dir: &str) -> Result<String, Error> {
        let mut options: Vec<String> = Vec::new();
        
        // Add detected removable media paths
        let detected_dirs = backend::find_key_directories();
        for dir in &detected_dirs {
            options.push(dir.clone());
        }
        
        // Add special options
        let same_as_volume = format!("Same as volume ({})", default_dir);
        let enter_manually = "Enter path manually".to_string();
        
        options.push(same_as_volume.clone());
        options.push(enter_manually.clone());
        
        let choice = Select::new("Where to save the key file?", options)
            .prompt()
            .map_err(|e| Error::MountFailed(e.to_string()))?;
        
        if choice == same_as_volume {
            Ok(default_dir.to_string())
        } else if choice == enter_manually {
            self.prompt("Key file directory")
        } else {
            Ok(choice)
        }
    }

    fn create_luks(&mut self, name: &str, mount: &str, path: &str, key_output_path: &str, size: u32) -> Result<(), Error> {
        println!("\n{}", format!("Creating LUKS volume '{}'", name).bold());
        
        if std::path::Path::new(path).exists() {
            eprintln!("{}: Image file already exists: {}", "Error".red(), path.cyan());
            eprintln!("  Use '{}' command to add an existing volume", "add".cyan());
            return Err(Error::MountFailed("Cannot overwrite existing volume".to_string()));
        }
        
        status(&format!("Creating {}MB image file at {}...", size, path));
        let dd = ProcessCommand::new("dd")
            .args(["if=/dev/zero", &format!("of={}", path), "bs=1M", &format!("count={}", size)])
            .status()?;
        if !dd.success() {
            return Err(Error::MountFailed("Failed to create image file".to_string()));
        }

        status("Generating encryption key...");
        let key_path = format!("/tmp/{}.key", name);
        let keygen = ProcessCommand::new("dd")
            .args(["if=/dev/urandom", "bs=512", "count=1"])
            .output()?;
        if !keygen.status.success() {
            return Err(Error::MountFailed("Failed to generate key".to_string()));
        }
        Self::write_key_file(&key_path, &keygen.stdout)?;

        status("Formatting LUKS volume...");
        let format = ProcessCommand::new("sudo")
            .args(["cryptsetup", "luksFormat", path, &key_path])
            .status()?;
        if !format.success() {
            std::fs::remove_file(&key_path)?;
            return Err(Error::MountFailed("Failed to format LUKS volume".to_string()));
        }

        status("Creating filesystem...");
        ProcessCommand::new("sudo")
            .args(["cryptsetup", "open", path, name, "--key-file", &key_path])
            .status()?;
        
        ProcessCommand::new("sudo")
            .args(["mkfs.ext4", &format!("/dev/mapper/{}", name)])
            .status()?;
        
        ProcessCommand::new("sudo")
            .args(["cryptsetup", "close", name])
            .status()?;

        status("Encrypting key with GPG...");
        Self::encrypt_key_with_gpg(&key_path, key_output_path)?;
        std::fs::remove_file(&key_path)?;

        success("LUKS volume created successfully!");
        info(&format!("Key saved to: {}", key_output_path.cyan()));
        println!("\n  {}: Move this key file to your removable media:", "Note".cyan());
        info(&format!("mv {} /run/media/$USER/YOUR_USB/keys/", key_output_path));

        let secret = Secret {
            name: name.to_string(),
            mount_path: mount.to_string(),
            backend: BackendConfig::Luks { image_path: path.to_string() },
        };
        self.config.add(secret)?;
        info(&format!("Added '{}' to configuration", name));

        Ok(())
    }

    fn create_gocryptfs(&mut self, name: &str, mount: &str, path: &str, key_output_path: &str) -> Result<(), Error> {
        println!("\n{}", format!("Creating gocryptfs volume '{}'", name).bold());

        if std::path::Path::new(path).exists() {
            let is_empty = std::fs::read_dir(path)?.next().is_none();
            if !is_empty {
                eprintln!("{}: Directory already exists and is not empty: {}", "Error".red(), path.cyan());
                eprintln!("  Use '{}' command to add an existing volume", "add".cyan());
                return Err(Error::MountFailed("Cannot overwrite existing volume".to_string()));
            }
        }

        status(&format!("Creating encrypted directory at {}...", path));
        std::fs::create_dir_all(path)?;

        status("Generating password...");
        let key_path = format!("/tmp/{}.key", name);
        let keygen = ProcessCommand::new("openssl")
            .args(["rand", "-base64", "64"])
            .output()?;
        if !keygen.status.success() {
            return Err(Error::MountFailed("Failed to generate password".to_string()));
        }
        Self::write_key_file(&key_path, &keygen.stdout)?;

        status("Initializing gocryptfs...");
        let init = ProcessCommand::new("gocryptfs")
            .args(["-init", "-passfile", &key_path, path])
            .status()?;
        if !init.success() {
            std::fs::remove_file(&key_path)?;
            return Err(Error::MountFailed("Failed to initialize gocryptfs".to_string()));
        }

        status("Encrypting key with GPG...");
        Self::encrypt_key_with_gpg(&key_path, key_output_path)?;
        std::fs::remove_file(&key_path)?;

        success("gocryptfs volume created successfully!");
        info(&format!("Key saved to: {}", key_output_path.cyan()));
        println!("\n  {}: Move this key file to your removable media:", "Note".cyan());
        info(&format!("mv {} /run/media/$USER/YOUR_USB/keys/", key_output_path));

        // Add to config
        let secret = Secret {
            name: name.to_string(),
            mount_path: mount.to_string(),
            backend: BackendConfig::Gocryptfs { encrypted_path: path.to_string() },
        };
        self.config.add(secret)?;
        info(&format!("Added '{}' to configuration", name));

        Ok(())
    }

    fn list(&self) -> Result<(), Error> {
        if self.config.secrets.is_empty() {
            println!("No secrets configured");
            println!("Add one with: secrets add <name> <mount_path> -t <luks|gocryptfs> -p <path>");
            return Ok(());
        }

        // Calculate column widths
        let name_width = self.config.secrets.iter().map(|s| s.name.len()).max().unwrap_or(4).max(4);
        let type_width = 9; // "gocryptfs" is longest
        let status_width = 6; // "closed" is longest
        let mount_width = self.config.secrets.iter().map(|s| s.mount_path.len()).max().unwrap_or(5).max(5);

        // Header
        println!(
            "{:<name_width$}  {:<type_width$}  {:<status_width$}  {:<mount_width$}  {}",
            "NAME", "TYPE", "STATUS", "MOUNT", "PATH"
        );
        println!(
            "{:-<name_width$}  {:-<type_width$}  {:-<status_width$}  {:-<mount_width$}  {}",
            "", "", "", "", "----"
        );

        // Rows
        for secret in &self.config.secrets {
            let is_open = backend::backend_for(secret).is_open(secret).unwrap_or(false);
            let status = if is_open { "open" } else { "closed" };
            let (backend_type, path) = match &secret.backend {
                BackendConfig::Luks { image_path } => ("luks", image_path.as_str()),
                BackendConfig::Gocryptfs { encrypted_path } => ("gocryptfs", encrypted_path.as_str()),
            };

            println!(
                "{:<name_width$}  {:<type_width$}  {:<status_width$}  {:<mount_width$}  {}",
                secret.name, backend_type, status, secret.mount_path, path
            );
        }

        Ok(())
    }

    fn open(&self, name: Option<&str>) -> Result<(), Error> {
        let secret = self.config.get(name.unwrap_or("default"))?;
        backend::backend_for(secret).open(secret)
    }

    fn close(&self, name: Option<&str>) -> Result<(), Error> {
        let secret = self.config.get(name.unwrap_or("default"))?;
        backend::backend_for(secret).close(secret)
    }

    fn delete(&mut self, name: &str) -> Result<(), Error> {
        let secret = self.config.get(name)?.clone();
        
        // Check if it's open
        if backend::backend_for(&secret).is_open(&secret)? {
            eprintln!("Secret '{}' is currently open.", name);
            eprintln!("Please close it first with: secrets close {}", name);
            return Err(Error::MountFailed("Cannot delete an open secret".to_string()));
        }

        // Get the path to delete
        let (path, type_name) = match &secret.backend {
            BackendConfig::Luks { image_path } => (image_path.clone(), "LUKS image"),
            BackendConfig::Gocryptfs { encrypted_path } => (encrypted_path.clone(), "gocryptfs directory"),
        };

        // Scary confirmation
        eprintln!("\n{}", "!!! WARNING: DESTRUCTIVE OPERATION !!!".red().bold());
        eprintln!("This will {} the {} at:", "PERMANENTLY DELETE".red().bold(), type_name);
        eprintln!("  {}", path.cyan());
        eprintln!("\nAll data in this encrypted volume will be {}.", "LOST FOREVER".red().bold());
        eprintln!("The key file ({}.key.gpg) will {} be deleted.", name, "NOT".green());
        
        let confirm = inquire::Confirm::new(&format!("Delete '{}' permanently?", name))
            .with_default(false)
            .prompt()
            .map_err(|e| Error::MountFailed(e.to_string()))?;

        if !confirm {
            info("Delete cancelled.");
            return Ok(());
        }

        // Double confirmation - type the name
        let typed_name = Text::new("Type the secret name to confirm:")
            .prompt()
            .map_err(|e| Error::MountFailed(e.to_string()))?;

        if typed_name != name {
            eprintln!("Name does not match. Delete cancelled.");
            return Ok(());
        }

        // Safety checks before deletion
        let path_obj = std::path::Path::new(&path);
        
        // Check 1: Path must be absolute
        if !path_obj.is_absolute() {
            return Err(Error::MountFailed(format!(
                "Refusing to delete relative path: {}",
                path
            )));
        }

        // Check 2: Path must exist
        if !path_obj.exists() {
            eprintln!("  {}: Path does not exist: {}", "Warning".yellow(), path);
            info("Removing from config only.");
            self.config.remove(name)?;
            success(&format!("Secret '{}' removed from config.", name));
            return Ok(());
        }

        // Check 3: Must not be a symlink (prevents symlink attacks)
        if path_obj.is_symlink() {
            return Err(Error::MountFailed(format!(
                "Refusing to delete symlink: {}",
                path
            )));
        }

        // Check 4: Canonicalize and verify it's not a critical path
        let canonical = path_obj.canonicalize()?;
        let canonical_str = canonical.to_string_lossy();
        
        let forbidden_paths = [
            "/", "/home", "/root", "/etc", "/usr", "/var", "/bin", "/sbin",
            "/lib", "/lib64", "/boot", "/dev", "/proc", "/sys", "/tmp", "/mnt",
            "/media", "/opt", "/run", "/srv",
        ];
        
        for forbidden in forbidden_paths {
            if canonical_str == forbidden || canonical_str.starts_with(&format!("{}/", forbidden)) && canonical_str.matches('/').count() <= 2 {
                return Err(Error::MountFailed(format!(
                    "Refusing to delete protected path: {}",
                    canonical_str
                )));
            }
        }

        // Check 5: For gocryptfs, verify it looks like a gocryptfs directory
        if let BackendConfig::Gocryptfs { .. } = &secret.backend {
            let conf_file = canonical.join("gocryptfs.conf");
            if !conf_file.exists() {
                return Err(Error::MountFailed(format!(
                    "Directory does not appear to be a gocryptfs volume (missing gocryptfs.conf): {}",
                    canonical_str
                )));
            }
        }

        // Check 6: For LUKS, verify it's a file not a directory
        if let BackendConfig::Luks { .. } = &secret.backend {
            if !path_obj.is_file() {
                return Err(Error::MountFailed(format!(
                    "LUKS path is not a file: {}",
                    path
                )));
            }
        }

        // Delete the data
        match &secret.backend {
            BackendConfig::Luks { image_path } => {
                status("Deleting LUKS image...");
                std::fs::remove_file(image_path)?;
            }
            BackendConfig::Gocryptfs { encrypted_path } => {
                status("Deleting gocryptfs directory...");
                std::fs::remove_dir_all(encrypted_path)?;
            }
        }

        // Remove from config
        self.config.remove(name)?;

        // Ask about mount point
        let mount_path = std::path::Path::new(&secret.mount_path);
        if mount_path.exists() {
            let is_empty = std::fs::read_dir(&secret.mount_path)
                .map(|mut entries| entries.next().is_none())
                .unwrap_or(false);
            
            if is_empty {
                let delete_mount = inquire::Confirm::new(&format!(
                    "Delete empty mount point directory '{}'?",
                    secret.mount_path
                ))
                    .with_default(true)
                    .prompt()
                    .map_err(|e| Error::MountFailed(e.to_string()))?;

                if delete_mount {
                    std::fs::remove_dir(&secret.mount_path)?;
                    status("Mount point deleted.");
                }
            } else {
                eprintln!("\n  {}: Mount point '{}' is not empty, leaving it alone.", "Warning".yellow(), secret.mount_path.cyan());
            }
        }

        success(&format!("Secret '{}' has been deleted.", name));
        println!("\n  {}: The key file ({}.key.gpg) still exists on your removable media.", "Note".cyan(), name);
        info("You should delete it manually if you no longer need it.");

        Ok(())
    }

    fn move_secret(&mut self, name: &str, target_dir: &str) -> Result<(), Error> {
        let secret = self.config.get(name)?.clone();

        // Check if it's open
        if backend::backend_for(&secret).is_open(&secret)? {
            eprintln!("Secret '{}' is currently open.", name);
            eprintln!("Please close it first with: secrets close {}", name);
            return Err(Error::MountFailed("Cannot move an open secret".to_string()));
        }

        // Get the current path
        let current_path = match &secret.backend {
            BackendConfig::Luks { image_path } => image_path.clone(),
            BackendConfig::Gocryptfs { encrypted_path } => encrypted_path.clone(),
        };

        let current_path_obj = std::path::Path::new(&current_path);

        // Check source exists
        if !current_path_obj.exists() {
            return Err(Error::MountFailed(format!(
                "Source path does not exist: {}",
                current_path
            )));
        }

        // Extract filename from current path
        let filename = current_path_obj
            .file_name()
            .ok_or_else(|| Error::MountFailed("Could not extract filename from path".to_string()))?;

        // Check target directory exists and is a directory
        let target_dir_obj = std::path::Path::new(target_dir);
        if !target_dir_obj.exists() {
            return Err(Error::MountFailed(format!(
                "Target directory does not exist: {}",
                target_dir
            )));
        }
        if !target_dir_obj.is_dir() {
            return Err(Error::MountFailed(format!(
                "Target is not a directory: {}",
                target_dir
            )));
        }

        // Canonicalize target directory to get absolute path
        let target_dir_canonical = target_dir_obj.canonicalize()?;

        // Build new path with absolute target directory
        let new_path = target_dir_canonical.join(filename);
        let new_path_str = new_path.to_string_lossy().to_string();

        // Check target doesn't already exist
        if new_path.exists() {
            return Err(Error::MountFailed(format!(
                "Target already exists: {}",
                new_path_str
            )));
        }

        // Perform the move
        status(&format!("Moving {} to {}...", current_path, new_path_str));
        if let Err(e) = std::fs::rename(&current_path, &new_path) {
            // Fall back to copy + delete for cross-device moves
            if e.kind() == std::io::ErrorKind::CrossesDevices {
                status("Cross-device move detected, copying instead...");
                std::fs::copy(&current_path, &new_path)?;
                std::fs::remove_file(&current_path)?;
            } else {
                return Err(e.into());
            }
        }

        // Update config
        let new_backend = match &secret.backend {
            BackendConfig::Luks { .. } => BackendConfig::Luks { image_path: new_path_str.clone() },
            BackendConfig::Gocryptfs { .. } => BackendConfig::Gocryptfs { encrypted_path: new_path_str.clone() },
        };

        let updated_secret = Secret {
            name: secret.name.clone(),
            mount_path: secret.mount_path.clone(),
            backend: new_backend,
        };

        self.config.remove(name)?;
        self.config.add(updated_secret)?;

        success(&format!("Moved '{}' to {}", name, new_path_str));
        Ok(())
    }

    fn key(&mut self, action: KeyCommand) -> Result<(), Error> {
        match action {
            KeyCommand::Show { name, base64 } => self.key_show(&name, base64),
            _ => {
                // TODO: Implement remaining LUKS key management
                // - key create: Generate new key, add to LUKS slot, encrypt with GPG
                // - key add: Add existing key file to LUKS slot
                // - key remove: Remove key from LUKS slot
                // - key list: Show which LUKS slots are in use (cryptsetup luksDump)
                eprintln!("{}: This key command is not yet implemented.", "Error".red());
                Ok(())
            }
        }
    }

    fn key_show(&self, name: &str, use_base64: bool) -> Result<(), Error> {
        let key_file_name = format!("{}.key.gpg", name);
        let key_file = backend::find_key_file(&key_file_name)?;
        
        eprintln!("  Found key file at: {}", key_file);
        eprintln!();
        
        if use_base64 {
            // Decrypt and base64 encode (for binary LUKS keys)
            let gpg = ProcessCommand::new("gpg")
                .args(["--decrypt", "--quiet", &key_file])
                .output()?;
            
            if !gpg.status.success() {
                return Err(Error::MountFailed("Failed to decrypt key".to_string()));
            }
            
            use std::io::Write;
            let mut encoder = ProcessCommand::new("base64")
                .stdin(std::process::Stdio::piped())
                .stdout(std::process::Stdio::inherit())
                .spawn()?;
            
            encoder.stdin.take().unwrap().write_all(&gpg.stdout)?;
            encoder.wait()?;
        } else {
            // Decrypt to stdout directly
            let status = ProcessCommand::new("gpg")
                .args(["--decrypt", &key_file])
                .status()?;
            
            if !status.success() {
                return Err(Error::MountFailed("Failed to decrypt key".to_string()));
            }
        }
        
        Ok(())
    }
}

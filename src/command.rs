use clap::Subcommand;

#[derive(Subcommand)]
pub enum Command {
    Init,
    /// Add an existing secret to config
    Add {
        /// Secret name
        name: String,
        /// Mount path
        #[arg(long, short = 'm')]
        mount: String,
        /// Backend type: luks or gocryptfs
        #[arg(long, short = 't')]
        backend_type: String,
        /// Path to encrypted data (image file for LUKS, directory for gocryptfs)
        #[arg(long, short = 'p')]
        path: String,
    },
    Remove { name: String },
    /// Create a new encrypted secret
    Create {
        /// Secret name (if omitted, interactive mode)
        name: Option<String>,
        /// Mount path
        #[arg(long, short = 'm')]
        mount: Option<String>,
        /// Backend type: luks or gocryptfs
        #[arg(long, short = 't')]
        backend_type: Option<String>,
        /// Directory for encrypted data (image/folder created inside)
        #[arg(long, short = 'p')]
        path: Option<String>,
        /// Size in MB for LUKS image (default: 100)
        #[arg(long, short = 's')]
        size: Option<u32>,
    },
    List,
    Open { name: Option<String> },
    Close { name: Option<String> },
    Delete { name: String },
    /// Key management for LUKS volumes (not yet implemented)
    Key {
        #[command(subcommand)]
        action: KeyCommand,
    },
}

/// Key management subcommands
#[derive(Subcommand)]
pub enum KeyCommand {
    /// Show the decrypted key (for backup purposes)
    Show {
        name: String,
        /// Output as base64 (useful for binary LUKS keys)
        #[arg(long)]
        base64: bool,
    },
    /// Create a new key file and add it to a LUKS slot (not yet implemented)
    Create { name: String },
    /// Add an existing key file to a LUKS slot (not yet implemented)
    Add { name: String },
    /// Remove a key from a LUKS slot (not yet implemented)
    Remove { name: String },
    /// List which LUKS key slots are in use (not yet implemented)
    List { name: String },
}

# Introduction

Secrets is a CLI tool for managing encrypted volumes using LUKS and gocryptfs. It handles creating, mounting, and unmounting encrypted storage with generated GPG-encrypted key files stored on removable media.


https://github.com/user-attachments/assets/68b22b5e-ef51-4a50-add3-7979400aace4


# Setup

**Dependencies:**
- `cryptsetup` - LUKS volume management
- `gocryptfs` - FUSE-based encrypted directories
- `gpg` - Key file encryption
- `fusermount` - Unmounting FUSE filesystems

**Install:**

```bash
cargo build --release
sudo cp target/release/secrets-app /usr/local/bin/secrets
```

**Initialize config:**

```bash
secrets init
```

# Usage and commands
Secrets relies on a removable media with keys stored in the root or in /keys. It automatically finds the key associated with your volume.


Overview of commands:
```bash
secrets create                      # Create a new encrypted volume (interactive)
secrets list                        # List all secrets and their status
secrets open <name>                 # Mount/decrypt a secret
secrets close <name>                # Unmount/encrypt a secret
secrets add <name> ...              # Add an existing encrypted volume to config
secrets remove <name>               # Remove a secret from config (keeps files)
secrets delete <name>               # Delete a secret and its encrypted data
secrets key show <name>             # Show decrypted key (for backup)
secrets key show <name> --base64    # Show key as base64 (for LUKS keys)
```


# Operating Systems
This app currently only works on Linux and supports LUKs and gocryptfs.

Future support for MacOS in exploration with dmg images and veracrypt.

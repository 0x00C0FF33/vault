[Features](#features) · [Installation](#installation) · [Usage](#usage) · [Security](#security) · [Documentation](#documentation) · [Dependencies](#dependencies)

# Vault

**vault** is a **securely encrypted credential manager** with a vim-style TUI, built in Rust.

Self-hosted, local-first architecture - your credentials never touch our servers.

![image](https://github.com/user-attachments/assets/cb5e0fe2-f242-4484-9c12-07a68c6d5796)

<a name="features"></a>
## ✨ Features

- **Secure Storage:** Credential secrets encrypted with ChaCha20-Poly1305 AEAD
- **Strong Key Derivation:** Argon2id with 19 MiB memory cost
- **Hierarchical Keys:** Master Key wraps DEK (Data Encryption Key), DEK encrypts credentials - enables password changes without re-encrypting data
    - **Password** → **Master key** → **DEK (wrapped)** → **Credential secrets**
- **Full-Text Search:** SQLite FTS5 for fast search
- **Search or filter by project/tag:** Organize your credentials and keys via tagging
- **Vim Keybindings:** Modal editing with hjkl navigation
- **TOTP Support:** Generate 2FA codes with countdown timer
- **Password Generator:** Configurable CSPRNG password generation
- **Password Strength Checker:** Evaluates the security of user passwords in real-time, providing feedback on complexity, and length to help users create stronger, safer passwords.
- **Audit Trail:** HMAC-signed logs for tamper detection and activity records
- **Auto-clear clipboard:** Automatically overwrite or wipe clipboard memory with 0-bytes (Zeroization) after 15 seconds
- **Auto-lock:** Automatically lock vault after 3 minutes of inactivity
- **Export:** Flexible credential export with format and encryption options
    - **Formats:** JSON, Plain Text
    - **Encryption:** None (not recommended), GPG (AES-256, requires `gpg`), age (ChaCha20-Poly1305, built in)
    - **Supports filtered export** when search or tag filters are active

<a name="installation"></a>
## ⚡ Installation

### Prerequisites

- Requires [Rust toolchain](https://rustup.rs/) **1.91 or newer** (rustc, cargo) to be installed on your system!

### Quick Install

**Unix (Linux/macOS):**
```bash
git clone https://github.com/iamKimlong/vault.git
cd vault
cargo build --release && sudo install -m 755 target/release/vault /usr/local/bin/vault
```

**Windows:**
```powershell
git clone https://github.com/iamKimlong/vault.git
cd vault
cargo build --release
Copy-Item .\target\release\vault.exe "$env:LOCALAPPDATA\Microsoft\WindowsApps\"
```

Developed and tested on Linux. See [docs/contributing.md](docs/contributing.md#platform-support) for the state of other platforms.

### Alternative Methods

<details>
<summary><b>Manual install (per-user)</b></summary>

```bash
cargo build --release
# Unix
mkdir -p ~/.local/bin && mv target/release/vault ~/.local/bin/
# Ensure ~/.local/bin is in your PATH
```
</details>

<details>
<summary><b>Cargo install</b></summary>

```bash
cargo install --path .
# Installs to ~/.cargo/bin (must be in PATH)
```
</details>

<details>
<summary><b>Development/testing</b></summary>

```bash
cargo run -- /tmp/test.db   # throwaway vault, not your real one
```
</details>

**📜 Note:** whenever you update the `vault`, your credentials will remain unchanged unless you explicitly delete them.

<a name="usage"></a>
## 🚀 Usage

```bash
vault                # default vault
vault /path/to.db    # specific vault file
```

Your vault lives at `~/.local/share/vault/vault.db` on Linux; see [docs/storage.md](docs/storage.md#location) for other platforms.

### Normal Mode
| Key | Action |
|-----|--------|
| `j/k` or `↓/↑` | Navigate up/down |
| `gg` | Go to top |
| `G` | Go to bottom |
| `Ctrl+d` | Half page down |
| `Ctrl+u` | Half page up |
| `Ctrl+f` | Page down |
| `Ctrl+b` | Page up |
| `Enter` | View details |
| `n` | New credential |
| `e` | Edit credential |
| `dd/x` | Delete credential |
| `yy/c` | Copy password |
| `u` | Copy username |
| `T` | Copy TOTP code |
| `Ctrl+t` | Copy TOTP secret |
| `Ctrl+s` | Toggle password visibility |
| `Ctrl+p` | Change master key |
| `Ctrl+l` | Clear message |
| `i` | View logs |
| `t` | View tags |
| `L` | Lock vault |
| `/` | Search |
| `:` | Command mode |
| `?` | Help |
| `q` | Quit |

### Commands
- `:q` - Quit
- `:new` - New credential
- `:project` - New project
- `:changepw` - Change master key
- `:gen` - Generate password
- `:audit` - Verify audit log integrity
- `:log` - View logs
- `:tag` - View existing tags
- `:type <name>` - Filter by credential type; bare `:type` clears it
- `:export` - Export credentials with options
- `:help` - Show help

<a name="security"></a>
## 🛡️ Security

### Encryption
- **ChaCha20-Poly1305** AEAD encryption for credential secrets
- **Argon2id** key derivation (19 MiB, 2 iterations) - resistant to GPU/ASIC attacks
- **HKDF-SHA256** splits the derived secret, so the value stored on disk cannot decrypt anything
- **Unique random salt** per vault

### Key Architecture
- **Master Key** derived from your password via Argon2id - never written to disk
- **Data Encryption Key (DEK)** random 256-bit key that encrypts all credentials
- **Wrapped DEK** - DEK encrypted by Master Key, stored in database
- **Password changes** only re-wrap the DEK - no need to re-encrypt credentials

### Memory Protection
- **Zeroized memory** for sensitive data
- `mlock()`/`VirtualLock()` to prevent key material from swapping to disk (best-effort)
- `PR_SET_DUMPABLE=0` to prevent core dumps (Linux)

### Audit Trail
- **Audit Trail** all sensitive actions logged (unlock, create, read, copy, update, delete, export)
- **HMAC-SHA256** signatures, hash-chained so each entry commits to the one before it
- **Signed chain head** covering the entry count, so truncation is detectable
- **Tamper detection** on unlock and via `:audit` command
- **Detects** modification, timestamp edits, deletion, reordering and truncation - see [docs/security.md](docs/security.md#what-is-detected)

### What is not encrypted

Credential **names, usernames, URLs and tags are stored in plaintext** so full-text search can index them. Anyone with your vault file learns which accounts you hold and under what usernames - but not the secrets. If that metadata is itself sensitive to you, read [docs/security.md](docs/security.md#what-is-protected) first.

### Miscellaneous
- **Auto-lock** after 3 minutes
- **Auto-wipe clipboard** after 15 seconds with zeroization

<a name="documentation"></a>
## 📚 Documentation

Reference documentation for contributors lives in [docs/](docs/):

- [Architecture](docs/architecture.md) - module layering, control flow, invariants
- [Security design](docs/security.md) - threat model, key hierarchy, limitations
- [Storage format](docs/storage.md) - on-disk layout, schema, versioning
- [Contributing](docs/contributing.md) - toolchain, tests, lint policy, conventions

<a name="dependencies"></a>
## ⚙️ Dependencies

### TUI

- [`ratatui`](https://crates.io/crates/ratatui)
- [`crossterm`](https://crates.io/crates/crossterm)

### Database

- [`rusqlite`](https://crates.io/crates/rusqlite)
    Features: `bundled`, `backup`

### Crypto

- [`argon2`](https://crates.io/crates/argon2)
- [`chacha20poly1305`](https://crates.io/crates/chacha20poly1305)
- [`hkdf`](https://crates.io/crates/hkdf)
- [`sha2`](https://crates.io/crates/sha2)
- [`hmac`](https://crates.io/crates/hmac)
- [`sha1`](https://crates.io/crates/sha1)
- [`age`](https://crates.io/crates/age)
- [`rand`](https://crates.io/crates/rand)
- [`subtle`](https://crates.io/crates/subtle)
- [`secrecy`](https://crates.io/crates/secrecy)
- [`zeroize`](https://crates.io/crates/zeroize)
    Features: `derive`

### TOTP

- [`totp-rs`](https://crates.io/crates/totp-rs)
  Features: `otpauth`
- [`url`](https://crates.io/crates/url),
  [`percent-encoding`](https://crates.io/crates/percent-encoding)
  Parsing `otpauth://` URIs; see `crypto/totp.rs::from_uri`

### Clipboard

- [`arboard`](https://crates.io/crates/arboard)

### Serialization

- [`serde`](https://crates.io/crates/serde)
    Features: `derive`
- [`serde_json`](https://crates.io/crates/serde_json)

### Utilities

- [`libc`](https://crates.io/crates/libc)
- [`chrono`](https://crates.io/crates/chrono)
    Features: `serde`
- [`uuid`](https://crates.io/crates/uuid)
    Features: `v4`
- [`hex`](https://crates.io/crates/hex)
- [`base64`](https://crates.io/crates/base64)
- [`dirs`](https://crates.io/crates/dirs)
- [`thiserror`](https://crates.io/crates/thiserror)
- [`anyhow`](https://crates.io/crates/anyhow)

### Development Dependencies

- [`tempfile`](https://crates.io/crates/tempfile)

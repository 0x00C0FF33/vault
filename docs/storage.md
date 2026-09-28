# Storage format

Everything vault persists lives in one SQLite database. There is no
configuration file, no keyring entry and no state elsewhere on disk.

## Location

| Platform | Default path |
| --- | --- |
| Linux | `$XDG_DATA_HOME/vault/vault.db`, else `~/.local/share/vault/vault.db` |
| macOS | `~/Library/Application Support/vault/vault.db` |
| Windows | `%APPDATA%\vault\vault.db` |

Resolved by `dirs::data_dir()` (`app/config.rs`), falling back to the
current directory if unavailable. A path given as the only CLI argument
(`vault /path/to.db`) overrides the default; `vault --help` prints the
resolved default.

The file is plain SQLite: readable by any SQLite client. Confidentiality
comes from the encrypted columns, not from the container. See
[security.md](security.md#what-is-protected) for exactly which columns
those are.

## Tables

### `metadata`

Key/value store for everything that is not a credential.

| Key | Contents |
| --- | --- |
| `schema_version` | Table structure version. Currently `4`. |
| `kdf_version` | Key-derivation format version. Currently `2`. |
| `kdf_salt` | 16-byte Argon2 salt, hex. |
| `kdf_params` | Argon2 cost parameters, JSON. |
| `kdf_verifier` | 32-byte password verifier, hex. |
| `wrapped_dek` | DEK encrypted under the master key, hex. |
| `audit_version` | Audit signing scheme version. Currently `2`. |
| `audit_head` | Signed chain head: HMAC over the entry count and final entry HMAC. |
| `pending_failed_unlocks` | Failed unlock count since last successful unlock. |
| `last_failed_unlock_at` | Timestamp of the most recent failed unlock. |
| `show_usernames` | `false` once usernames are hidden in the list (`U`); absent or `true` shows them. |
| `scrolloff` | Rows kept around the cursor, set by `:set so=<n>`; absent means 5. |

A freshly created vault:

```
kdf_params      = {"memory_cost":19456,"time_cost":2,"parallelism":1,"output_len":32}
kdf_salt        = a6c292521da74c473c679fa843c0d6cb
kdf_verifier    = 2ae834798e481ecda50e87ac390d08593db8718483084b2bdd420816d26e2695
kdf_version     = 2
audit_head      = 9f1c…
audit_version   = 2
schema_version  = 4
wrapped_dek     = 6ca72a6c5c4f260c8b01c24b67e13756…
```

`kdf_salt`, `kdf_params` and `kdf_verifier` are not secret. None of them,
alone or together, can decrypt `wrapped_dek` — that requires the master
key, which is derived from the password and never stored.

### `credentials`

| Column | Type | Encrypted |
| --- | --- | --- |
| `id` | TEXT PRIMARY KEY | no — UUID v4 |
| `name` | TEXT NOT NULL | no |
| `credential_type` | TEXT NOT NULL | no |
| `username` | TEXT | no |
| `encrypted_secret` | TEXT NOT NULL | **yes** |
| `encrypted_notes` | TEXT | **yes** |
| `encrypted_totp_secret` | TEXT | **yes** |
| `url` | TEXT | no |
| `tags` | TEXT NOT NULL | no — JSON array, default `[]` |
| `created_at` | TEXT NOT NULL | no — RFC 3339 |
| `updated_at` | TEXT NOT NULL | no — RFC 3339 |
| `accessed_at` | TEXT | no — RFC 3339 |

Encrypted columns hold hex-encoded `nonce ‖ ciphertext ‖ tag`: a 12-byte
random nonce followed by the ChaCha20-Poly1305 output
(`crypto/encryption.rs`).

Indexes on `credential_type` and `updated_at DESC`.

Search is not a database concern. `apply_search_filter`
(`app/credentials_handler.rs`) matches a lowercased substring against
`name`, `username`, `url` and `tags` in the already-fetched list, so it
finds `hub` inside `GitHub` and narrows whatever the tag and type filters
left rather than issuing a query that would discard them.

Schema 3 and earlier also carried `credentials_fts`, an FTS5
external-content table maintained by three triggers. No query read it, so
v4 removed it — which is why a v3 database is refused rather than opened.

### `audit_log`

| Column | Type | Notes |
| --- | --- | --- |
| `id` | INTEGER PRIMARY KEY AUTOINCREMENT | chain order |
| `timestamp` | TEXT NOT NULL | RFC 3339, signed |
| `action` | TEXT NOT NULL | signed; see below |
| `credential_id` | TEXT | signed |
| `credential_name` | TEXT | signed |
| `username` | TEXT | signed |
| `details` | TEXT | signed |
| `hmac` | TEXT NOT NULL | HMAC-SHA256, hex; covers the row **and** the previous row's hmac |

Indexed on `timestamp DESC`. Chain verification orders by `id`, which is
the sequence entries were signed in.

`action` is one of `create`, `read`, `update`, `delete`, `copy`,
`export`, `import`, `unlock`, `lock`, `failed_unlock`. Any other value
parses to `Unknown` and renders as `UNKNOWN`, so an unrecognised or
corrupt row is never displayed as ordinary activity.

For what the chain detects, see
[security.md](security.md#what-is-detected).

## Format versions

Three independent version numbers, because table structure, key
derivation and audit signing change for different reasons. Each is
checked, and a marker exists only because something branches on it.

### `schema_version` — table structure

Checked at open (`db/schema.rs`). A database carrying a different version
is refused with `DbError::UnsupportedVersion`.

The version is written from the `SCHEMA_VERSION` constant rather than
inlined in the DDL, so bumping the constant cannot stamp new databases
with a number their own check would reject.

Current version: **4**. No conversion code exists; a database at any
other version is rejected.

### `kdf_version` — key material

Checked at unlock (`vault/manager.rs`). Version 2 is the scheme in
[security.md](security.md#key-hierarchy).

### `audit_version` — audit signing

Checked at unlock (`vault/audit.rs`). Version 2 is the hash chain
described in [security.md](security.md#audit-trail).

### Compatibility within a major version

From 1.0.0, every 1.x release opens a vault written by any earlier 1.x
release. A change to any of the three formats ships with conversion code
that upgrades the vault when it is opened, and that code stays for the
rest of 1.x. Dropping it, or changing the export format below
incompatibly, needs a major release.

### Vaults this build cannot open

All three checks are strict: a vault whose `schema_version`,
`kdf_version` or `audit_version` is missing or unrecognised is rejected —
`DbError::UnsupportedVersion` for the first, `VaultError::UnsupportedFormat`
for the others — rather than being read on a guess. Each error names the
version found and the version expected.

Conversion code for pre-1.0 layouts was removed once no such vault
remained. It is still in the git history, so recovering an old vault
means building a revision that had it, opening the vault once to convert
it, and returning to the current build. Version markers are kept
precisely so that a future change has a defined place to branch, and so
an unreadable vault reports *why* instead of appearing corrupt.

## Export formats

Exports are generated from decrypted data and are not part of the
database.

**JSON** — an object with `version`, `exported_at`, `credential_count`
and a `credentials` array. Field names match the decrypted credential.

**Text** — `Key: value` lines per credential, blank-line separated,
omitting empty fields.

Both may be wrapped in GPG or age encryption, or written unencrypted.
An unencrypted export contains plaintext secrets.

## Working with the file directly

Inspecting a vault is a reasonable way to confirm what is stored:

```sh
sqlite3 ~/.local/share/vault/vault.db 'SELECT key, value FROM metadata;'
sqlite3 ~/.local/share/vault/vault.db 'SELECT name, username, url FROM credentials;'
```

Both queries return plaintext. Nothing in `encrypted_secret` is readable
without the password.

Back up by copying the file while the application is closed. `rusqlite`
is built with the `backup` feature, but no scheduled backup is
implemented.

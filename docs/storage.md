# Storage format

Everything vault persists lives in one SQLite database. There is no
configuration file, no keyring entry and no state elsewhere on disk.

## Location

| Platform | Default path |
| --- | --- |
| Linux | `$XDG_DATA_HOME/vault/vault.db`, else `~/.local/share/vault/vault.db` |
| macOS | `~/Library/Application Support/vault/vault.db` |
| Windows | `%APPDATA%\vault\vault.db` |

Resolved by `dirs::data_dir()` (`vault/manager.rs`), falling back to the
current directory if unavailable. A path given as the first CLI argument
overrides the default.

The file is plain SQLite: readable by any SQLite client. Confidentiality
comes from the encrypted columns, not from the container. See
[security.md](security.md#what-is-protected) for exactly which columns
those are.

## Tables

### `metadata`

Key/value store for everything that is not a credential.

| Key | Contents |
| --- | --- |
| `schema_version` | Table structure version. Currently `3`. |
| `kdf_version` | Key-derivation format version. Currently `2`. |
| `kdf_salt` | 16-byte Argon2 salt, hex. |
| `kdf_params` | Argon2 cost parameters, JSON. |
| `kdf_verifier` | 32-byte password verifier, hex. |
| `wrapped_dek` | DEK encrypted under the master key, hex. |
| `audit_version` | Audit signing scheme version. Currently `2`. |
| `audit_head` | Signed chain head: HMAC over the entry count and final entry HMAC. |
| `pending_failed_unlocks` | Failed unlock count since last successful unlock. |
| `last_failed_unlock_at` | Timestamp of the most recent failed unlock. |

A freshly created vault:

```
kdf_params      = {"memory_cost":19456,"time_cost":2,"parallelism":1,"output_len":32}
kdf_salt        = a6c292521da74c473c679fa843c0d6cb
kdf_verifier    = 2ae834798e481ecda50e87ac390d08593db8718483084b2bdd420816d26e2695
kdf_version     = 2
schema_version  = 3
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

### `credentials_fts`

An FTS5 external-content table over `credentials`, indexing `name`,
`username`, `url` and `tags`.

Three triggers keep it synchronised — `credentials_ai` after insert,
`credentials_ad` after delete, `credentials_au` after update. The delete
and update triggers issue FTS5 `'delete'` commands with the *old* row
values, which external-content tables require to stay consistent.

This table is why those four columns are plaintext. FTS5 cannot index
ciphertext.

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

Two independent version numbers, because table structure and key
derivation change for different reasons.

### `schema_version` — table structure

Checked at open (`db/schema.rs`). Version 3 added
`encrypted_totp_secret`. Migrations are additive and idempotent:
`migrate_to_v3` guards its `ALTER TABLE` with a `has_column` check, so
running it twice is harmless.

A vault whose `schema_version` is already current is left alone.

### `kdf_version` — key material

Checked at unlock (`vault/manager.rs`). Version 2 is the scheme in
[security.md](security.md#key-hierarchy). Version 1 is implicit: those
vaults carry a `password_hash` row and no `kdf_version`.

A version 1 vault is converted on its next successful unlock:

1. The legacy row opens the vault once.
2. The DEK is unwrapped.
3. Fresh version 2 key material is derived from the same password.
4. The DEK is re-wrapped under the new master key.
5. New rows are written and `password_hash` is deleted — in one
   transaction.

The DEK is unchanged, so every stored credential remains readable; only
the layer protecting it is replaced. Because the rewrite is a single
transaction, an interrupted conversion leaves the vault openable by the
version 1 path and it is retried on the next unlock.

An incorrect password converts nothing.

### `audit_version` — audit signing

Checked at unlock, after the key hierarchy is available. Version 2 is the
hash chain described in
[security.md](security.md#audit-trail). Version 1 is implicit: entries
signed individually, without the timestamp or a predecessor.

A version 1 log is converted on the next unlock. Each entry is checked
under the version 1 rules and, if it passes, re-signed into the chain. An
entry that fails keeps its stored HMAC, so it continues to report as
tampered instead of being laundered into a valid chain; later entries
chain onto that stored value and verify normally, keeping the damage
attributed to the entry it belongs to.

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

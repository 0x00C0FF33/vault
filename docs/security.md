# Security design

This document describes the cryptographic construction, the boundary
between protected and unprotected data, and the limits of both. Read the
[Threat model](#threat-model) and [What is protected](#what-is-protected)
sections before relying on any property described elsewhere.

## Threat model

vault is a local-first store. There is no server, no sync, and no network
traffic. The attacker it is built to resist is one who obtains the vault
file — through a stolen laptop, a backup, a misplaced USB stick, or read
access to the user's home directory — while the vault is locked.

### Defended

- **Offline attack on the vault file.** Credential secrets are encrypted
  and the key that decrypts them cannot be recovered from the file. An
  attacker must brute-force the password through Argon2id.
- **Password change without re-encryption.** The password protects a key
  that protects the data, so changing it rewrites two rows rather than
  every credential.
- **Swap and core-dump leakage.** Key material is memory-locked and the
  process is marked non-dumpable.
- **Tampering with audit records.** Entries are hash-chained and the
  chain head is signed, so modification, deletion, reordering and
  truncation are all detectable. See [Audit trail](#audit-trail).

### Not defended

- **An attacker with code execution as the user.** They can read the
  process memory of an unlocked vault, log keystrokes, or replace the
  binary. Nothing here defends against that.
- **An unlocked vault on an unattended machine.** Auto-lock reduces the
  window; it does not close it.
- **Metadata disclosure.** Credential names, usernames, URLs and tags are
  stored in plaintext. See [What is protected](#what-is-protected).
- **A malicious or compromised clipboard consumer.** Any application can
  read the system clipboard during the copy window.
- **Physical attacks on RAM** — cold boot, DMA — and hostile kernels or
  hypervisors.
- **Denial of service.** An attacker with write access can corrupt or
  delete the vault file. There is no integrity protection over the
  database as a whole.

## Key hierarchy

Three keys, each with one job.

```
password
   |
   | Argon2id  (salt + cost parameters from metadata)
   v
 root secret ......................................... never stored
   |
   +-- HKDF-SHA256, info="vault:verifier" ---> verifier ---> stored
   |
   +-- HKDF-SHA256, info="vault:master-key" -> master key .. never stored
                                                   |
                                                   | ChaCha20-Poly1305
                                                   v
                                            wrapped DEK ---> stored
                                                   |
                                                   v
                                                  DEK ...... never stored
                                                   |
                        +--------------------------+-------------------+
                        |                                              |
                        v                                              v
              credential secrets                        HKDF, info="audit:log"
              (ChaCha20-Poly1305)                                      |
                                                                       v
                                                                 audit HMAC key
```

Implementation: `crypto/kdf.rs`, `crypto/key_hierarchy.rs`, `crypto/dek.rs`.

### Why the root secret is split

The value stored on disk to check a password and the value that unwraps
the DEK are derived from the same root under **different HKDF labels**.
HKDF is one-way, so possessing the verifier gives no information about
the master key.

This is the property that makes the vault file safe to lose. It rests
entirely on `INFO_MASTER_KEY` and `INFO_VERIFIER` (`crypto/kdf.rs`)
remaining distinct — if they were ever made equal, the stored verifier
would *be* the master key and the file would decrypt itself. The
invariant is asserted by `test_stored_material_cannot_unwrap_dek` and
`test_stored_material_is_not_the_master_key`.

### Why a DEK exists

Credentials are encrypted under a random 256-bit DEK, not under the
password-derived key. The DEK is encrypted ("wrapped") by the master key
and stored in that form. Changing the password re-wraps the DEK under a
new master key; the DEK, and therefore every ciphertext, is untouched.

The DEK is generated once at vault creation and never rotates. Rotating
it would require re-encrypting every credential and is not implemented.

## Primitives

| Purpose | Primitive | Parameters |
| --- | --- | --- |
| Password stretching | Argon2id | m = 19456 KiB (19 MiB), t = 2, p = 1, 32-byte output, 16-byte random salt |
| Subkey derivation | HKDF-SHA256 | salt `vault-kdf-v2`, distinct info labels |
| Secret encryption | ChaCha20-Poly1305 | 256-bit key, 96-bit random nonce per operation |
| DEK wrapping | ChaCha20-Poly1305 | as above, key = master key |
| Audit signatures | HMAC-SHA256 | key derived from DEK |
| TOTP | HMAC-SHA1, or SHA-256/512 when an `otpauth://` URI asks for it | per RFC 6238; SHA-1 is the default the standard mandates |

Argon2id parameters meet the OWASP minimum. They are stored per vault in
`kdf_params`, so a vault created under one setting keeps opening after
the default changes — but note that nothing currently re-derives a vault
under stronger parameters. Raising the default only affects new vaults.

Nonces are random per encryption, 96 bits. ChaCha20-Poly1305 tolerates
this: with random nonces the birthday bound is far beyond any plausible
number of credential writes.

## What is protected

This is the most important table in this document. **Only three fields
are encrypted.**

| Field | Storage | Visible to anyone with the file |
| --- | --- | --- |
| `encrypted_secret` | ChaCha20-Poly1305 | no |
| `encrypted_notes` | ChaCha20-Poly1305 | no |
| `encrypted_totp_secret` | ChaCha20-Poly1305 | no |
| `name` | plaintext | **yes** |
| `username` | plaintext | **yes** |
| `url` | plaintext | **yes** |
| `tags` | plaintext | **yes** |
| `credential_type` | plaintext | **yes** |
| timestamps | plaintext | **yes** |
| audit log contents | plaintext, signed | **yes** |

An attacker with the vault file learns which services you hold accounts
for, under which usernames, at which URLs, how you have grouped them, and
when you last touched each one. They do not learn the secrets.

This is a deliberate trade, not an oversight: the credential list is
rendered from these columns and searched over them
(`app/credentials_handler.rs`), which requires them in the clear.
Encrypting them would mean decrypting every row to draw a list or match a
query — not implemented, and not free.

If credential *names* are themselves sensitive in your threat model,
vault is not sufficient on its own.

## Memory protection

- **Memory locking.** `LockedBuffer<N>` (`crypto/mod.rs`) calls `mlock()`
  on Unix and `VirtualLock()` on Windows so key pages are not written to
  swap. Locking may fail under `RLIMIT_MEMLOCK`; failure is tolerated and
  the program continues, so this is best-effort rather than guaranteed.
- **Zeroization.** Buffers holding key material are zeroed on drop
  regardless of lock status. Intermediate arrays are explicitly zeroized
  after being copied into a locked buffer.
- **Non-dumpable process.** `harden_process()` (`main.rs`) sets
  `PR_SET_DUMPABLE = 0` so the kernel refuses to write a core dump.
- **Debug redaction.** `MasterKey`, `DerivedKey` and `DataEncryptionKey`
  implement `Debug` without printing bytes, so key material cannot reach
  a log through formatting.
- **Secret wrappers.** Decrypted values are held in `secrecy::SecretString`,
  requiring an explicit `expose_secret()` call to read.

Rust's ownership model does not prevent copies. Values moved through
`String` or `Vec` before reaching a locked buffer may leave residue on
the heap; the guarantees above cover key material, not every transient
copy of a plaintext secret.

## Audit trail

Sensitive actions — unlock, create, read, copy, update, delete, export —
are written to `audit_log`, each row signed with HMAC-SHA256 under a key
derived from the DEK (`vault/audit.rs`).

Entries form a hash chain. Each signature covers the entry's own fields
*and* the HMAC of the entry before it:

```
hmac[i] = HMAC(audit_key, hmac[i-1] ‖ timestamp ‖ action
                          ‖ credential_id ‖ credential_name
                          ‖ username ‖ details)
```

The first entry chains onto a fixed genesis string. Fields are
length-prefixed before signing, so no arrangement of field contents can
produce another arrangement's message.

Removing or reordering an entry changes what the next entry chains onto,
so that entry stops verifying. Deleting from the *end* leaves a
self-consistent chain, so the head — the entry count and the final HMAC —
is signed separately and stored in `audit_head`.

Verification walks entries in `id` order. Each is checked against its
predecessor's **stored** HMAC rather than the recomputed one, so a
modified entry flags only itself and attribution stays precise.

Both checks run on unlock and on demand via `:audit`. Comparisons are
constant-time.

### What is detected

| Manipulation | Detected by |
| --- | --- |
| Modifying a signed field | that entry's signature |
| Editing a timestamp | that entry's signature |
| Deleting an entry | the following entry's chain link |
| Reordering entries | the chain |
| Deleting from the end | the signed head |
| Forging or re-signing entries | requires the audit key, derived from the DEK |

### Limitations

- **Whole-database rollback is not detected.** Replacing the vault file
  with an older complete copy yields a valid chain and a valid head.
  Defending against this needs an anchor outside the file.
- **Detection is not prevention.** An attacker with write access can
  still destroy the log; verification tells you that it happened, not
  that it did not.
- **The key lives with the data.** The audit key derives from the DEK, so
  an attacker who learns the password can rewrite the entire log
  undetectably. The chain protects against tampering by someone who has
  the file but not the password.

## Clipboard

Copied secrets are cleared after 15 seconds (`app/clipboard.rs`). The
in-process copy is zeroized, and a generation counter ensures a later
copy supersedes an earlier pending clear rather than being wiped by it.

Once a secret reaches the system clipboard it is outside vault's control:
any process may read it, clipboard managers may persist it to disk, and
on some desktop environments the contents may sync to other devices.

## Auto-lock

The vault locks after 3 minutes measured from the last user activity, not
from unlock (`app/config.rs`, `vault/manager.rs`). Locking drops the key
hierarchy and the database handle, so the DEK and master key leave memory.

## Export

Exports are written as JSON or plain text, optionally encrypted with GPG
(AES-256) or age (ChaCha20-Poly1305), both invoked as external processes.

An unencrypted export is plaintext credentials on disk with no protection
whatsoever. The option exists because it is occasionally necessary; it
should be treated as a deliberate, temporary act.

The two backends work differently:

- **GPG** is an external process, invoked with `--passphrase-fd 0` and
  the passphrase written to stdin, so it never appears in the process
  table. It must be installed.
- **age** is linked in as a library (the `age` crate) rather than shelled
  out. The passphrase never leaves the process, and no `age` binary is
  required. Output is standard age format and decrypts with `age -d`.

age is used in-process because the `age` CLI reads passphrases from the
controlling terminal, which this program holds in raw mode; driving it
non-interactively would require a pty.

## Reporting

Security issues should go to the repository maintainer privately rather
than through a public issue.

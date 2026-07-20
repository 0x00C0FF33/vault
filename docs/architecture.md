# Architecture

vault is a single-binary terminal application. There is no daemon, no IPC
and no network layer. All state lives in one SQLite file and in the
process's memory while unlocked.

## Layering

Five layers. Dependencies point downward only.

```
        main.rs            process setup, terminal lifecycle, top-level loop
           |
           v
          app/             application state, action dispatch, orchestration
           |
     +-----+-----+
     |           |
     v           v
   ui/         input/      rendering            key -> Action translation
     |           |
     +-----+-----+
           |
           v
        vault/             domain operations: unlock, credentials, audit, export
           |
     +-----+-----+
     |           |
     v           v
   crypto/      db/        keys and ciphers      SQLite persistence
```

**The dependency rule:** `crypto/` and `db/` know nothing above them.
`vault/` composes them into domain operations and is the only layer that
uses both. `ui/` renders a state snapshot and never touches `vault/` or
`db/` directly. `input/` maps keys to `Action` values and holds no
application state.

The practical consequence: rendering cannot mutate the vault, and the
crypto layer cannot be made to depend on UI concerns. A change to key
handling should not require touching anything under `ui/`.

## Modules

| Module | Responsibility |
| --- | --- |
| `main.rs` | Terminal setup/teardown, `PR_SET_DUMPABLE`, unlock prompt, event loop |
| `app/` | `App` state, action execution, clipboard, auto-lock timing |
| `app/input.rs` | Routes a key to a handler based on the current mode |
| `input/keymap.rs` | Key + modifier to `Action`; the binding table |
| `input/modes.rs` | Modal state machine and the shared text buffer |
| `ui/renderer.rs` | Draws a frame from a `UiState` snapshot |
| `ui/components/` | Widgets: list, detail, form, dialogs, logs, tags, export |
| `vault/manager.rs` | Vault lifecycle: initialize, unlock, lock, change password |
| `vault/credential.rs` | Encrypt/decrypt credential fields |
| `vault/audit.rs` | HMAC-signed audit records |
| `vault/search.rs` | Search and tag filtering |
| `vault/export.rs` | Export formats and external encryption |
| `crypto/kdf.rs` | Argon2id + HKDF derivation, verifier |
| `crypto/key_hierarchy.rs` | Master key, DEK, subkey derivation |
| `crypto/dek.rs` | DEK generation, wrapping, re-wrapping |
| `crypto/encryption.rs` | ChaCha20-Poly1305 |
| `crypto/mod.rs` | `LockedBuffer`, error types |
| `db/schema.rs` | DDL, FTS triggers, migrations |
| `db/queries.rs` | All SQL; parameterised without exception |
| `db/models.rs` | Row types |

## Control flow

### Startup and unlock

```
main
 └─ harden_process()            PR_SET_DUMPABLE = 0
 └─ terminal setup              raw mode, alternate screen
 └─ run_with_auth
     └─ Vault::state()          Uninitialized | Locked | Unlocked
     └─ prompt for password
     └─ Vault::unlock
         ├─ load_key_material   metadata rows
         ├─ verify + derive     Argon2id, HKDF, constant-time compare
         ├─ load_wrapped_dek
         └─ unwrap DEK          ChaCha20-Poly1305
     └─ event loop
```

`Vault::unlock` branches on the stored format version. See
[storage.md](storage.md#format-versions).

### The event loop

One iteration per input event or tick:

```
crossterm event
  -> App::handle_key_event
       -> resolve_action(mode, key)      input/keymap.rs
       -> execute_action(action)         app/actions.rs
            -> vault/ operation
            -> db/ read or write
            -> audit log entry
  -> App::ui_state()                     snapshot for rendering
  -> Renderer::draw(state)               ui/renderer.rs
```

Rendering takes an immutable snapshot. A widget cannot mutate application
state, so a redraw is always safe to repeat.

### Reading a credential

```
Action::CopySecret
  -> App looks up selected Credential      plaintext row
  -> Vault::dek()                          fails if locked
  -> decrypt_credential                    ChaCha20-Poly1305
  -> SecretString                          requires expose_secret()
  -> clipboard::copy_with_timeout          spawns clearing thread
  -> audit::log_action(Copy, ...)          HMAC-signed
```

Every path that reaches a secret goes through `Vault::dek()`, which
returns `VaultError::Locked` unless the key hierarchy is present. Locking
drops that hierarchy, so no code path can read a secret from a locked
vault.

## Modal input

Modes are a state machine in `input/modes.rs`:

```
        +------------------ Esc -------------------+
        |                                          |
     Normal --- i/n/e ---> Insert                  |
        |  --- : -------> Command  --- Enter ----> |
        |  --- / -------> Search   --- Enter ----> |
        |  --- ? -------> Help                     |
        |  --- i -------> Logs                     |
        |  --- t -------> Tags                     |
        |  --- :export -> Export                   |
        |                                          |
     Confirm <--- destructive action --------------+
```

`App::resolve_action` (`app/input.rs`) dispatches on the current mode.
The match is exhaustive over `InputMode` — adding a mode is a compile
error until it is handled, which is deliberate.

For the full path from a raw `KeyEvent` to a text-buffer mutation,
including the separate route the credential form and export dialog take,
see [keymap.md](keymap.md).

Popup modes (Help, Logs, Tags) share a handler shape: an exit check that
may claim the key, then scroll handling. The exit check returns
`ExitOutcome`, distinguishing "not my key" from "handled, nothing to do"
from "handled, run this action".

## Concurrency

The application is single-threaded apart from clipboard clearing.

`clipboard::copy_with_timeout` spawns a detached thread that sleeps for
the timeout, zeroizes its copy, and clears the system clipboard. A global
`AtomicU64` generation counter means a newer copy supersedes an older
pending clear rather than being wiped by it.

There is no shared mutable state between these threads and the main loop;
the clipboard thread owns its buffer.

## Error handling

- `crypto/` returns `CryptoResult<T>` with a `CryptoError` enum.
- `db/` returns `DbResult<T>` with `DbError`.
- `vault/` returns `VaultResult<T>` with `VaultError`, converting from
  both of the above.
- `app/` and `main.rs` use `Box<dyn Error>` at the boundary, where the
  error becomes a user-facing message.

Crypto errors are deliberately coarse at the boundary. A wrong password
yields `VaultError::InvalidPassword` whether the failure was in
derivation or comparison, so the message does not distinguish cases.

Errors surfaced to the user go through `App::set_message` and appear in
the status line. Failures during rendering are not recoverable and abort
after terminal restoration.

## Invariants

Properties the code relies on. Breaking one is a bug even if it compiles:

1. **A locked vault holds no key material.** `lock()` clears the key
   hierarchy, key material and database handle.
2. **Secrets reach the UI only as `SecretString`.** Rendering a secret
   requires an explicit `expose_secret()`.
3. **All SQL is parameterised.** No query is built by concatenating user
   input. `has_column` (`db/schema.rs`) formats identifiers into a pragma
   query, but its arguments are compile-time constants, never user input.
4. **The rendering path is read-only.** `ui/` receives `UiState` and
   returns nothing.
5. **Every state-changing credential operation writes an audit entry.**
6. **HKDF labels are distinct.** See
   [security.md](security.md#why-the-root-secret-is-split).

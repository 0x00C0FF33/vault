# Contributing

## Toolchain

Rust **1.91 or newer**, declared as `rust-version` in `Cargo.toml`.

Two things set the floor: edition 2024 needs 1.85, and
`Duration::from_mins` (`app/config.rs`) stabilised in 1.91. Cargo enforces
the declared minimum, so an older toolchain fails with a clear message
rather than a confusing type error.

No nightly features are used.

## Build and test

```sh
cargo build                 # debug
cargo build --release       # optimised, LTO, stripped
cargo test                  # 120 tests, all in-crate
cargo clippy --all-targets  # must be silent
cargo run -- /tmp/test.db   # run against a throwaway vault
```

Run against a throwaway path during development. The default path is a
real vault.

Tests are unit tests inside their modules — the crate is a binary, so
there is no `tests/` directory and no public API to integrate against.
Tests that need a database use `tempfile::TempDir` and an on-disk or
in-memory SQLite instance.

Tests involving key derivation use `KdfParams::testing()` (1 MiB, one
iteration) rather than the production parameters, which would make the
suite take minutes. Never use those values outside `#[cfg(test)]`.

## Lint policy

`cargo clippy` must produce no output. Pedantic is enabled at **deny** in
`Cargo.toml`, so a violation fails the build:

```toml
[lints.clippy]
pedantic = { level = "deny", priority = -1 }
```

Run it as plain `cargo clippy`. Passing `-W clippy::pedantic` on the
command line re-levels the whole group and discards the manifest's
exceptions, which produces warnings that the project has deliberately
resolved.

### Exceptions

Four lints are allowed project-wide in `Cargo.toml`, each with a reason:

| Lint | Why |
| --- | --- |
| `trivially_copy_pass_by_ref` | Would churn public signatures to pass 1-byte `Copy` enums by value |
| `many_single_char_names` | Crypto code uses conventional short names |
| `similar_names` | As above |
| `struct_field_names` | As above |

Everything else is scoped to the code it applies to, with a comment
saying why:

- `ui/mod.rs` — `cast_possible_truncation`. ratatui's geometry API is
  `u16` throughout, so narrowing from `usize` is pervasive and a terminal
  wide enough to truncate does not exist.
- `input/keymap.rs`, `ui/components/statusline.rs` — `match_same_arms`.
  These matches are lookup tables; one arm per binding is the point, and
  merging identical arms hides which keys are bound.
- `crypto/password_gen.rs` — cast lints on `password_strength`, where
  entropy is non-negative and every arm is bounded to `0..=100`, so the
  narrowing is an intended floor. Also `struct_excessive_bools` on
  `PasswordPolicy`, whose four character-class toggles are the
  conventional shape for a generator policy.
- `db/connection.rs` — `needless_pass_by_value` on `make_dir_error`, kept
  by value so it stays point-free in `map_err`.

**Prefer a scoped exception to a global one.** A blanket allow in the
manifest silences code that has not been looked at; an attribute next to
the code documents a decision. Add to the manifest table only when the
lint is wrong for the whole codebase.

Adding an exception means adding the comment explaining it. An
undocumented `#[allow]` will be questioned in review.

## Code style

- Guard clauses over nesting. Prefer `let ... else` and early return.
- Functions do one thing; extract rather than comment sections.
- Names state intent. A function returning `Result` should be able to
  fail — see the commit history for signatures corrected on that basis.
- No `unwrap()` outside tests, except where a panic is genuinely correct
  and the reason is written down.
- Comments explain *why*. The code already says what.

## Security-sensitive changes

Changes under `crypto/`, or to anything that reads or writes key material,
carry extra requirements:

1. **Do not invent constructions.** Use the vetted crates already
   present. New primitives need a specific reason.
2. **Key material goes in `LockedBuffer`.** Zeroize intermediate buffers
   after copying into one.
3. **Never persist a value that can decrypt data.** The verifier written
   to disk must not unwrap the DEK. This is asserted by
   `test_stored_material_cannot_unwrap_dek` — if that test fails, the
   change is wrong regardless of what else passes.
4. **Compare secrets in constant time**, via `subtle::ConstantTimeEq`.
5. **`Debug` must not print key bytes.** Follow the existing
   `finish_non_exhaustive()` pattern.
6. **Changing derivation requires a version bump and a migration.**
   `kdf_version` identifies the scheme; see
   [storage.md](storage.md#format-versions). A vault that exists must
   keep opening.

Read [security.md](security.md) before changing anything in this area.

## Commits

Conventional Commits, matching the existing log:

```
type(scope): imperative subject under 72 characters

Body explaining why, wrapped at 72. The diff shows what.
```

Types in use: `feat`, `fix`, `refactor`, `style`, `test`, `docs`,
`chore`.

- One concern per commit. If the subject needs "and", it is two commits.
- Every commit must build and pass tests on its own — the history is
  expected to be bisectable. Order matters: fix violations before
  enabling the lint that forbids them.
- No AI attribution or tool advertising in messages.

Verify a series before pushing:

```sh
git rebase --exec 'cargo test --quiet' origin/main
```

## Adding features

Common changes and where they land:

**A new key binding** — add the `Action` variant in `input/keymap.rs`,
map the key, handle it in `app/actions.rs`, document it in the README
table.

**A new credential field** — migration in `db/schema.rs` with a version
bump, column in `db/models.rs`, encrypt/decrypt in
`vault/credential.rs` if it is secret, form field in
`ui/components/form.rs`, and a line in the
[storage.md](storage.md#credentials) table stating whether it is
encrypted.

**A new export format** — variant in `ExportFormat`, serialiser in
`vault/export.rs`, option in `ui/components/export.rs`.

**A new mode** — variant in `InputMode` (`input/modes.rs`), then follow
the compiler: `App::resolve_action` matches exhaustively, so every site
needing an update will fail to build.

## Platform support

Developed and tested on Linux. Windows has memory-locking support
(`VirtualLock`) and a documented install path.

macOS is not currently verified. `harden_process()` (`main.rs`) is gated
on `#[cfg(unix)]` but calls `libc::prctl` with `PR_SET_DUMPABLE`, which
the `libc` crate exposes on Linux and Android only — the gate is wider
than the call it guards. Anyone building on macOS should expect to
narrow that to `#[cfg(target_os = "linux")]` and decide what the
equivalent hardening is.

Clipboard handling has separate Linux (X11 and Wayland) and non-Linux
paths in `app/clipboard.rs`.

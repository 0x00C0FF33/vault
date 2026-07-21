# vault documentation

Reference documentation for people working on vault. It describes how the
program is built and why, not how to use it — for usage see the top-level
[README](../README.md).

## Contents

- **[architecture.md](architecture.md)** — module layering, the dependency
  rule, and how a keystroke becomes a database write.
- **[keymap.md](keymap.md)** — the key handling pipeline in detail, from
  crossterm event to text-buffer mutation.
- **[security.md](security.md)** — threat model, key hierarchy, what is and
  is not encrypted, and the limitations that follow.
- **[storage.md](storage.md)** — on-disk format: tables, metadata keys,
  and format versioning.
- **[contributing.md](contributing.md)** — toolchain, tests, lint policy,
  and commit conventions.

## Conventions

Source references are given as `path:line` against the current tree. Line
numbers drift; the surrounding function name is the durable anchor.

Statements about behaviour describe what the code does today. Where a
design has a known weakness it is stated in the text rather than omitted —
a document that only lists strengths cannot be used to reason about risk.

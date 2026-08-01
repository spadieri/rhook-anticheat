# rhook-anticheat

**A defensive anti-cheat scanner — the same low-level primitives as
[rhook](https://github.com/spadieri/rhook), used in the opposite
direction.**

> Research / educational project. It inspects processes you own to
> demonstrate how a defender detects the very techniques rhook teaches
> (DLL injection, inline hooking, thread manipulation). Not for use
> against software you do not control.

## What it does

`rhook-anticheat` attaches to a target process and compares what is
actually running against what should be running:

- **Injected modules** — modules loaded from unexpected paths, or absent
  from the on-disk image set.
- **Changed code** — the running bytes against a clean reference image,
  first at every exported function's entry point, then across every
  executable section wholesale. The section sweep is the one that
  matters: IL2CPP compiles game methods without exporting them, so an
  export-driven check would be blind to the most common hook target. A
  detour shows up as the bytes it actually changed, with the address and
  a hex dump of both sides.
- **Foreign threads** — threads whose start address falls outside every
  mapped module (the classic `CreateRemoteThread` tell). This one cannot
  see `LoadLibrary` injection, whose thread starts inside a properly
  loaded module; that is the module check's job, and the code says so.

Every stage reports **what it examined**, not only what it objected to,
and regions it could not validate are counted rather than passed over —
an unchecked region is a coverage gap, not a clean bill of health.

It is the mirror of the offensive engine: both are built on the same
memory / module / process helpers, so studying one clarifies the other.

## Relationship to rhook

This repo is a standalone consumer of
[`rhook`](https://github.com/spadieri/rhook). It
depends on the `rhook-common` crate (process / memory / module helpers,
PE parser) via a pinned git revision — see `Cargo.toml`. The scanner was
extracted from the framework monorepo so its research direction can grow
on its own cadence.

## Build & run

```bash
cargo build --release
cargo run --release -- <process-name-or-pid>
```

Options:

| Flag | Effect |
| --- | --- |
| `--watch` | Keep scanning; each finding is reported once, not every pass. |
| `--verbose`, `-v` | Show what was examined and skipped, not just the findings. |
| `--log <path>` | Write the transcript to a file as well as the console. |
| `--module <name>` | Also check a module by name. Repeatable. |

By default **every** module in the target is checked. `--module` adds to
that; it does not narrow it.

`rhook-common` is fetched over git. If cargo's built-in git transport
cannot authenticate, use the git CLI instead:

```bash
CARGO_NET_GIT_FETCH_WITH_CLI=true cargo build --release
```

## Status

Single-binary scanner, validated end to end against rhook on a live
IL2CPP target: the injected module and the installed hook are both
reported, at the exact address, with the detour visible in the byte
dump.

Known limits, all of them counted and printed rather than hidden:

- Sections the Windows loader rewrites at map time (`fothk` thunks)
  cannot be validated against a disk reference. Where the scanner has
  its own copy of the module loaded it uses that instead, and the
  comparison is meaningful again; where it does not, the region is
  excluded **and reported** as unvalidated.
- Packed or self-modifying code will differ from its disk image for
  reasons that have nothing to do with hooking.
- A kernel-mode or hypervisor-level cheat is out of scope by
  construction: this is a user-mode scanner.

## License

Mozilla Public License 2.0 — see [LICENSE](./LICENSE). Same licence as
[rhook](https://github.com/spadieri/rhook), whose `rhook-common` crate
this links.

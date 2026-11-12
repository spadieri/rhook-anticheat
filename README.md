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
- **Where each hook leads** — every changed region is followed through
  its jumps and trampolines to the code it finally runs. A hook that ends
  in a module with a valid signature (the Steam overlay hooks input and
  window APIs in every game) is counted and named in the summary instead
  of raised as an alert. A hook that goes through a *dispatch thunk* is
  never let through this way: CoreCLR's thunk ends in a generic stub in
  the Microsoft-signed `coreclr.dll`, and so does every Harmony patch on
  an IL2CPP game, legitimate or not.
- **Foreign threads** — threads whose start address falls outside every
  mapped module (the classic `CreateRemoteThread` tell). This one cannot
  see `LoadLibrary` injection, whose thread starts inside a properly
  loaded module; that is the module check's job, and the code says so.
- **Module provenance** — where each module's file lives (Windows, the
  game's directory, elsewhere), whether its Authenticode signature
  verifies, and whether it shadows a `System32` DLL of the same name.
  An unsigned file shadowing a system DLL is the *proxy DLL* pattern —
  how BepInEx, MelonLoader and most Unity cheats get loaded — and it is
  already in place before any scanner can attach, which is why the
  module baseline cannot catch it. With `--manifest`, the game's files
  are also checked against SHA-256 hashes taken from a clean install.
- **Executable memory outside every image** — private or mapped
  executable allocations, and image mappings missing from the module
  list (an unlinked or hand-mapped DLL). A plain IL2CPP game generates no
  code, so on one every such region is a finding; on a Mono game, or
  anything with a JIT, they are expected and reported for the reader to
  judge.

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
| `--manifest <file>` | Check the game's `.dll`/`.exe` files against a hash manifest. |
| `--write-manifest <file>` | Hash every `.dll`/`.exe` under the target's directory into a manifest and exit. Run it on a clean install. It walks the whole directory, so point it at a game, not at something living in `C:\Windows`. |

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

Also run against a modded IL2CPP game (BepInEx 6 + Harmony, Steam
running): the proxy `winhttp.dll`, the Harmony hooks in
`GameAssembly.dll` and the .NET runtime's generated code are all
reported, and the ~160 Steam overlay hooks are attributed to the overlay
instead of drowning them out.

Known limits:

- **Data hooks are invisible.** Only executable sections are compared.
  On IL2CPP the most common technique replaces a pointer instead —
  `MethodInfo->methodPointer`, a vtable entry, an IAT slot — and does not
  change a single byte of `.text`.
- **Hooks without a patch are invisible.** Hardware breakpoints
  (`Dr0`–`Dr3`) paired with a vectored exception handler, or `PAGE_GUARD`
  tricks, change no bytes at all.
- **The scanner is not protected.** It runs at the same privilege as the
  cheat, which can suspend or kill it without the game noticing, and its
  verdict is a local exit code that no server ever receives.
- **It samples.** `--watch` rescans every 2 s, which leaves a window for
  a hook that is installed, used and removed in between. Only PE32+
  (64-bit) targets are supported.
- **Attribution trusts signatures.** A hook that ends in a signed module
  is not alerted. Anyone can buy a code-signing certificate, so the pass
  summary always names the modules that were let through this way.
- Sections the Windows loader rewrites at map time (`fothk` thunks)
  cannot be validated against a disk reference. Where the scanner has
  its own copy of the module loaded it uses that instead, and the
  comparison is meaningful again; where it does not, the region is
  excluded **and reported** as unvalidated.
- Packed or self-modifying code will differ from its disk image for
  reasons that have nothing to do with hooking.
- Windows-directory files are trusted by location: most are
  catalog-signed, which a `WinVerifyTrust` call on the file cannot see.
- **Out of scope by construction:** external cheats that only read
  memory (ESP), cheats that only change values in memory, and kernel-mode
  or hypervisor-level cheats. This is a user-mode, in-process-tampering
  scanner.

## Next steps

1. **Method-pointer integrity** — walk IL2CPP's method metadata and
   check that every `MethodInfo->methodPointer`, vtable slot and IAT
   entry still points inside `GameAssembly.dll`'s code, catching the data
   hooks above.
2. **Patchless hooks** — read each game thread's debug registers with
   `GetThreadContext`, and flag `PAGE_GUARD` pages inside module code.

## License

Mozilla Public License 2.0 — see [LICENSE](./LICENSE). Same licence as
[rhook](https://github.com/spadieri/rhook), whose `rhook-common` crate
this links.

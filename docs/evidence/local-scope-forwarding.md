# Local-scope forwarding evidence

## Root cause from the first hardware attempt

The raw evidence log remains local. This section contains only a derived,
privacy-safe control-flow summary.

The real TOD loader loaded the Broadcom plugin, probe/open succeeded, and
enrollment reached the state-1 capture call. The preload intercepted
`cv_fingerprint_capture_start`, then its old forwarding lookup failed:

```text
symbol resolution failed for cv_fingerprint_capture_start:
undefined symbol: cv_fingerprint_capture_start
```

The loader source explains the result:

```c
g_module_open (module_path, G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
```

`RTLD_NEXT` could not see the original symbol in that local object. No real
`0x66`, `0x6c`, status `0x89`, or experimental repeated `0x8a` was reached.
Ctrl+C produced cancellation completion, `dev_close`, and
`device_closed=yes`; the USB node had no remaining open handle. This was a
forwarding implementation failure, not a protocol result.

## Corrected resolver contract

The runner supplies a canonical absolute target path in
`CV2_0X89_TARGET_PATH`. The interposer:

```text
realpath + stat expected target
  -> dl_iterate_phdr: same canonical path + device + inode required
  -> dlopen(expected, RTLD_LAZY | RTLD_NOLOAD)
  -> dlsym(target_handle, required symbol)
  -> dladdr(symbol): same canonical path + device + inode required
  -> retain handle and cache pointers with pthread_once
```

There is no `RTLD_NEXT` fallback, `RTLD_GLOBAL`, scope promotion, early
`dlclose`, or attempt to load an absent target.

Only `cv_fingerprint_update_enrollment` is interposed. The readiness function
is an experiment control API, not a driver wrapper. Capture start, initial
enrollment start, commit, verify, cancellation, capture-cancel, and discard
are not interposed.

## Proven by new repository-local tests

The fixture uses the same GModule flags as TOD:

```c
g_module_open(plugin_path,
              G_MODULE_BIND_LAZY | G_MODULE_BIND_LOCAL);
```

Tests prove:

- The old `RTLD_NEXT` resolver fails against the local-scope mock.
- The new resolver discovers the already-loaded local target.
- `RTLD_NOLOAD` acquires a target-specific handle without loading another DSO.
- Both required originals resolve from that handle.
- `dladdr` ownership passes for the correct target.
- A symbol supplied by a dependency is rejected as the wrong DSO.
- An IFUNC deliberately returning the interposer wrapper is rejected before
  recursion.
- An absent target remains absent after readiness fails.
- A wrong target path fails before the mock enrollment function runs.
- Duplicate preload and wrong target hash/Build ID profiles are rejected.
- Non-`0x89` statuses passed bit-exact in this resolver test. The later
  bounded `0x59` experiment is documented separately.
- `0x89` plus successful `0x8a` produces the mock logical sequence
  `0x6c -> 0x89 -> 0x8a -> original 0x89 -> 0x66 -> 0x6c`.
- Failed `0x8a` produces exactly one mock capture-cancel and one discard, no
  `0x66`, and no loop.
- Two test builds are byte-identical and leave their validated input
  unchanged. Production target identity is checked separately before use.

These are loader and control-flow tests. They are not hardware evidence.

## Subsequently proven on hardware

- The corrected resolver reached real commands `0x66` and `0x6c`.
- Nine real `0x89 -> 0x8a -> capture` retry cycles completed.
- Three samples were accepted before the separate `0x59` boundary.
- The later bounded `0x59` run passed that boundary and reached host progress
  13/10, but completion remained zero.

Enrollment completion, template commit, and verification remain unproven.

# zmoltcp Fuzzing

zmoltcp fuzzing covers packet-facing parsers, public stack ingress, fragment
reassembly, storage buffers, socket state machines, RPL state, and PHY
middleware. Fuzz targets live in `src/fuzz.zig` and are imported only from
`src/root.zig`'s root test block.

## Policy

- Any new externally influenced parser or packet ingress path needs malformed
  input coverage in the same change.
- Any fuzz failure must become a deterministic regression test before or with
  the fix.
- Harnesses use bounded loops and fixed scratch buffers. Do not add production
  heap allocation to make fuzzing easier.
- Operation-stream fuzzers should call valid public APIs unless the change is
  deliberately hardening that API boundary.

## Local Commands

Run the deterministic suite first:

```bash
mise run test
```

Run a bounded native fuzz pass:

```bash
mise run fuzz
```

The `fuzz` task and CI both use `scripts/fuzz-smoke.sh`, which treats Zig
0.16.0 saved-crash output as a failure even when the build process exits zero.

Use a larger limit, such as `--fuzz=100K`, for local parser or ingress work
when the extra runtime is acceptable. Keep PR and CI limits small enough that
the step is a regression gate, not a long campaign.

Run `mise run check` for the full local suite: tests, demos, bounded fuzz, and
the freestanding cross-compile check.

## Zig 0.16.0 Notes

Use the dedicated `fuzz` build step rather than `zig build test --fuzz`. The
fuzz step builds a threaded test binary and disables error tracing because the
Zig 0.16.0 fuzz runner needs concurrent input polling and fails to compile with
error traces enabled.

The limited fuzz report can print the first registered fuzz test name even when
a later target found the crash. Read the failure stack trace as the source of
truth. Also treat output containing `run test failure`, `terminated with
signal`, `input saved to`, `panic:`, or `failed with error` as a failed fuzz
run even if the build process exits zero.

On GitHub's Linux runners, Zig 0.16.0 can repeatedly fail native fuzzing with
`corrupted coverage file` before executing a target. CI retries that runner
artifact with fresh caches and then falls back to non-instrumented fuzz target
smoke so parser and state-machine fuzz tests still compile and run. Local
`mise run fuzz` does not enable that fallback; coverage corruption should stay
visible during development.

## Failure Flow

1. Reproduce the failure with the saved input from `.zig-cache/f/crash`.
2. Minimize the shape enough to understand the parser or state-machine bug.
3. Add a deterministic test in the module that owns the failed invariant.
4. Fix the code.
5. Rerun `zig build test` and the matching bounded fuzz command.

Do not commit `.zig-cache` artifacts.

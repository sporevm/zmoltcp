# zmoltcp In-Depth Fuzz Testing Plan

Date: 2026-06-18
Status: Implemented for the first native fuzzing slice; scheduled long-run
fuzzing remains deferred.
Goal: Add in-depth fuzz coverage for packet-facing parsers, ingress paths,
fragment reassembly, storage buffers, and socket state machines.

## Summary

zmoltcp already has broad deterministic conformance coverage against smoltcp,
RFC-derived vectors, and end-to-end demos. The missing layer is adversarial
input coverage: arbitrary packets, malformed protocol options, odd fragment
orders, and bounded state-machine operation streams.

The model to copy from SporeVM is simple: every parser or state machine that
accepts attacker-influenced bytes gets a fuzz target in the same slice that
introduces or changes it. Fuzzing is not a one-off audit; it becomes part of
the definition of done for packet-facing work.

The first version stays native to Zig 0.16.0 and the current build system. It
uses `std.testing.fuzz` harnesses, keeps deterministic validation on
`zig build test`, and runs bounded fuzz campaigns through the dedicated
`zig build fuzz --fuzz=<limit>` step before moving to heavier scheduled or
continuous fuzzing.

## Problem

The current suite proves many named examples and reference behaviors. It does
not prove that malformed packets are always rejected cleanly, that parser
loops are bounded, or that state machines keep their invariants when inputs
arrive in unexpected orders.

This matters because zmoltcp is a freestanding network stack. Bytes can come
from Ethernet, raw IP, IEEE 802.15.4, 6LoWPAN, DNS/DHCP servers, peers, and
hostile local networks. A conformance vector is a good regression test, but it
does not explore the shape of invalid input.

Without fuzzing, the highest-risk classes are:

- Out-of-bounds reads or writes in packet parsing and test device helpers.
- Infinite or excessively long loops in DNS compression, IPv6 extension header
  walking, TCP option parsing, 6LoWPAN decompression, and RPL option parsing.
- Reassembly states that accept impossible ranges, overlap oddly, or assemble
  data before the packet is complete.
- Socket state transitions that hit `unreachable`, assertions, or stale buffer
  assumptions when malformed wire input reaches them.
- CI drift where new packet-facing features land with deterministic tests but
  no malformed-input coverage.

## Current State

- `build.zig` exposes `test`, `fuzz`, and `demo` steps. `zig build test`
  compiles `src/root.zig`, whose root test imports every module so tests and
  empty-corpus fuzz smoke checks are collected.
- `build.zig.zon` requires Zig 0.16.0. Local help for that toolchain exposes
  compiler fuzz instrumentation with `-ffuzz` and build-runner fuzzing with
  `zig build --fuzz[=limit]`.
- `README.md`, `SPEC.md`, and `tests/FUZZING.md` document the current fuzzing
  policy and local commands.
- `src/fuzz.zig` contains native `std.testing.fuzz` target groups for P0, P1,
  and P2 surfaces and is imported only from `src/root.zig`'s test block.
- Public ingress already has a reusable Ethernet `LoopbackDevice` in
  `stack.zig`. Existing stack tests also define raw-IP and IEEE 802.15.4
  wrappers that can be lifted into test-only support if ingress fuzzers need
  them outside `stack.zig`. Fuzz harnesses must clamp frames before using
  fixed-frame helpers because their storage is sized to `MAX_FRAME_LEN`.

## Goals

- Add fuzz targets for every externally influenced parser and packet ingress
  path.
- Make fuzz coverage visible in the repo through a surface inventory and
  delivery slices.
- Keep the first implementation compatible with `zig build test` and Zig's
  native fuzzing support.
- Preserve the zero-allocation design: fuzz harnesses may use test-only
  scratch buffers and `std.testing.allocator`, but production code must not
  gain hidden allocation to make fuzzing easier.
- Convert every fuzz failure into a deterministic regression test before or
  alongside the fix.
- Establish a CI split between cheap deterministic checks, bounded PR fuzzing,
  and longer scheduled fuzz campaigns.

## Non-Goals

- Do not replace the smoltcp conformance suite. Fuzzing complements it.
- Do not introduce AFL, libFuzzer wrappers, honggfuzz, or an external corpus
  framework in the first slice.
- Do not make random fuzzing the default success metric for every PR. CI needs
  bounded, understandable gates.
- Do not fuzz invalid calls to private helpers whose preconditions are already
  enforced by typed public APIs, unless the slice deliberately hardens that
  helper into a public fail-closed boundary.
- Do not add heap allocation to production parsing paths for corpus, tracing,
  or minimization convenience.

## Fuzzing Model

Each fuzz target has one of four shapes.

### 1. Raw Byte Parser Fuzzers

Feed arbitrary bytes into a protocol parser. The target accepts two outcomes:

- The parser rejects the bytes with an error or `null`.
- The parser returns a representation whose derived slices, lengths, and
  round-trip emission stay inside caller-provided buffers.

Example shape:

```zig
fn fuzzDnsName(_: void, s: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = s.slice(&buf);
    const start = if (len == 0) 0 else s.value(usize) % len;
    _ = dns.parseName(buf[0..len], start) catch return;
}

test "fuzz DNS name parsing" {
    try std.testing.fuzz({}, fuzzDnsName, .{});
}
```

Use this shape for `wire/*` parsers, `payloadSlice` helpers, and parser pairs
where successful parse can be emitted back into a fixed buffer.

### 2. Whole-Ingress Fuzzers

Feed arbitrary frames through the public stack ingress path instead of calling
only low-level parse functions. The target initializes a small stack, gives it
one or more addresses, enqueues a clamped frame, calls `poll`, and drains
bounded TX output.

This catches interactions between Ethernet/IP demux, neighbor caches,
fragmentation, socket routing, ICMP error generation, and egress serialization.
It also verifies malformed frames fail closed at the same boundary a consumer
uses.

Use separate targets for:

- Ethernet medium.
- Raw IP medium.
- IEEE 802.15.4 medium with 6LoWPAN enabled.

### 3. Bounded Operation-Stream Fuzzers

Use `std.testing.Smith` to choose a bounded sequence of valid operations
against a state machine or storage type. This mirrors SporeVM's budgeted MMIO
and virtqueue harnesses.

The harness should maintain its own model-level invariants after each step:

- Length never exceeds capacity.
- Dequeued bytes were previously enqueued.
- Reassembly returns only after the contiguous front reaches total size.
- Socket buffers and sequence numbers move monotonically according to the TCP
  state being exercised.
- `pollAt` never moves into an impossible time range.

Use this shape for `storage/assembler.zig`, `storage/ring_buffer.zig`,
`storage/packet_buffer.zig`, `fragmentation.zig`, TCP sockets, DNS sockets,
DHCP sockets, and RPL timers.

### 4. Corpus-To-Regression Flow

Do not rely on fuzz campaigns as the only proof after a failure. When fuzzing
finds a crash, hang, assertion, or invariant violation:

1. Minimize the input enough to understand the bug.
2. Add a deterministic unit test or conformance-style regression test.
3. Fix the code.
4. Keep the fuzz target broad so related shapes remain covered.

The existing smoltcp vectors, RFC arrays, and examples should remain
deterministic tests. They can inform fuzz harness setup, but the first version
does not need a separate seed-corpus format.

## Target Surface Inventory

| Priority | Surface | Input Source | First Fuzz Target | Core Invariants |
|---|---|---|---|---|
| P0 | DNS names, questions, records, and resolver responses | DNS/mDNS peers | `wire/dns.zig`, `socket/dns.zig` | Compression pointers terminate, label count is bounded, CNAME rewrites stay inside fixed name buffers. |
| P0 | TCP header and options | Remote TCP peers | `wire/tcp.zig` | Option cursor always advances or returns, parsed options fit the header length, emit length is bounded by 60 bytes. |
| P0 | IPv4/IPv6 headers and payload slicing | Remote IP peers | `wire/ipv4.zig`, `wire/ipv6.zig` | Payload slices are clamped to declared lengths and never expose bytes outside the packet. |
| P0 | IPv6 extension header walking | Remote IPv6 peers | `wire/ipv6ext_header.zig`, stack IPv6 ingress | Extension chains remain bounded; declared lengths cannot stall or overrun payload slicing. |
| P0 | Stack ingress for Ethernet and raw IP | Device RX | `stack.zig` harnesses | Malformed frames are dropped or produce bounded error responses; TX frames never exceed device MTU. |
| P0 | IPv4/IPv6/6LoWPAN reassembly | Fragmented peers | `fragmentation.zig`, `stack.zig` | Overlaps, gaps, eviction, expiry, and oversized offsets fail closed or assemble only complete data. |
| P1 | NDP, MLD, and ICMPv6 message bodies | IPv6 peers | `wire/ndisc*.zig`, `wire/mld.zig`, `wire/icmpv6.zig` | Option lengths cannot stall or overrun; multicast and hop-limit rules fail closed. |
| P1 | DHCP packets and client processing | DHCP servers | `wire/dhcp.zig`, `socket/dhcp.zig` | Option parsing advances, lease/router/DNS extraction is bounded, malformed offers do not corrupt client state. |
| P1 | IEEE 802.15.4 and 6LoWPAN IPHC/NHC/FRAG | Low-power network peers | `wire/ieee802154.zig`, `wire/sixlowpan*.zig`, 802.15.4 stack ingress | Decompression writes only within scratch buffers, dispatch types fail closed, fragment offsets remain valid. |
| P1 | RPL wire and Trickle state | RPL peers and timers | `wire/rpl.zig`, `rpl.zig` | Option parsing advances, parent/relation tables stay bounded, timer math does not overflow into invalid ranges. |
| P2 | Storage buffers and packet queues | Socket and stack internals | `storage/*.zig` | Public operations preserve capacity, wrap-around order, padding semantics, and assembler hole invariants. |
| P2 | TCP/UDP/ICMP/raw socket state machines | Parsed packet delivery | `socket/*.zig` | Packet processing cannot hit unreachable paths, buffer lengths stay valid, dispatch emits bounded reprs. |
| P2 | PHY middleware fault injection and pcap writer | Test and integration devices | `phy.zig` | Corruption/drop decisions stay bounded and pcap records match frame lengths. |

## Safety Model

Fuzz targets should enforce these rules:

- No panic, assertion failure, integer trap, out-of-bounds access, use-after-free,
  leak, or unbounded loop from malformed external input.
- Malformed input fails closed: parser error, `null`, no socket delivery, no TX,
  or a bounded protocol error response.
- Every successful parse obeys length invariants before any derived slice is
  used by a caller.
- Operation-stream fuzzers generate valid public API calls unless the explicit
  purpose is to harden a public boundary.
- Harness loops must have explicit budgets. Never fuzz a `while (device.receive())`
  path without a fixed device queue size and bounded poll calls.
- Fuzz-only helpers must not become production dependencies.

## Build And CI Contract

The first implementation keeps fuzz tests discoverable by the existing root
test import pattern. The cross-module targets live in `src/fuzz.zig` because
ingress, reassembly, socket, storage, and PHY fuzzers share setup and scratch
helpers. Smaller future fuzzers can still be colocated if they only cover one
module.

Expected local commands:

```bash
mise run test
mise run fuzz
mise run demo
mise run cross
mise run check
```

CI should eventually have three tiers:

- PR deterministic: `zig build test` and `zig build demo`.
- PR bounded fuzz: `zig build fuzz --fuzz=10K --test-timeout 30s`, wrapped so
  Zig 0.16.0 output that saves a crash still fails the CI step.
- Scheduled fuzz: longer P0/P1/P2 campaigns on `master`, allowed to run with
  larger iteration limits and stricter failure artifact capture.

Do not add the scheduled tier until the first two tiers have stable runtime
and a documented failure-to-regression workflow.

## Delivery Strategy

### Phase 0: Fuzz Policy And Build Shape - Complete

Scope:

- Land this plan.
- Add fuzzing policy to `SPEC.md` and operational commands to
  `tests/FUZZING.md`.
- Use one central test-only `src/fuzz.zig` module for reusable ingress devices
  and operation-stream helpers.

Definition of done:

- The repo states which surfaces require fuzz coverage.
- The first implementation PR has a clear command for bounded local fuzzing:
  `mise run fuzz`.
- CI fuzz coverage is only claimed after `src/fuzz.zig` targets exist.

### Phase 1: P0 Raw Parser Fuzzers - Complete

Scope:

- Add `std.testing.fuzz` targets for DNS name/record parsing, TCP header/options
  parsing, IPv4 payload slicing, IPv6 payload slicing, and IPv6 extension header
  parsing.
- Keep targets in `src/fuzz.zig` while they share cross-module scratch setup.
- Add deterministic regression tests for any crash or invariant failure found.

Definition of done:

- `zig build test` passes.
- `mise run fuzz` runs locally through the native fuzz runner.
- Successful parses check at least one invariant beyond "did not crash" where
  the module exposes enough information to do so.

### Phase 2: P0 Ingress And Reassembly Fuzzers - Complete

Scope:

- Add bounded Ethernet and raw-IP ingress fuzzers through `Stack`.
- Add bounded reassembler operation-stream fuzzers for IPv4, IPv6, and 6LoWPAN
  keys.
- Add a frame-clamping helper so test-device fixed arrays do not become the
  target of false-positive oversized `memcpy` crashes.

Definition of done:

- Malformed ingress is exercised at the public `poll` boundary.
- TX output is drained and checked for MTU bounds.
- Reassembly fuzzing covers overlaps, gaps, changed keys, expiry, oversized
  offsets, and last-fragment total-size changes.

### Phase 3: P1 Protocol-Specific Fuzzers - Complete

Scope:

- Add DHCP wire/client fuzzing.
- Add NDP, MLD, ICMPv6, 6LoWPAN, IEEE 802.15.4, and RPL fuzzing.
- Add one operation-stream fuzzer for the RPL state machine, especially parent
  table and relation-table capacity behavior.

Definition of done:

- Every P1 surface has at least one malformed-input target.
- Any parser with variable-length options proves the cursor advances or returns
  on every iteration.
- The 802.15.4 stack ingress target covers both direct IPHC and fragmented
  paths.

### Phase 4: P2 Storage And Socket State Fuzzers - Complete

Scope:

- Add operation-stream fuzzers for `RingBuffer`, `PacketBuffer`, and
  `Assembler`.
- Add socket-level fuzzers where structured parsed reprs are generated from
  `Smith` and fed through `accepts`, `process`, `dispatch`, and `pollAt`.
- Separate valid-operation fuzzing from explicit contract-hardening work.

Definition of done:

- Storage fuzzers maintain an independent shadow model for order and capacity.
- Socket fuzzers do not manufacture impossible private state unless the target
  is specifically testing recovery from internal corruption.
- Any public API that can receive malformed external input fails closed rather
  than relying on `unreachable`.

### Phase 5: CI Hardening And Fuzz Operations - PR Gate Complete, Scheduled Tier Deferred

Scope:

- Add bounded PR fuzzing once runtime is stable.
- Defer scheduled long-running fuzzing for all targets.
- Document how to capture a failure, minimize it, add a regression test, and
  rerun the matching target.

Definition of done:

- CI failures point at the target name and command used.
- Long-running fuzzing does not block ordinary PRs.
- New packet-facing PRs update the surface inventory when they add or change
  externally influenced parsing.

## Verification

Each implementation slice should prove its scope with:

- `mise run test`
- A bounded fuzz command, initially `mise run fuzz`
- `mise run demo` when ingress, socket, or device behavior changes.
- `mise run cross` when build wiring changes.
- Deterministic regression tests for any fuzz-discovered failure.
- A search check that newly changed parser surfaces either have a fuzz target
  or an explicit note in this plan explaining why they are deferred.

## Resolved Decisions

- Use Zig's native `std.testing.fuzz` first. This matches the current toolchain
  and avoids introducing external fuzz runners before the harness boundaries
  are stable.
- Keep the first target set in `src/fuzz.zig`. The initial scope crosses wire,
  stack, storage, socket, RPL, and PHY boundaries, so one test-only module
  avoids duplicating device wrappers and scratch helpers.
- Use a dedicated `fuzz` build step. Zig 0.16.0's fuzz runner needs threaded IO
  and currently fails to compile with error tracing enabled, while the normal
  `test` step should keep its existing deterministic test settings.
- Start with P0 parser and ingress targets before storage-only or socket-only
  fuzzers. Raw network bytes are the direct attacker-influenced surface.
- Treat fuzz failures as regression-test generators, not as one-off bugs to
  patch silently.

## Deferred Work

- External fuzz engines, corpus synchronization, and coverage reporting can
  wait until native Zig fuzzing has more runtime data.
- Performance benchmarking under fuzz instrumentation is deferred. The first
  safety target is crash and invariant discovery, not throughput.
- Cross-target fuzzing for freestanding architectures is deferred until native
  host fuzzing has covered packet parsing and stack ingress.
- Scheduled long-running fuzzing is deferred until the `10K` PR gate is stable
  enough to pick a larger nightly limit.

## Open Questions

- Should crash repro inputs live as standalone binary fixtures or be encoded
  inline in deterministic Zig tests? Default recommendation remains inline
  small minimized repros; add fixtures only when binary size or readability
  demands it.

## Key Learnings From Pressure-Testing

- Fuzzing private helpers with arbitrary invalid calls can create noise when
  the helper is protected by a typed public API. The plan now separates
  valid-operation fuzzing from explicit contract-hardening work.
- Whole-ingress fuzzing must clamp frames before using `LoopbackDevice`;
  otherwise the fixed-size test device can fail before the network stack is
  actually exercised.
- CI should not start with an unbounded fuzz job. The first gate is a bounded
  local and PR command, with scheduled long runs only after target runtime is
  known.
- Successful parses need invariant checks. A fuzz target that only catches
  panics is useful, but it misses semantic bugs like impossible slice lengths,
  oversized TX output, and incomplete reassembly.
- Zig 0.16.0 limited fuzz output is not enough by itself for CI. The report can
  name the first registered fuzz test even when a later target fails, and a
  saved crash may still leave the build process with exit code 0, so CI scans
  the output for failure markers.
- The first `100K` local run found an AH parser integer overflow. The fix added
  a deterministic regression test for payload length values below the minimum
  AH header size.

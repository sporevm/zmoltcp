// Fuzz targets for externally influenced packet, ingress, storage, and socket
// surfaces. Imported only from root.zig's test block.

const std = @import("std");
const testing = std.testing;

const time = @import("time.zig");
const iface = @import("iface.zig");
const stack_mod = @import("stack.zig");
const phy = @import("phy.zig");
const fragmentation = @import("fragmentation.zig");
const rpl_state = @import("rpl.zig");

const ring_buffer_mod = @import("storage/ring_buffer.zig");
const packet_buffer_mod = @import("storage/packet_buffer.zig");
const assembler_mod = @import("storage/assembler.zig");

const arp = @import("wire/arp.zig");
const dhcp = @import("wire/dhcp.zig");
const dns = @import("wire/dns.zig");
const ethernet = @import("wire/ethernet.zig");
const icmp = @import("wire/icmp.zig");
const icmpv6 = @import("wire/icmpv6.zig");
const ieee802154 = @import("wire/ieee802154.zig");
const ipv4 = @import("wire/ipv4.zig");
const ipv6 = @import("wire/ipv6.zig");
const ipv6ext_header = @import("wire/ipv6ext_header.zig");
const ipv6fragment = @import("wire/ipv6fragment.zig");
const ipv6hbh = @import("wire/ipv6hbh.zig");
const ipv6option = @import("wire/ipv6option.zig");
const ipv6routing = @import("wire/ipv6routing.zig");
const igmp = @import("wire/igmp.zig");
const ipsec_ah = @import("wire/ipsec_ah.zig");
const ipsec_esp = @import("wire/ipsec_esp.zig");
const mld = @import("wire/mld.zig");
const ndisc = @import("wire/ndisc.zig");
const ndiscoption = @import("wire/ndiscoption.zig");
const rpl_wire = @import("wire/rpl.zig");
const sixlowpan = @import("wire/sixlowpan.zig");
const sixlowpan_frag = @import("wire/sixlowpan_frag.zig");
const tcp_wire = @import("wire/tcp.zig");
const udp_wire = @import("wire/udp.zig");

const dhcp_socket = @import("socket/dhcp.zig");
const dns_socket = @import("socket/dns.zig");
const icmp_socket = @import("socket/icmp.zig");
const raw_socket = @import("socket/raw.zig");
const tcp_socket = @import("socket/tcp.zig");
const udp_socket = @import("socket/udp.zig");

const LOCAL_HW = ethernet.Address{ 0x02, 0, 0, 0, 0, 1 };
const LOCAL_V4 = ipv4.Address{ 192, 0, 2, 1 };
const REMOTE_V4 = ipv4.Address{ 192, 0, 2, 2 };
const LOCAL_V6 = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 };
const REMOTE_V6 = ipv6.Address{ 0xfe, 0x80, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 2 };

fn fuzzLen(s: *std.testing.Smith, comptime max: usize) usize {
    return if (max == 0) 0 else s.value(usize) % (max + 1);
}

fn fuzzInstant(s: *std.testing.Smith) time.Instant {
    return time.Instant.fromMicros(@intCast(s.value(u32) % 10_000_000));
}

fn fuzzV4(s: *std.testing.Smith) ipv4.Address {
    var addr: ipv4.Address = .{0} ** ipv4.ADDRESS_LEN;
    _ = s.slice(&addr);
    return addr;
}

fn fuzzV6(s: *std.testing.Smith) ipv6.Address {
    var addr: ipv6.Address = .{0} ** ipv6.ADDRESS_LEN;
    _ = s.slice(&addr);
    return addr;
}

fn fuzzIeeeAddr(s: *std.testing.Smith) ieee802154.Address {
    switch (s.value(u8) % 3) {
        0 => return .absent,
        1 => {
            var short: [2]u8 = .{0} ** 2;
            _ = s.slice(&short);
            return .{ .short = short };
        },
        else => {
            var extended: [8]u8 = .{0} ** 8;
            _ = s.slice(&extended);
            return .{ .extended = extended };
        },
    }
}

fn nonzeroPort(v: u16) u16 {
    return if (v == 0) 1 else v;
}

fn drainTx(comptime Device: type, device: *Device, max_len: usize) !void {
    var budget: usize = 16;
    while (budget > 0) : (budget -= 1) {
        const frame = device.dequeueTx() orelse return;
        try testing.expect(frame.len <= max_len);
    }
}

fn RawIpLoopbackDevice(comptime max_frames: usize) type {
    return struct {
        const Self = @This();
        pub const medium: iface.Medium = .ip;

        inner: stack_mod.LoopbackDevice(max_frames) = .{},

        pub fn init() Self {
            return .{};
        }

        pub fn capabilities() iface.DeviceCapabilities {
            return .{};
        }

        pub fn receive(self: *Self) ?[]const u8 {
            return self.inner.receive();
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            self.inner.transmit(frame);
        }

        pub fn enqueueRx(self: *Self, frame: []const u8) void {
            self.inner.enqueueRx(frame);
        }

        pub fn dequeueTx(self: *Self) ?[]const u8 {
            return self.inner.dequeueTx();
        }
    };
}

fn Ieee802154LoopbackDevice(comptime max_frames: usize) type {
    return struct {
        const Self = @This();
        pub const medium: iface.Medium = .ieee802154;

        inner: stack_mod.LoopbackDevice(max_frames) = .{},

        pub fn init() Self {
            return .{};
        }

        pub fn capabilities() iface.DeviceCapabilities {
            return .{ .max_transmission_unit = ieee802154.MAX_FRAME_LEN };
        }

        pub fn receive(self: *Self) ?[]const u8 {
            return self.inner.receive();
        }

        pub fn transmit(self: *Self, frame: []const u8) void {
            self.inner.transmit(frame);
        }

        pub fn enqueueRx(self: *Self, frame: []const u8) void {
            self.inner.enqueueRx(frame);
        }

        pub fn dequeueTx(self: *Self) ?[]const u8 {
            return self.inner.dequeueTx();
        }
    };
}

fn initIfaceAddresses(comptime Stack: type, st: *Stack) void {
    st.iface.v4.addIpAddr(.{ .address = LOCAL_V4, .prefix_len = 24 });
    st.iface.v6.addIpAddr(.{ .address = LOCAL_V6, .prefix_len = 64 });
    _ = st.iface.joinMulticastGroupV6(ipv6.LINK_LOCAL_ALL_NODES);
}

pub fn fuzzDnsParsing(_: void, s: *std.testing.Smith) !void {
    var buf: [512]u8 = undefined;
    const len = s.slice(&buf);
    const data = buf[0..len];

    _ = dns.transactionId(data) catch {};
    _ = dns.flags(data) catch {};
    _ = dns.opcode(data) catch {};
    _ = dns.rcode(data) catch {};
    _ = dns.questionCount(data) catch {};
    _ = dns.answerCount(data) catch {};
    _ = dns.authorityCount(data) catch {};
    _ = dns.additionalCount(data) catch {};
    _ = dns.payload(data) catch {};
    _ = dns.parseNamePart(data) catch {};
    _ = dns.parseQuestion(data) catch {};
    _ = dns.parseRecord(data) catch {};

    const start = if (data.len == 0) 0 else s.value(usize) % (data.len + 1);
    _ = dns.parseName(data, start) catch {};
}

pub fn fuzzTcpHeaderParsing(_: void, s: *std.testing.Smith) !void {
    var buf: [128]u8 = undefined;
    const len = s.slice(&buf);
    const data = buf[0..len];

    const repr = tcp_wire.parse(data) catch return;
    const header_len = tcp_wire.headerLen(repr);
    try testing.expect(header_len <= tcp_wire.MAX_HEADER_LEN);

    var out: [tcp_wire.MAX_HEADER_LEN]u8 = undefined;
    const emitted = tcp_wire.emit(repr, &out) catch return;
    try testing.expect(emitted <= out.len);
    _ = try tcp_wire.parse(out[0..emitted]);
}

pub fn fuzzIpHeaderParsing(_: void, s: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = s.slice(&buf);
    const data = buf[0..len];

    if (ipv4.parse(data)) |repr| {
        _ = ipv4.payloadSlice(data) catch {};
        _ = ipv4.checkLen(data) catch {};
        _ = ipv4.verifyChecksum(data);
        var out: [tcp_wire.MAX_HEADER_LEN]u8 = undefined;
        const header_len: usize = @as(usize, repr.ihl) * 4;
        if (header_len <= out.len) {
            const emitted = try ipv4.emit(repr, &out);
            try testing.expect(emitted == header_len);
        }
    } else |_| {}

    if (ipv6.parse(data)) |repr| {
        const payload = try ipv6.payloadSlice(data);
        try testing.expect(payload.len <= repr.payload_len);
        var out: [ipv6.HEADER_LEN]u8 = undefined;
        const emitted = try ipv6.emit(repr, &out);
        try testing.expectEqual(ipv6.HEADER_LEN, emitted);
    } else |_| {
        _ = ipv6.payloadSlice(data) catch {};
    }
}

pub fn fuzzIpv6ExtensionParsing(_: void, s: *std.testing.Smith) !void {
    var buf: [2048]u8 = undefined;
    const len = s.slice(&buf);
    const data = buf[0..len];

    if (ipv6ext_header.parse(data)) |repr| {
        const total = ipv6ext_header.headerLen(repr.length);
        try testing.expect(total <= data.len);
        try testing.expect(repr.data.len == total - 2);
        var out: [2048]u8 = undefined;
        const emitted = try ipv6ext_header.emit(repr, &out);
        try testing.expectEqual(total, emitted);
    } else |_| {}
    _ = ipv6ext_header.payloadSlice(data) catch {};

    if (ipv6fragment.parse(data)) |repr| {
        var out: [ipv6fragment.HEADER_LEN]u8 = undefined;
        const emitted = try ipv6fragment.emit(repr, &out);
        try testing.expectEqual(ipv6fragment.HEADER_LEN, emitted);
    } else |_| {}
    if (ipv6option.parse(data)) |repr| {
        var out: [258]u8 = undefined;
        _ = ipv6option.emit(repr, &out) catch {};
    } else |_| {}
    if (ipv6routing.parse(data)) |repr| {
        var out: [64]u8 = undefined;
        _ = ipv6routing.emit(repr, &out) catch {};
    } else |_| {}
    if (ipv6hbh.parse(data)) |repr| {
        var out: [64]u8 = undefined;
        _ = ipv6hbh.emit(repr, &out) catch {};
    } else |_| {}
}

pub fn fuzzStackIngress(_: void, s: *std.testing.Smith) !void {
    const EthernetDevice = stack_mod.LoopbackDevice(4);
    const EthernetStack = stack_mod.Stack(EthernetDevice, void);
    var eth_stack = EthernetStack.init(LOCAL_HW, {});
    initIfaceAddresses(EthernetStack, &eth_stack);
    var eth_device = EthernetDevice.init();
    var eth_frame: [stack_mod.MAX_FRAME_LEN]u8 = undefined;
    const eth_len = s.slice(&eth_frame);
    eth_device.enqueueRx(eth_frame[0..eth_len]);
    _ = eth_stack.poll(fuzzInstant(s), &eth_device);
    try drainTx(EthernetDevice, &eth_device, stack_mod.MAX_FRAME_LEN);

    const IpDevice = RawIpLoopbackDevice(4);
    const IpStack = stack_mod.Stack(IpDevice, void);
    var ip_stack = IpStack.init(LOCAL_HW, {});
    initIfaceAddresses(IpStack, &ip_stack);
    var ip_device = IpDevice.init();
    var ip_frame: [stack_mod.MAX_FRAME_LEN]u8 = undefined;
    const ip_len = s.slice(&ip_frame);
    ip_device.enqueueRx(ip_frame[0..ip_len]);
    _ = ip_stack.poll(fuzzInstant(s), &ip_device);
    try drainTx(IpDevice, &ip_device, stack_mod.MAX_FRAME_LEN);

    const LowpanDevice = Ieee802154LoopbackDevice(4);
    const LowpanStack = stack_mod.Stack(LowpanDevice, void);
    var lowpan_stack = LowpanStack.init(LOCAL_HW, {});
    initIfaceAddresses(LowpanStack, &lowpan_stack);
    var lowpan_device = LowpanDevice.init();
    var lowpan_frame: [ieee802154.MAX_FRAME_LEN]u8 = undefined;
    const lowpan_len = s.slice(&lowpan_frame);
    lowpan_device.enqueueRx(lowpan_frame[0..lowpan_len]);
    _ = lowpan_stack.poll(fuzzInstant(s), &lowpan_device);
    try drainTx(LowpanDevice, &lowpan_device, ieee802154.MAX_FRAME_LEN);
}

// -- Coverage-model helpers (shared by the assembler and reassembler oracles) --
//
// The assembler and reassembler track which byte ranges have been received.
// A boolean-per-byte shadow lets the fuzzer assert not just "did not crash"
// but the exact reported coverage and, for the reassembler, the exact bytes.

fn leadingTrue(seen: []const bool) usize {
    var k: usize = 0;
    while (k < seen.len and seen[k]) : (k += 1) {}
    return k;
}

fn allFalse(seen: []const bool) bool {
    for (seen) |b| {
        if (b) return false;
    }
    return true;
}

/// Shift the coverage window left by `k` bytes, zero-filling the tail. Mirrors
/// the coordinate shift the assembler applies when it removes its front run.
fn shiftLeftBool(seen: []bool, k: usize) void {
    if (k == 0) return;
    var i: usize = 0;
    while (i + k < seen.len) : (i += 1) seen[i] = seen[i + k];
    while (i < seen.len) : (i += 1) seen[i] = false;
}

fn fuzzFragKeyV4(s: *std.testing.Smith) fragmentation.FragKey {
    return .{
        .id = s.value(u16),
        .src_addr = fuzzV4(s),
        .dst_addr = fuzzV4(s),
        .protocol = @enumFromInt(s.value(u8)),
    };
}

fn fuzzFragKeyV6(s: *std.testing.Smith) fragmentation.FragKeyV6 {
    return .{
        .id = s.value(u32),
        .src_addr = fuzzV6(s),
        .dst_addr = fuzzV6(s),
    };
}

fn fuzzFragKey6lowpan(s: *std.testing.Smith) fragmentation.FragKey6LoWPAN {
    return fragmentation.FragKey6LoWPAN.fromAddrs(
        fuzzIeeeAddr(s),
        fuzzIeeeAddr(s),
        s.value(u16),
        s.value(u16),
    );
}

/// Drive a Reassembler against a byte-accurate shadow model. Every successful
/// add is recorded into a coverage bitmap and a shadow buffer; every assemble
/// is checked for exact length AND exact byte content, so a reassembler that
/// returned wrong or uninitialized bytes would fail here rather than slip past
/// a length-only bound.
fn fuzzReassemblerModeled(
    comptime Key: type,
    s: *std.testing.Smith,
    keyGen: *const fn (*std.testing.Smith) Key,
) !void {
    const BUF = 128;
    const Reasm = fragmentation.Reassembler(Key, .{ .buffer_size = BUF, .max_segments = 4 });
    var r = Reasm{};

    var active = false;
    var cur_key: Key = undefined;
    var expires: time.Instant = time.Instant.ZERO;
    var total: ?usize = null;
    var seen = [_]bool{false} ** BUF;
    var shadow = [_]u8{0} ** BUF;
    var payload: [32]u8 = undefined;

    var budget: usize = 64;
    while (budget > 0) : (budget -= 1) {
        switch (s.value(u8) % 5) {
            0 => {
                const key = keyGen(s);
                const e = fuzzInstant(s);
                // accept() only resets when the key differs from the current one.
                if (!(active and cur_key.eql(key))) {
                    active = true;
                    cur_key = key;
                    expires = e;
                    total = null;
                    seen = [_]bool{false} ** BUF;
                }
                r.accept(key, e);
            },
            1 => {
                const len = s.slice(&payload);
                // Deliberately reach past BUF sometimes to exercise the reject path.
                const off = s.value(usize) % (BUF + 16);
                if (r.add(payload[0..len], off)) {
                    // Success implies active and off + len <= BUF.
                    for (0..len) |i| {
                        seen[off + i] = true;
                        shadow[off + i] = payload[i];
                    }
                }
            },
            2 => {
                const size = s.value(usize) % (BUF + 1);
                total = size;
                r.setTotalSize(size);
            },
            3 => {
                const now = fuzzInstant(s);
                if (active and expires.lessThan(now)) {
                    active = false;
                    total = null;
                    seen = [_]bool{false} ** BUF;
                }
                r.removeExpired(now);
            },
            else => {
                const expect_len: ?usize = if (total) |t|
                    (if (leadingTrue(&seen) == t) t else null)
                else
                    null;
                if (r.assemble()) |packet| {
                    const t = expect_len orelse return error.TestUnexpectedAssembly;
                    try testing.expectEqual(t, packet.len);
                    for (0..t) |i| {
                        try testing.expect(seen[i]);
                        try testing.expectEqual(shadow[i], packet[i]);
                    }
                    // assemble() resets the reassembler on success.
                    active = false;
                    total = null;
                    seen = [_]bool{false} ** BUF;
                } else {
                    try testing.expect(expect_len == null);
                }
            },
        }
    }
}

pub fn fuzzReassembly(_: void, s: *std.testing.Smith) !void {
    try fuzzReassemblerModeled(fragmentation.FragKey, s, fuzzFragKeyV4);
    try fuzzReassemblerModeled(fragmentation.FragKeyV6, s, fuzzFragKeyV6);
    try fuzzReassemblerModeled(fragmentation.FragKey6LoWPAN, s, fuzzFragKey6lowpan);
}

pub fn fuzzProtocolParsers(_: void, s: *std.testing.Smith) !void {
    var buf: [1024]u8 = undefined;
    const len = s.slice(&buf);
    const data = buf[0..len];

    _ = arp.parse(data) catch {};
    _ = dhcp.parse(data) catch {};
    _ = udp_wire.parse(data) catch {};
    _ = udp_wire.payloadSlice(data) catch {};
    _ = icmp.parse(data) catch {};
    _ = igmp.parse(data) catch {};
    _ = ipsec_esp.parse(data) catch {};
    _ = ipsec_ah.parse(data) catch {};

    _ = ndiscoption.optionLen(data) catch {};
    if (ndiscoption.parse(data)) |repr| {
        var out: [64]u8 = undefined;
        _ = ndiscoption.emit(repr, &out) catch {};
    } else |_| {}

    const ndisc_type = switch (s.value(u8) % 5) {
        0 => ndisc.ROUTER_SOLICIT,
        1 => ndisc.ROUTER_ADVERT,
        2 => ndisc.NEIGHBOR_SOLICIT,
        3 => ndisc.NEIGHBOR_ADVERT,
        else => ndisc.REDIRECT,
    };
    if (ndisc.parse(ndisc_type, data)) |repr| {
        var out: [128]u8 = undefined;
        _ = ndisc.emit(repr, &out) catch {};
    } else |_| {}

    const mld_type: u8 = if (s.value(u8) & 1 == 0) 0x82 else 0x8f;
    if (mld.parse(mld_type, data)) |repr| {
        var out: [32]u8 = undefined;
        _ = mld.emit(repr, &out) catch {};
    } else |_| {}
    if (mld.parseAddressRecord(data)) |record| {
        const record_len = mld.addressRecordLen(record);
        try testing.expect(record_len >= 20);
        if (record.num_srcs == 0 and record.aux_data_len == 0) {
            var out: [20]u8 = undefined;
            const emitted = try mld.emitAddressRecord(record, &out);
            try testing.expectEqual(record_len, emitted);
        }
    } else |_| {}

    _ = icmpv6.parse(data, fuzzV6(s), fuzzV6(s)) catch {};

    if (ieee802154.parse(data)) |repr| {
        var out: [ieee802154.MAX_FRAME_LEN]u8 = undefined;
        _ = ieee802154.emit(repr, &out) catch {};
    } else |_| {}
    _ = ieee802154.payloadSlice(data) catch {};

    const contexts = [_]sixlowpan.AddressContext{
        .{ 0xfd, 0, 0, 0, 0, 0, 0, 0 },
    };
    _ = sixlowpan.dispatchType(if (data.len == 0) 0 else data[0]);
    _ = sixlowpan.parseIphc(data, fuzzIeeeAddr(s), fuzzIeeeAddr(s), &contexts) catch {};
    if (sixlowpan.parseExtHeaderNhc(data)) |parsed| {
        var out: [16]u8 = undefined;
        _ = sixlowpan.emitExtHeaderNhc(parsed.repr, &out) catch {};
    } else |_| {}
    if (sixlowpan.parseUdpNhc(data)) |parsed| {
        var out: [8]u8 = undefined;
        _ = sixlowpan.emitUdpNhc(parsed.repr, &out) catch {};
    } else |_| {}
    if (sixlowpan_frag.parse(data)) |repr| {
        var out: [sixlowpan_frag.NEXT_FRAGMENT_HEADER_SIZE]u8 = undefined;
        _ = sixlowpan_frag.emit(repr, &out) catch {};
    } else |_| {}
    _ = sixlowpan_frag.payloadSlice(data) catch {};

    _ = rpl_wire.parse(s.value(u8), data) catch {};
    var iter = rpl_wire.OptionIterator.init(data);
    var option_budget: usize = 64;
    while (option_budget > 0) : (option_budget -= 1) {
        _ = iter.next() orelse break;
    }
    _ = rpl_wire.DodagConfigurationOption.parseOption(data) catch {};
    _ = rpl_wire.RplTargetOption.parseOption(data) catch {};
    _ = rpl_wire.TransitInformationOption.parseOption(data) catch {};
    _ = rpl_wire.HopByHopRepr.parseOption(data) catch {};
}

fn fuzzRingBuffer(s: *std.testing.Smith) !void {
    const Ring = ring_buffer_mod.RingBuffer(u8);
    var backing: [16]u8 = .{0} ** 16;
    var ring = Ring.init(&backing);
    var model: [16]u8 = undefined;
    var model_len: usize = 0;

    var budget: usize = 96;
    while (budget > 0) : (budget -= 1) {
        switch (s.value(u8) % 4) {
            0 => {
                var data: [8]u8 = undefined;
                const len = s.slice(&data);
                const written = ring.enqueueSlice(data[0..len]);
                try testing.expect(written <= data.len);
                try testing.expect(model_len + written <= model.len);
                @memcpy(model[model_len..][0..written], data[0..written]);
                model_len += written;
            },
            1 => {
                var out: [8]u8 = undefined;
                const want = fuzzLen(s, out.len);
                const read = ring.dequeueSlice(out[0..want]);
                try testing.expect(read <= model_len);
                try testing.expectEqualSlices(u8, model[0..read], out[0..read]);
                std.mem.copyForwards(u8, model[0 .. model_len - read], model[read..model_len]);
                model_len -= read;
            },
            2 => {
                var data: [8]u8 = undefined;
                const len = s.slice(&data);
                const written = ring.writeUnallocated(0, data[0..len]);
                try testing.expect(written <= ring.window());
                ring.enqueueUnallocated(written);
                try testing.expect(model_len + written <= model.len);
                @memcpy(model[model_len..][0..written], data[0..written]);
                model_len += written;
            },
            else => {
                const count = if (ring.len() == 0) 0 else s.value(usize) % (ring.len() + 1);
                ring.dequeueAllocated(count);
                std.mem.copyForwards(u8, model[0 .. model_len - count], model[count..model_len]);
                model_len -= count;
            },
        }
        try testing.expectEqual(model_len, ring.len());
        try testing.expect(ring.len() <= ring.capacity());
    }
}

fn fuzzPacketBuffer(s: *std.testing.Smith) !void {
    const PacketBuffer = packet_buffer_mod.PacketBuffer(u8);
    const Meta = packet_buffer_mod.PacketMeta(u8);
    var meta: [4]Meta = .{Meta{}} ** 4;
    var payload: [16]u8 = .{0} ** 16;
    var packets = PacketBuffer.init(&meta, &payload);

    var budget: usize = 64;
    while (budget > 0) : (budget -= 1) {
        switch (s.value(u8) % 4) {
            0 => {
                const size = s.value(usize) % 24;
                if (packets.enqueue(size, s.value(u8))) |slot| {
                    @memset(slot, s.value(u8));
                    try testing.expect(slot.len == size);
                } else |_| {}
            },
            1 => if (packets.dequeue()) |pkt| {
                try testing.expect(pkt.payload.len <= payload.len);
            } else |_| {},
            2 => if (packets.peek()) |pkt| {
                try testing.expect(pkt.payload.len <= payload.len);
            } else |_| {},
            else => packets.reset(),
        }
        try testing.expect(packets.packetCapacity() == meta.len);
        try testing.expect(packets.payloadCapacity() == payload.len);
    }
}

fn fuzzAssembler(s: *std.testing.Smith) !void {
    const Assembler = assembler_mod.Assembler(4);
    var asmb = Assembler.init();

    // Shadow coverage in the assembler's current coordinate space (index 0 is
    // the front). removeFront shifts the whole window left, mirrored below.
    const N = 160;
    var seen = [_]bool{false} ** N;

    var budget: usize = 96;
    while (budget > 0) : (budget -= 1) {
        switch (s.value(u8) % 5) {
            0 => {
                const off = s.value(usize) % N;
                const size = s.value(usize) % (N - off + 1);
                var tmp = seen;
                for (0..size) |i| tmp[off + i] = true;
                // add is atomic: on TooManyHoles the state is unchanged, so we
                // only adopt the new coverage when it succeeds.
                if (asmb.add(off, size)) |_| {
                    seen = tmp;
                } else |_| {}
            },
            1 => {
                const off = s.value(usize) % N;
                const size = s.value(usize) % (N - off + 1);
                var tmp = seen;
                for (0..size) |i| tmp[off + i] = true;
                const k = leadingTrue(&tmp);
                if (asmb.addThenRemoveFront(off, size)) |removed| {
                    try testing.expectEqual(k, removed);
                    shiftLeftBool(&tmp, k);
                    seen = tmp;
                } else |_| {}
            },
            2 => {
                const k = leadingTrue(&seen);
                try testing.expectEqual(k, asmb.removeFront());
                shiftLeftBool(&seen, k);
            },
            3 => {
                asmb.clear();
                seen = [_]bool{false} ** N;
            },
            else => {},
        }

        // Front run, emptiness, and the exact set of data ranges must match the
        // model. iterData coalesces adjacent data, so maximal runs of the shadow
        // map correspond one-to-one with the reported ranges.
        try testing.expectEqual(leadingTrue(&seen), asmb.peekFront());
        try testing.expectEqual(allFalse(&seen), asmb.isEmpty());

        var iter = asmb.iterData(0);
        var pos: usize = 0;
        while (pos < N) {
            while (pos < N and !seen[pos]) pos += 1;
            if (pos == N) break;
            const left = pos;
            while (pos < N and seen[pos]) pos += 1;
            const range = iter.next() orelse return error.TestMissingRange;
            try testing.expectEqual(left, range[0]);
            try testing.expectEqual(pos, range[1]);
        }
        try testing.expect(iter.next() == null);
    }
}

pub fn fuzzStorageStreams(_: void, s: *std.testing.Smith) !void {
    try fuzzRingBuffer(s);
    try fuzzPacketBuffer(s);
    try fuzzAssembler(s);
}

fn fuzzUdpSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const Sock = udp_socket.Socket(ipv4);
    var rx_meta: [4]Sock.PacketMeta = .{Sock.PacketMeta{}} ** 4;
    var rx_payload: [128]u8 = undefined;
    var tx_meta: [4]Sock.PacketMeta = .{Sock.PacketMeta{}} ** 4;
    var tx_payload: [128]u8 = undefined;
    var sock = Sock.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);

    const local_port = nonzeroPort(s.value(u16));
    sock.bind(.{ .addr = null, .port = local_port }) catch {};
    const repr = udp_socket.UdpRepr{
        .src_port = nonzeroPort(s.value(u16)),
        .dst_port = local_port,
    };
    if (sock.accepts(REMOTE_V4, LOCAL_V4, repr)) {
        sock.process(REMOTE_V4, LOCAL_V4, repr, payload);
    }
    var out: [128]u8 = undefined;
    _ = sock.recvSlice(&out) catch {};
    _ = sock.sendSlice(payload, .{
        .endpoint = .{ .addr = REMOTE_V4, .port = nonzeroPort(s.value(u16)) },
        .local_addr = null,
    }) catch {};
    _ = sock.dispatch();
    _ = sock.pollAt();
}

fn fuzzIcmpSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const Sock = icmp_socket.Socket(ipv4);
    var rx_meta: [4]Sock.PacketMeta = .{Sock.PacketMeta{}} ** 4;
    var rx_payload: [128]u8 = undefined;
    var tx_meta: [4]Sock.PacketMeta = .{Sock.PacketMeta{}} ** 4;
    var tx_payload: [128]u8 = undefined;
    var sock = Sock.init(&rx_meta, &rx_payload, &tx_meta, &tx_payload);

    const ident = s.value(u16);
    sock.bind(.{ .ident = ident }) catch {};
    const repr = icmp.Repr{ .echo = .{
        .icmp_type = .echo_request,
        .code = 0,
        .checksum = 0,
        .identifier = ident,
        .sequence = s.value(u16),
    } };
    if (sock.accepts(REMOTE_V4, LOCAL_V4, repr, payload)) {
        sock.process(REMOTE_V4, LOCAL_V4, repr, payload);
    }
    var out: [128]u8 = undefined;
    _ = sock.recvSlice(&out) catch {};
    _ = sock.sendSlice(payload, REMOTE_V4) catch {};
    _ = sock.dispatch();
    _ = sock.pollAt();
}

fn fuzzRawSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const Sock = raw_socket.Socket(ipv4, .{ .payload_size = 64 });
    var rx_store: [4]Sock.Packet = undefined;
    var tx_store: [4]Sock.Packet = undefined;
    var sock = Sock.init(&rx_store, &tx_store);

    const proto: ipv4.Protocol = @enumFromInt(s.value(u8));
    sock.bind(proto) catch {};
    if (sock.accepts(proto)) {
        sock.process(REMOTE_V4, proto, payload);
    }
    var out: [64]u8 = undefined;
    _ = sock.recvSlice(&out) catch {};
    _ = sock.sendSlice(payload[0..@min(payload.len, out.len)], REMOTE_V4) catch {};
    _ = sock.dispatch();
    _ = sock.pollAt();
}

fn fuzzDnsSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const Sock = dns_socket.Socket(ipv4);
    var slots: [2]Sock.QuerySlot = .{Sock.QuerySlot{}} ** 2;
    const servers = [_]ipv4.Address{.{ 8, 8, 8, 8 }};
    var sock = Sock.init(&slots, &servers);

    _ = sock.startQuery("example.com", .a) catch {};
    var out: [512]u8 = undefined;
    if (sock.dispatch(fuzzInstant(s), &out)) |query| {
        sock.process(query.dst_ip, query.src_port, payload);
    }
    _ = sock.dispatch(fuzzInstant(s), &out);
    _ = sock.pollAt();
}

fn fuzzDhcpSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const hw = ethernet.Address{ 0x02, 0, 0, 0, 0, 0x10 };
    var sock = dhcp_socket.Socket.init(hw);
    if (dhcp.parse(payload)) |repr| {
        sock.process(fuzzInstant(s), fuzzV4(s), repr);
    } else |_| {}
    _ = sock.dispatch(fuzzInstant(s));
    _ = sock.poll();
    _ = sock.pollAt();
}

fn fuzzTcpSocket(s: *std.testing.Smith, payload: []const u8) !void {
    const Sock = tcp_socket.Socket(ipv4, 4);
    var rx_storage: [128]u8 = undefined;
    var tx_storage: [128]u8 = undefined;
    var sock = Sock.init(&rx_storage, &tx_storage);

    const local_port: u16 = 80;
    sock.listen(.{ .addr = null, .port = local_port }) catch {};
    var repr = tcp_socket.TcpRepr{
        .src_port = nonzeroPort(s.value(u16)),
        .dst_port = local_port,
        .control = switch (s.value(u8) % 5) {
            0 => .none,
            1 => .psh,
            2 => .syn,
            3 => .fin,
            else => .rst,
        },
        .seq_number = tcp_wire.SeqNumber.fromU32(s.value(u32)),
        .ack_number = if (s.value(u8) & 1 == 0) null else tcp_wire.SeqNumber.fromU32(s.value(u32)),
        .window_len = s.value(u16),
        .payload = payload,
    };
    if (repr.control == .rst) repr.ack_number = null;

    if (sock.accepts(REMOTE_V4, LOCAL_V4, repr)) {
        _ = sock.process(fuzzInstant(s), REMOTE_V4, LOCAL_V4, repr);
    }
    _ = sock.dispatch(fuzzInstant(s));
    _ = sock.pollAt();
}

pub fn fuzzSocketStateMachines(_: void, s: *std.testing.Smith) !void {
    var buf: [64]u8 = undefined;
    const len = s.slice(&buf);
    const payload = buf[0..len];

    try fuzzUdpSocket(s, payload);
    try fuzzIcmpSocket(s, payload);
    try fuzzRawSocket(s, payload);
    try fuzzDnsSocket(s, payload);
    try fuzzDhcpSocket(s, payload);
    try fuzzTcpSocket(s, payload);
}

pub fn fuzzRplState(_: void, s: *std.testing.Smith) !void {
    const Parents = rpl_state.ParentSet(4);
    const Relations = rpl_state.Relations(4);
    var parents = Parents{};
    var relations = Relations{};

    var timer = rpl_state.TrickleTimer.init(
        s.value(u32) % 16,
        s.value(u32) % 8,
        s.value(u8) % 16,
        fuzzInstant(s),
        s.value(u32),
    );

    var budget: usize = 96;
    while (budget > 0) : (budget -= 1) {
        const addr = fuzzV6(s);
        const parent = rpl_state.Parent{
            .rank = .{
                .value = s.value(u16),
                .min_hop_rank_increase = rpl_state.DEFAULT_MIN_HOP_RANK_INCREASE,
            },
            .preference = s.value(u8),
            .version_number = .{ .value = s.value(u8) },
            .dodag_id = fuzzV6(s),
        };

        switch (s.value(u8) % 8) {
            0 => _ = parents.add(addr, parent),
            1 => _ = parents.remove(addr),
            2 => _ = parents.find(addr),
            3 => _ = relations.addRelation(addr, fuzzV6(s), fuzzInstant(s)),
            4 => _ = relations.removeRelation(addr),
            5 => _ = relations.findNextHop(addr),
            6 => relations.purge(fuzzInstant(s)),
            else => {
                const now = fuzzInstant(s);
                _ = timer.poll(now, s.value(u32));
                if (s.value(u8) & 1 == 0) timer.hearConsistent();
                if (s.value(u8) & 1 == 0) timer.hearInconsistency(now, s.value(u32));
                _ = timer.pollAt();
            },
        }

        try testing.expect(parents.count() <= 4);
        try testing.expect(relations.count() <= 4);
    }
}

var fuzz_rng_value: u32 = 0;

fn fuzzRng() u32 {
    return fuzz_rng_value;
}

fn discardWrite(_: []const u8) void {}

pub fn fuzzPhyMiddleware(_: void, s: *std.testing.Smith) !void {
    const Base = stack_mod.LoopbackDevice(4);
    var frame: [stack_mod.MAX_FRAME_LEN]u8 = undefined;
    const len = s.slice(&frame);

    var base = Base.init();
    base.enqueueRx(frame[0..len]);

    const Faulty = phy.FaultInjector(Base);
    fuzz_rng_value = s.value(u32);
    var faulty = Faulty.init(base, .{
        .rx_drop_pct = @truncate(s.value(u8) % 101),
        .tx_drop_pct = @truncate(s.value(u8) % 101),
        .rx_corrupt_pct = @truncate(s.value(u8) % 101),
        .tx_corrupt_pct = @truncate(s.value(u8) % 101),
    }, fuzzRng);
    if (faulty.receive()) |rx| try testing.expect(rx.len == len);
    faulty.transmit(frame[0..len]);

    const Pcap = phy.PcapWriter(Base);
    var pcap = Pcap.init(Base.init(), discardWrite, .both);
    pcap.transmit(frame[0..len]);
}

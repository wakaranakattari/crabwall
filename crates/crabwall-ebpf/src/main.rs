//! eBPF connect observer: reports every `connect()` syscall with pid,
//! family, port and address via a perf-event array.
//!
//! Observe-only: always returns 0, never blocks traffic. Blocking is the
//! NFQUEUE path's job (`nflink`); this feed exists so the correlator
//! attributes queued packets instantly instead of scanning `/proc`.
//!
//! Layouts: `sockaddr_in/sin6` per POSIX (ports/addresses network order),
//! `trace_event_raw_sys_enter` (`ent` 8B + `id` 8B + `args[6]`, so the
//! user sockaddr pointer is the second arg at offset 24).
//!
//! Hook choice, argued explicitly. A `cgroup_sock_addr` program would
//! seem natural, but it has two defects for this system: the byte order
//! of its port/address fields is not POSIX-pinned (guessing wrong means
//! misattribution), and attaching requires a cgroupfs layout that varies
//! across distributions and containers. The tracepoint reads the
//! userspace `sockaddr` directly, where network order is guaranteed, and
//! attaches through tracefs anywhere with `CAP_BPF`.
//!
//! Verifier discipline, because the kernel is the strictest reviewer:
//! every read is bounded and fallible (`Result` propagation, no panics),
//! arrays are built element-wise (the backend cannot lower `memset` or
//! `memcpy` calls), families other than v4/v6 return early, and the only
//! loop in the object is the unreachable panic handler.
//!
//! Built with: `cargo xtask build-ebpf` (nightly + bpf-linker, or stable
//! with RUSTC_BOOTSTRAP; see xtask for the toolchain fallback).

#![no_std]
#![no_main]

use aya_ebpf::{
    helpers::{bpf_get_current_pid_tgid, bpf_probe_read_user},
    macros::{map, tracepoint},
    maps::PerfEventArray,
    programs::TracePointContext,
};

/// Wire layout shared with the userspace decoder (`ebpf::decode_event`).
/// Deliberately free of endianness ambiguity: pid is little-endian u32
/// (host order from the helper, stored directly), family is a single
/// byte, dport is converted in-BPF from network to host order with
/// `u16::from_be` (pure arithmetic, verifier-safe), and the address is
/// copied octet-by-octet so network order survives verbatim. IPv4 uses
/// the first 4 octets. Total 24 bytes, 4-aligned, no padding surprises.
#[repr(C)]
pub struct ConnectEvent {
    pub pid: u32,
    pub family: u8,
    pub _pad: u8,
    pub dport: u16,
    pub addr: [u8; 16],
}

#[map]
static EVENTS: PerfEventArray<ConnectEvent> = PerfEventArray::new(0);

/// Kernel license declaration. Our helpers need no GPL-only calls; the
/// string uses the kernel's accepted vocabulary for permissive code.
#[link_section = "license"]
#[no_mangle]
static LICENSE: [u8; 13] = *b"Dual MIT/GPL\0";

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

/// AF_INET / AF_INET6, stable on every Linux arch.
const AF_INET_U16: u16 = 2;
const AF_INET6_U16: u16 = 10;

#[tracepoint(category = "syscalls", name = "sys_enter_connect")]
pub fn crabwall_connect(ctx: TracePointContext) -> u32 {
    let _ = try_emit(&ctx);
    0
}

fn try_emit(ctx: &TracePointContext) -> Result<(), i64> {
    let uservaddr = unsafe { ctx.read_at::<u64>(24)? } as *const u8;
    if uservaddr.is_null() {
        return Err(-1);
    }
    let family = unsafe { bpf_probe_read_user(uservaddr as *const u16).map_err(|e| e as i64)? };
    // sin_port sits at offset 2 in both sockaddr_in and sockaddr_in6.
    let port_ptr = uservaddr.wrapping_add(2) as *const u16;
    let port_be = unsafe { bpf_probe_read_user(port_ptr).map_err(|e| e as i64)? };
    // NOTE: no zero-initialized buffers here - the BPF backend cannot
    // lower memset/memcpy calls, so every array is built element-wise.
    let addr: [u8; 16] = match family {
        f if f == AF_INET_U16 => {
            // sin_addr at offset 4, network octet order.
            let base = uservaddr.wrapping_add(4);
            let b0 = unsafe { bpf_probe_read_user(base as *const u8).map_err(|e| e as i64)? };
            let b1 = unsafe {
                bpf_probe_read_user(base.wrapping_add(1) as *const u8).map_err(|e| e as i64)?
            };
            let b2 = unsafe {
                bpf_probe_read_user(base.wrapping_add(2) as *const u8).map_err(|e| e as i64)?
            };
            let b3 = unsafe {
                bpf_probe_read_user(base.wrapping_add(3) as *const u8).map_err(|e| e as i64)?
            };
            [b0, b1, b2, b3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]
        }
        f if f == AF_INET6_U16 => {
            let ip6_ptr = uservaddr.wrapping_add(8) as *const [u8; 16];
            unsafe { bpf_probe_read_user(ip6_ptr).map_err(|e| e as i64)? }
        }
        _ => return Err(-1), // AF_UNIX and friends: not our business.
    };
    let event = ConnectEvent {
        pid: (bpf_get_current_pid_tgid() & 0xFFFF_FFFF) as u32,
        family: family as u8,
        _pad: 0,
        dport: u16::from_be(port_be),
        addr,
    };
    EVENTS.output(ctx, &event, 0);
    Ok(())
}

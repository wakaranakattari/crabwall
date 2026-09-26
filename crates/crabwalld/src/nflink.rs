//! Minimal `NETLINK_NETFILTER` / NFQUEUE client. Hand-rolled on libc:
//! no libnetfilter_queue, no new system build dependencies, and - decisively -
//! no GPL-licensed dependency, so the crate license stays plain MIT.
//!
//! Protocol summary (layouts follow `linux/netfilter/nfnetlink_queue.h`
//! and `linux/netlink.h`, verified against the installed kernel headers).
//! The client opens an `AF_NETLINK` socket bound to its own PID, then
//! exchanges typed messages with the kernel: `CONFIG` to bind the inet
//! and inet6 families, bind queue 0, request `COPY_PACKET` mode with full
//! range, and set the `UID_GID` flag so queued packets arrive annotated
//! with the owning socket's UID/GID for free. Every CONFIG round-trips
//! against a kernel ACK matched by sequence number (5s budget); a NACK
//! aborts setup with its errno, which is exactly how unprivileged runs
//! discover they must fall back to nft-sets. Packets arrive as `PACKET`
//! messages (inline 7-byte header with packet id, then TLV attributes
//! for payload, UID, mark); verdicts go back as `VERDICT` messages
//! carrying the packet id, fire-and-forget. All wire (de)serialization
//! is pure and unit-tested, including byte-exact encoding vectors and a
//! hand-built kernel-style packet; the syscalls are thin and fail-soft.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::Duration;

// --- protocol constants -------------------------------------------------
// linux/netfilter/nfnetlink.h
const NFNL_SUBSYS_QUEUE: u16 = 3;
const NFNETLINK_V0: u8 = 0;
// linux/netfilter/nfnetlink_queue.h :: nfqnl_msg_types
const MSG_PACKET: u8 = 0;
const MSG_VERDICT: u8 = 1;
const MSG_CONFIG: u8 = 2;
// nfqnl_msg_config_cmds
const CMD_BIND: u8 = 1;
const CMD_PF_BIND: u8 = 3;
// nfqnl_config_mode
const COPY_PACKET: u8 = 2;
// nfqnl_attr_config
const CFG_CMD: u16 = 1;
const CFG_PARAMS: u16 = 2;
const CFG_QUEUE_MAXLEN: u16 = 3;
const CFG_MASK: u16 = 4;
const CFG_FLAGS: u16 = 5;
// NFQA_CFG_F_* flags
const F_UID_GID: u32 = 1 << 3;
// nfqnl_attr_type (explicit discriminants; order matters)
const NFQA_MARK: u16 = 3;
const NFQA_PAYLOAD: u16 = 10;
const NFQA_UID: u16 = 16;
const NFQA_GID: u16 = 17;
// linux/netfilter.h verdicts
const NF_DROP: u32 = 0;
const NF_ACCEPT: u32 = 1;
// linux/netlink.h
const NLM_F_REQUEST: u16 = 0x01;
const NLM_F_ACK: u16 = 0x04;
const NLMSG_ERROR: u16 = 2;
const NLMSG_HDRLEN: usize = 16;
/// Default kernel queue length; overflow drops (fail-closed, documented).
const QUEUE_MAXLEN: u32 = 1024;
/// Bytes copied per packet: full 64K, we need L3/L4 headers + TLS hello.
const COPY_RANGE: u32 = 0xFFFF;

/// Accept or drop a queued packet.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    Accept,
    Drop,
}

/// One packet delivered by the kernel.
/// The id is the only handle the kernel understands: verdicts echo it
/// back, and ids are unique per queue while pending, so no additional
/// correlation token is needed. UID/GID arrive only because the queue
/// was created with the UID_GID flag; without it they stay None and
/// attribution falls back to slower sources.
#[derive(Debug, Clone)]
pub struct QueuedPacket {
    /// Kernel packet id; echoed back in the verdict.
    pub id: u32,
    /// Netfilter hook the packet was queued at.
    pub hook: u8,
    /// L3 protocol (e.g. `0x0800`), network order value as seen on wire.
    pub hw_proto: u16,
    /// Socket owner uid, present when the queue was created with
    /// the `UID_GID` flag (we always set it).
    pub uid: Option<u32>,
    /// Socket owner gid, same condition as `uid`.
    pub gid: Option<u32>,
    /// Netfilter mark at queue time, if any.
    pub mark: Option<u32>,
    /// Full packet starting at the L3 header.
    pub payload: Vec<u8>,
}

// --- pure wire codec (unit-tested) ---------------------------------------

fn nl_type(msg: u8) -> u16 {
    (NFNL_SUBSYS_QUEUE << 8) | u16::from(msg)
}

/// Append a netlink attribute (4-byte aligned) to `buf`.
fn push_attr(buf: &mut Vec<u8>, atype: u16, payload: &[u8]) {
    let len = (payload.len() + 4) as u16;
    buf.extend_from_slice(&len.to_ne_bytes());
    buf.extend_from_slice(&atype.to_ne_bytes());
    buf.extend_from_slice(payload);
    while !buf.len().is_multiple_of(4) {
        buf.push(0);
    }
}

/// Start a netlink message; returns the buffer with a length placeholder.
fn msg_start(msg: u8, seq: u32, pid: u32) -> Vec<u8> {
    let mut m = Vec::with_capacity(64);
    m.extend_from_slice(&[0u8; 4]); // nlmsg_len, patched by finish()
    m.extend_from_slice(&nl_type(msg).to_ne_bytes());
    m.extend_from_slice(&(NLM_F_REQUEST | NLM_F_ACK).to_ne_bytes());
    m.extend_from_slice(&seq.to_ne_bytes());
    m.extend_from_slice(&pid.to_ne_bytes());
    m
}

fn msg_finish(mut m: Vec<u8>) -> Vec<u8> {
    let len = m.len() as u32;
    m[0..4].copy_from_slice(&len.to_ne_bytes());
    m
}

/// `nfgenmsg`: family + version + big-endian resource id.
fn push_nfgen(buf: &mut Vec<u8>, family: u8, res_id: u16) {
    buf.push(family);
    buf.push(NFNETLINK_V0);
    buf.extend_from_slice(&res_id.to_be_bytes());
}

/// CONFIG message binding a protocol family (`PF_BIND`).
fn encode_pf_bind(seq: u32, pid: u32, family: u16) -> Vec<u8> {
    let mut m = msg_start(MSG_CONFIG, seq, pid);
    push_nfgen(&mut m, 0, 0);
    let mut cmd = vec![CMD_PF_BIND, 0];
    cmd.extend_from_slice(&family.to_be_bytes());
    push_attr(&mut m, CFG_CMD, &cmd);
    msg_finish(m)
}

/// CONFIG message binding our queue number.
fn encode_queue_bind(seq: u32, pid: u32, queue: u16) -> Vec<u8> {
    let mut m = msg_start(MSG_CONFIG, seq, pid);
    push_nfgen(&mut m, 0, queue);
    push_attr(&mut m, CFG_CMD, &[CMD_BIND, 0, 0, 0]);
    msg_finish(m)
}

/// CONFIG message selecting copy mode + range.
fn encode_set_mode(seq: u32, pid: u32, queue: u16) -> Vec<u8> {
    let mut m = msg_start(MSG_CONFIG, seq, pid);
    push_nfgen(&mut m, 0, queue);
    let mut params = Vec::with_capacity(5);
    params.extend_from_slice(&COPY_RANGE.to_be_bytes());
    params.push(COPY_PACKET);
    push_attr(&mut m, CFG_PARAMS, &params);
    msg_finish(m)
}

/// CONFIG message tuning queue length and flags (mask + value).
fn encode_queue_opts(seq: u32, pid: u32, queue: u16, mask: u32, flags: u32) -> Vec<u8> {
    let mut m = msg_start(MSG_CONFIG, seq, pid);
    push_nfgen(&mut m, 0, queue);
    push_attr(&mut m, CFG_QUEUE_MAXLEN, &QUEUE_MAXLEN.to_ne_bytes());
    push_attr(&mut m, CFG_MASK, &mask.to_ne_bytes());
    push_attr(&mut m, CFG_FLAGS, &flags.to_ne_bytes());
    msg_finish(m)
}

/// VERDICT message for one packet id.
fn encode_verdict(seq: u32, pid: u32, queue: u16, id: u32, verdict: Verdict) -> Vec<u8> {
    let v = match verdict {
        Verdict::Accept => NF_ACCEPT,
        Verdict::Drop => NF_DROP,
    };
    let mut m = msg_start(MSG_VERDICT, seq, pid);
    push_nfgen(&mut m, 0, queue);
    m.extend_from_slice(&v.to_be_bytes());
    m.extend_from_slice(&id.to_be_bytes());
    msg_finish(m)
}

/// One netlink message inside a received datagram.
struct NlMsg<'a> {
    mtype: u16,
    payload: &'a [u8],
}

/// Split a datagram into messages (NLMSG alignment = 4).
fn split_messages(buf: &[u8]) -> Vec<NlMsg<'_>> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + NLMSG_HDRLEN <= buf.len() {
        let len = u32::from_ne_bytes(buf[off..off + 4].try_into().unwrap_or([0; 4])) as usize;
        if len < NLMSG_HDRLEN || off + len > buf.len() {
            break;
        }
        out.push(NlMsg {
            mtype: u16::from_ne_bytes([buf[off + 4], buf[off + 5]]),
            payload: &buf[off + NLMSG_HDRLEN..off + len],
        });
        off += (len + 3) & !3;
        if len == 0 {
            break;
        }
    }
    out
}

/// Iterate TLV attributes; stops on truncation. Masks the NESTED flag.
fn each_attr(mut b: &[u8], mut f: impl FnMut(u16, &[u8])) {
    while b.len() >= 4 {
        let len = u16::from_ne_bytes([b[0], b[1]]) as usize;
        let atype = u16::from_ne_bytes([b[2], b[3]]) & 0x3FFF;
        if len < 4 || len > b.len() {
            break;
        }
        f(atype, &b[4..len]);
        b = &b[(len + 3) & !3..];
    }
}

/// Parse a PACKET message payload (`nfgenmsg` + 7-byte packet hdr + attrs).
fn parse_packet(payload: &[u8], queue: u16) -> Option<QueuedPacket> {
    let gen = payload.get(..4)?;
    if u16::from_be_bytes([gen[2], gen[3]]) != queue {
        return None;
    }
    let hdr = payload.get(4..11)?;
    let id = u32::from_be_bytes([hdr[0], hdr[1], hdr[2], hdr[3]]);
    let hw_proto = u16::from_be_bytes([hdr[4], hdr[5]]);
    let hook = hdr[6];
    let mut pkt = QueuedPacket {
        id,
        hook,
        hw_proto,
        uid: None,
        gid: None,
        mark: None,
        payload: Vec::new(),
    };
    each_attr(payload.get(11..)?, |t, v| match t {
        NFQA_PAYLOAD => pkt.payload = v.to_vec(),
        NFQA_UID if v.len() >= 4 => {
            pkt.uid = Some(u32::from_ne_bytes(v[..4].try_into().unwrap_or([0; 4])));
        }
        NFQA_GID if v.len() >= 4 => {
            pkt.gid = Some(u32::from_ne_bytes(v[..4].try_into().unwrap_or([0; 4])));
        }
        NFQA_MARK if v.len() >= 4 => {
            pkt.mark = Some(u32::from_ne_bytes(v[..4].try_into().unwrap_or([0; 4])));
        }
        _ => {}
    });
    Some(pkt)
}

/// Parse an ERROR message: `Ok(seq)` on ACK, `Err(errno)` otherwise.
/// Layout: error code (4B) + echoed request header; seq sits at +8
/// inside that header, i.e. payload bytes 12..16.
fn parse_ack(payload: &[u8]) -> Result<u32, i32> {
    let code = i32::from_ne_bytes(
        payload
            .get(..4)
            .unwrap_or(&[0; 4])
            .try_into()
            .unwrap_or([0; 4]),
    );
    if code == 0 {
        let seq = u32::from_ne_bytes(
            payload
                .get(12..16)
                .unwrap_or(&[0; 4])
                .try_into()
                .unwrap_or([0; 4]),
        );
        Ok(seq)
    } else {
        Err(code)
    }
}

// --- socket owner ----------------------------------------------------------

/// Bound NFQUEUE handle. `Send + Sync`: verdicts may be issued from any
/// thread while the queue thread owns receiving.
/// Thread safety rests on two facts: the socket fd is owned (no close
/// races) and sequence numbers come from an atomic counter, so concurrent
/// verdict sends serialize in the kernel without userspace locking.
pub struct Nflink {
    fd: OwnedFd,
    pid: u32,
    queue: u16,
    seq: AtomicU32,
}

impl Nflink {
    /// Open, PF-bind inet/inet6, bind the queue, set mode/opts.
    /// Fails without privileges - callers fall back to nft-sets.
    pub fn bind(queue: u16) -> anyhow::Result<Self> {
        // SAFETY: socket() with constant args; fd checked below.
        let raw =
            unsafe { libc::socket(libc::AF_NETLINK, libc::SOCK_RAW, libc::NETLINK_NETFILTER) };
        if raw < 0 {
            anyhow::bail!("netlink socket: {}", std::io::Error::last_os_error());
        }
        // SAFETY: freshly owned fd from a successful socket().
        let fd = unsafe { OwnedFd::from_raw_fd(raw) };
        // SAFETY: pid is ours; the kernel needs nonzero nl_pid.
        let pid = unsafe { libc::getpid() } as u32;
        // SAFETY: all-zero sockaddr_nl is valid (pad/groups are zero),
        // then family + pid are set explicitly. (Newer libc hides the
        // padding field, so a struct literal is not possible.)
        let mut addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
        addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
        addr.nl_pid = pid;
        // SAFETY: addr is a valid sockaddr_nl; bind copies it.
        let rc = unsafe {
            libc::bind(
                fd.as_raw_fd(),
                (&addr as *const libc::sockaddr_nl).cast(),
                std::mem::size_of::<libc::sockaddr_nl>() as u32,
            )
        };
        if rc != 0 {
            anyhow::bail!("netlink bind: {}", std::io::Error::last_os_error());
        }
        let link = Self {
            fd,
            pid,
            queue,
            seq: AtomicU32::new(1),
        };
        link.roundtrip(&encode_pf_bind(link.next_seq(), pid, libc::AF_INET as u16))?;
        // IPv6 may be compiled out; warn and continue.
        if let Err(e) = link.roundtrip(&encode_pf_bind(link.next_seq(), pid, libc::AF_INET6 as u16))
        {
            tracing::warn!("nfqueue: inet6 pf bind failed ({e:#}), v4 only");
        }
        link.roundtrip(&encode_queue_bind(link.next_seq(), pid, queue))?;
        link.roundtrip(&encode_set_mode(link.next_seq(), pid, queue))?;
        link.roundtrip(&encode_queue_opts(
            link.next_seq(),
            pid,
            queue,
            F_UID_GID,
            F_UID_GID,
        ))?;
        Ok(link)
    }

    fn next_seq(&self) -> u32 {
        self.seq.fetch_add(1, Ordering::Relaxed)
    }

    fn send(&self, msg: &[u8]) -> anyhow::Result<()> {
        // SAFETY: msg is a valid slice; SOCK_RAW netlink send is
        // thread-safe for concurrent verdicts.
        let n = unsafe { libc::send(self.fd.as_raw_fd(), msg.as_ptr().cast(), msg.len(), 0) };
        if n < 0 || (n as usize) != msg.len() {
            anyhow::bail!("netlink send: {}", std::io::Error::last_os_error());
        }
        Ok(())
    }

    /// Send a CONFIG message and wait for its ACK (5s budget).
    fn roundtrip(&self, msg: &[u8]) -> anyhow::Result<()> {
        let seq = u32::from_ne_bytes(msg[8..12].try_into().unwrap_or([0; 4]));
        self.send(msg)?;
        let deadline = std::time::Instant::now() + Duration::from_secs(5);
        let mut buf = vec![0u8; 65536];
        loop {
            // SAFETY: buf has capacity; recv fills it, returns byte count.
            let n = unsafe {
                libc::recv(
                    self.fd.as_raw_fd(),
                    buf.as_mut_ptr().cast(),
                    buf.len(),
                    libc::MSG_DONTWAIT,
                )
            };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::WouldBlock {
                    if std::time::Instant::now() > deadline {
                        anyhow::bail!("netlink ACK timeout (seq {seq})");
                    }
                    std::thread::sleep(Duration::from_millis(5));
                    continue;
                }
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                anyhow::bail!("netlink recv: {e}");
            }
            for m in split_messages(&buf[..n as usize]) {
                if m.mtype == NLMSG_ERROR {
                    match parse_ack(m.payload) {
                        Ok(ack_seq) if ack_seq == seq => return Ok(()),
                        Ok(_) => continue, // ACK for another message
                        Err(code) => anyhow::bail!("netlink NACK (seq {seq}): errno {}", -code),
                    }
                }
                // PACKETs arriving mid-handshake are unexpected here;
                // verdicts only start after bind() returns.
            }
            if std::time::Instant::now() > deadline {
                anyhow::bail!("netlink ACK timeout (seq {seq})");
            }
        }
    }

    /// Block until the next queued packet arrives.
    pub fn next_packet(&self) -> anyhow::Result<QueuedPacket> {
        let mut buf = vec![0u8; 65536];
        loop {
            // SAFETY: blocking recv into owned buffer.
            let n =
                unsafe { libc::recv(self.fd.as_raw_fd(), buf.as_mut_ptr().cast(), buf.len(), 0) };
            if n < 0 {
                let e = std::io::Error::last_os_error();
                if e.kind() == std::io::ErrorKind::Interrupted {
                    continue;
                }
                anyhow::bail!("nfqueue recv: {e}");
            }
            for m in split_messages(&buf[..n as usize]) {
                if m.mtype == nl_type(MSG_PACKET) {
                    if let Some(pkt) = parse_packet(m.payload, self.queue) {
                        return Ok(pkt);
                    }
                }
                // ACKs/ERRORs outside handshake are ignored here.
            }
        }
    }

    /// Issue a verdict for a packet id. Thread-safe.
    pub fn verdict(&self, id: u32, verdict: Verdict) -> anyhow::Result<()> {
        let seq = self.next_seq();
        self.send(&encode_verdict(seq, self.pid, self.queue, id, verdict))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pf_bind_encoding_is_exact() {
        // type 0x302, REQUEST|ACK, seq 7, pid 42, nfgenmsg family 0 res 0,
        // CMD attr: len 8, type 1, {PF_BIND, pad, AF_INET be}.
        let m = encode_pf_bind(7, 42, 2);
        assert_eq!(m.len(), 16 + 4 + 8);
        assert_eq!(&m[0..4], &28u32.to_ne_bytes());
        assert_eq!(&m[4..6], &0x0302u16.to_ne_bytes());
        assert_eq!(&m[6..8], &0x0005u16.to_ne_bytes());
        assert_eq!(&m[8..12], &7u32.to_ne_bytes());
        assert_eq!(&m[12..16], &42u32.to_ne_bytes());
        assert_eq!(&m[16..20], &[0, 0, 0, 0]);
        assert_eq!(&m[20..22], &8u16.to_ne_bytes()); // attr len
        assert_eq!(&m[22..24], &CFG_CMD.to_ne_bytes()); // attr type
        assert_eq!(&m[24..28], &[3, 0, 0, 2]); // PF_BIND, pad, AF_INET be
    }

    #[test]
    fn verdict_encoding_is_exact() {
        let m = encode_verdict(9, 42, 0, 0xDEAD_BEEF, Verdict::Drop);
        assert_eq!(&m[4..6], &0x0301u16.to_ne_bytes());
        assert_eq!(&m[20..24], &0u32.to_be_bytes()); // NF_DROP
        assert_eq!(&m[24..28], &0xDEAD_BEEFu32.to_be_bytes());
        let m = encode_verdict(9, 42, 0, 1, Verdict::Accept);
        assert_eq!(&m[20..24], &1u32.to_be_bytes()); // NF_ACCEPT
    }

    #[test]
    fn attr_padding_and_iteration() {
        let mut b = Vec::new();
        push_attr(&mut b, 10, &[1, 2, 3]); // len 7 -> padded to 8
        push_attr(&mut b, 16, &[9, 9, 9, 9]); // len 8
        assert_eq!(b.len(), 16);
        let mut got = Vec::new();
        each_attr(&b, |t, v| got.push((t, v.to_vec())));
        assert_eq!(got, vec![(10, vec![1, 2, 3]), (16, vec![9, 9, 9, 9])]);
        // Truncated tail stops iteration instead of panicking.
        let mut short = b.clone();
        short.truncate(15);
        let mut n = 0;
        each_attr(&short, |_, _| n += 1);
        assert_eq!(n, 1);
    }

    #[test]
    fn parses_kernel_style_packet() {
        // Hand-built PACKET message: nfgenmsg res 0, hdr{id,hwproto,hook},
        // UID + PAYLOAD attrs.
        let mut payload = vec![0, 0, 0, 0]; // nfgenmsg
        payload.extend_from_slice(&0xCAFEBABEu32.to_be_bytes());
        payload.extend_from_slice(&0x0800u16.to_be_bytes());
        payload.push(3); // hook = NF_INET_LOCAL_OUT
        let mut attrs = Vec::new();
        push_attr(&mut attrs, NFQA_UID, &1000u32.to_ne_bytes());
        push_attr(&mut attrs, NFQA_MARK, &7u32.to_ne_bytes());
        push_attr(&mut attrs, NFQA_PAYLOAD, &[0x45, 0, 0, 40]);
        payload.extend_from_slice(&attrs);
        let pkt = parse_packet(&payload, 0).expect("parse");
        assert_eq!(pkt.id, 0xCAFEBABE);
        assert_eq!(pkt.hook, 3);
        assert_eq!(pkt.hw_proto, 0x0800);
        assert_eq!(pkt.uid, Some(1000));
        assert_eq!(pkt.mark, Some(7));
        assert_eq!(pkt.payload, vec![0x45, 0, 0, 40]);
        // Wrong queue number is rejected.
        assert!(parse_packet(&payload, 1).is_none());
    }

    #[test]
    fn ack_parsing() {
        // ERROR with code 0 + echoed 16-byte request header (seq at +8).
        let mut p = vec![0, 0, 0, 0];
        p.extend_from_slice(&[0u8; 16]);
        p[4 + 8..4 + 12].copy_from_slice(&55u32.to_ne_bytes());
        assert_eq!(parse_ack(&p), Ok(55));
        let mut n = vec![13, 255, 255, 255]; // -EACCES-ish
        n.extend_from_slice(&[0u8; 16]);
        assert!(parse_ack(&n).is_err());
    }

    #[test]
    fn message_splitting() {
        let a = encode_queue_bind(1, 2, 0);
        let b = encode_set_mode(3, 2, 0);
        let mut both = a.clone();
        both.extend_from_slice(&b);
        let msgs = split_messages(&both);
        assert_eq!(msgs.len(), 2);
        // Split lands on message boundaries: payloads are the bodies.
        assert_eq!(msgs[0].payload.len(), a.len() - NLMSG_HDRLEN);
        assert_eq!(msgs[1].payload.len(), b.len() - NLMSG_HDRLEN);
        assert_eq!(msgs[0].mtype, msgs[1].mtype);
        assert!(split_messages(&both[..10]).is_empty()); // truncated
    }
}

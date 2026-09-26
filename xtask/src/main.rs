//! xtask: repository automation that deserves code, not shell scripts.
//!
//! Three tasks. `build-ebpf` compiles the eBPF program crate to a loadable
//! object (see its docs for the toolchain fallback chain). `bench` runs
//! dependency-free smoke benchmarks of the packet hot paths. `build-deb`
//! is a historical stub pointing at `packaging/debian/`; real .debs are
//! built with `dpkg-buildpackage`, not here.

use anyhow::{Context, Result};
use std::process::Command;

const EBPF_TARGET: &str = "bpfel-unknown-none";

fn main() -> Result<()> {
    let task = std::env::args()
        .nth(1)
        .context("usage: xtask <build-ebpf|build-deb|bench>")?;
    match task.as_str() {
        "build-ebpf" => build_ebpf(),
        "build-deb" => {
            println!("build .debs with dpkg-buildpackage from packaging/debian/; see README");
            Ok(())
        }
        "bench" => bench(),
        _ => anyhow::bail!("unknown task {task}"),
    }
}

/// Build the eBPF object the official way (aya-template): the program
/// crate is a binary, `-Z build-std` provides core, rustc links the final
/// ELF itself. Tries nightly first (ecosystem-blessed), then stable with
/// `RUSTC_BOOTSTRAP`, because the installed bpf-linker may lag rustc's
/// LLVM bitcode version (observed in the wild: LLVM 23 producer vs
/// LLVM 22 reader). Whichever toolchain wins must also satisfy the
/// section check in [`verify_ebpf`], so a silently wrong object can never
/// ship as a successful build. Needs the rust-src component for the
/// toolchain used.
fn build_ebpf() -> Result<()> {
    // AYA_BPF_TARGET_ARCH pins the bindings variant explicitly instead of
    // inheriting the host triple implicitly (same value here, but explicit
    // and cross-build-safe).
    let host_arch = std::env::consts::ARCH.to_string();
    let attempts: Vec<(&str, Vec<(&str, &str)>)> = vec![
        ("nightly (blessed)", vec![]),
        (
            "stable+RUSTC_BOOTSTRAP (fallback)",
            vec![("RUSTC_BOOTSTRAP", "1")],
        ),
    ];
    let mut errors = Vec::new();
    for (label, env) in &attempts {
        match build_once(label, env, &host_arch) {
            Ok(()) => return verify_ebpf(),
            Err(e) => {
                println!("toolchain {label} failed: {e:#}");
                errors.push(format!("{label}: {e:#}"));
            }
        }
    }
    anyhow::bail!(
        "ebpf build failed with all toolchains:\n{}",
        errors.join("\n")
    );
}

fn build_once(label: &str, env: &[(&str, &str)], host_arch: &str) -> Result<()> {
    println!("trying toolchain: {label}");
    let mut cmd = Command::new("cargo");
    if label.starts_with("nightly") {
        cmd.arg("+nightly");
    }
    cmd.env(
        "CARGO_ENCODED_RUSTFLAGS",
        "-Cdebuginfo=2\x1f-Clink-arg=--btf",
    );
    for (k, v) in env {
        cmd.env(k, v);
    }
    cmd.env("AYA_BPF_TARGET_ARCH", host_arch);
    let st = cmd
        .args([
            "build",
            "-Z",
            "build-std=core",
            "--target",
            EBPF_TARGET,
            "--release",
            "-p",
            "crabwall-ebpf",
        ])
        .status()
        .context("spawn cargo for ebpf build")?;
    if !st.success() {
        anyhow::bail!("cargo build failed");
    }
    Ok(())
}

/// Smoke benchmarks: throughput of the hot paths (packet parsers).
/// Numbers are machine-local medians over one warm run - good enough to
/// catch 10x regressions, not for publication.
fn bench() -> Result<()> {
    use crabwall_packet::frame::parse_frame;
    use crabwall_packet::{dns_parse, sni, test_util};
    use std::time::Instant;

    let dns = test_util::test_dns_response();
    let hello = test_util::build_client_hello("tracker.example.com");
    let mut frame = vec![0u8; 12];
    frame.extend_from_slice(&[0x08, 0x00]);
    let total = (20 + 8 + dns.len()) as u16;
    let mut ip = vec![
        0x45, 0x00, 0, 0, 0, 0, 0, 0, 64, 17, 0, 0, 8, 8, 8, 8, 1, 2, 3, 4,
    ];
    ip[2..4].copy_from_slice(&total.to_be_bytes());
    frame.extend_from_slice(&ip);
    let ulen = (8 + dns.len()) as u16;
    let mut udp = vec![0x00, 0x35, 0x00, 0x35];
    udp.extend_from_slice(&ulen.to_be_bytes());
    udp.extend_from_slice(&[0x00, 0x00]);
    frame.extend_from_slice(&udp);
    frame.extend_from_slice(&dns);

    fn time(label: &str, iters: u64, mut f: impl FnMut()) {
        // Warm up, then measure once (stable enough for smoke purposes).
        for _ in 0..1000 {
            f();
        }
        let start = Instant::now();
        for _ in 0..iters {
            f();
        }
        let ns = start.elapsed().as_nanos() / u128::from(iters);
        println!("{label:24} {ns:>8} ns/op ({:.1} Mop/s)", 1000.0 / ns as f64);
    }

    time("dns_parse", 50_000, || {
        std::hint::black_box(dns_parse::parse_dns_response(&dns));
    });
    time("sni_extract", 50_000, || {
        std::hint::black_box(sni::extract_sni(&hello));
    });
    time("frame_parse", 50_000, || {
        std::hint::black_box(parse_frame(&frame));
    });
    Ok(())
}

/// The loader (aya-obj) needs exactly these: program section, maps, license.
fn verify_ebpf() -> Result<()> {
    let path = format!("target/{EBPF_TARGET}/release/crabwall-ebpf");
    let sections = Command::new("llvm-readelf")
        .args(["-S", "--wide", &path])
        .output()
        .context("llvm-readelf the ebpf object")?;
    let text = String::from_utf8_lossy(&sections.stdout);
    println!("{text}");
    for need in ["tracepoint/syscalls/sys_enter_connect", "maps", "license"] {
        if !text.contains(need) {
            anyhow::bail!("ebpf object missing section: {need}");
        }
    }
    println!("ebpf object: {path}");
    Ok(())
}

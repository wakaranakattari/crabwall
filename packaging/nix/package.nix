{ lib, rustPlatform }:

rustPlatform.buildRustPackage {
  pname = "crabwall";
  version = "1.0.0";

  # Workspace root is two levels up from packaging/nix.
  src = ../..;
  cargoLock.lockFile = ../../Cargo.lock;

  # rusqlite uses the bundled SQLite; nftables CLI is a runtime dep.
  buildInputs = [ ];

  # Only the two binaries; the eBPF object needs nightly + bpf-linker
  # and is built separately (see `cargo xtask build-ebpf`).
  cargoBuildFlags = [ "-p" "crabwalld" "-p" "crabwall" ];
  cargoTestFlags = [ "--workspace" "--exclude" "crabwall-ebpf" ];

  postInstall = ''
    install -Dm0644 $src/packaging/systemd/crabwalld.service \
      $out/lib/systemd/system/crabwalld.service
    install -Dm0644 $src/man/crabwall.1 $out/share/man/man1/crabwall.1
    install -Dm0644 $src/man/crabwalld.8 $out/share/man/man8/crabwalld.8
  '';

  meta = with lib; {
    description = "Little Snitch for Linux: per-app firewall prompts";
    homepage = "https://github.com/wakaranakattari/crabwall";
    license = licenses.mit;
    platforms = platforms.linux;
    mainProgram = "crabwall";
  };
}

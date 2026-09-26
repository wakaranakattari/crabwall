#!/bin/sh
# crabwall service installer: detects the init system and installs
# the matching service definition.
#
#   ./packaging/install.sh                        # build + install + start
#   ./packaging/install.sh --no-build
#   ./packaging/install.sh --services-only --no-start   # CI: files only
#   ./packaging/install.sh uninstall
#
# Privileges are handled automatically: binaries always build as the
# invoking user (root builds poison target/ and root rarely has a Rust
# toolchain), installation escalates with sudo. So just run it directly -
# no sudo needed, no PATH/HOME surprises.
#
# Env: PREFIX (default /usr/local), SCANDIR (s6), CRABWALL_INIT
# (force systemd|runit|openrc|s6|sysvinit, useful in containers/chroots).
#
# Supported: systemd, runit, OpenRC, s6, SysVinit (LSB fallback).
# The daemon itself is init-agnostic: it logs to stdout/stderr and
# needs no systemd-only features.

set -eu

PREFIX="${PREFIX:-/usr/local}"
NO_BUILD=0
NO_START=0
SERVICES_ONLY=0
ESCALATED=0
ACTION="install"

for arg in "$@"; do
	case "$arg" in
	--no-build) NO_BUILD=1 ;;
	--no-start) NO_START=1 ;;
	--services-only) SERVICES_ONLY=1 ;;
	--escalated) ESCALATED=1 ;; # internal: set on the sudo re-exec below
	uninstall) ACTION="uninstall" ;;
	-h | --help)
		echo "Usage: $0 [--no-build] [--no-start] [--services-only] [uninstall]"
		exit 0
		;;
	*)
		echo "Unknown arg: $arg" >&2
		exit 1
		;;
	esac
done

HERE="$(dirname "$0")"
ROOT="$(cd "$HERE/.." && pwd)"
cd "$ROOT" || exit 1
DAEMON_SRC="target/release/crabwalld"
CLI_SRC="target/release/crabwall"

detect_init() {
	if [ -n "${CRABWALL_INIT:-}" ]; then
		echo "$CRABWALL_INIT"
	elif [ -d /run/systemd/system ]; then
		echo systemd
	elif command -v runsvdir >/dev/null 2>&1 \
		|| [ -d /run/runit/service ] || [ -d /var/service ]; then
		echo runit
	elif command -v openrc-run >/dev/null 2>&1 \
		|| [ -d /run/openrc ]; then
		echo openrc
	elif command -v s6-svscan >/dev/null 2>&1; then
		echo s6
	elif [ -d /etc/init.d ]; then
		echo sysvinit
	else
		echo none
	fi
}

runit_service_dir() {
	for d in /run/runit/service /var/service /service; do
		if [ -d "$d" ]; then
			echo "$d"
			return
		fi
	done
	echo "/var/service"
}

install_bins() {
	if [ ! -f "$DAEMON_SRC" ] || [ ! -f "$CLI_SRC" ]; then
		echo "binaries missing ($DAEMON_SRC). Re-run without --no-build." >&2
		exit 1
	fi
	mkdir -p "$PREFIX/bin"
	install -m 0755 "$DAEMON_SRC" "$PREFIX/bin/crabwalld"
	install -m 0755 "$CLI_SRC" "$PREFIX/bin/crabwall"
	echo "==> binaries in $PREFIX/bin"
	install_manpages
}

install_manpages() {
	mkdir -p "$PREFIX/share/man/man1" "$PREFIX/share/man/man8"
	install -m 0644 "$HERE/../man/crabwall.1" "$PREFIX/share/man/man1/crabwall.1" 2>/dev/null || true
	install -m 0644 "$HERE/../man/crabwalld.8" "$PREFIX/share/man/man8/crabwalld.8" 2>/dev/null || true
}

do_systemd() {
	# mkdir: minimal containers ship systemctl without its unit dirs.
	mkdir -p /etc/systemd/system
	install -m 0644 "$HERE/systemd/crabwalld.service" /etc/systemd/system/
	command -v systemctl >/dev/null 2>&1 || {
		echo "systemd selected but systemctl not found" >&2
		exit 1
	}
	# Best-effort: fails without a running systemd (containers, chroots).
	systemctl daemon-reload || true
	if [ "$NO_START" -eq 0 ]; then
		systemctl enable --now crabwalld
		systemctl status crabwalld --no-pager || true
	else
		systemctl enable crabwalld
	fi
}

do_runit() {
	SVC="$(runit_service_dir)"
	mkdir -p /etc/sv/crabwalld/log /var/log/crabwalld
	install -m 0755 "$HERE/runit/crabwalld/run" /etc/sv/crabwalld/run
	install -m 0755 "$HERE/runit/crabwalld/log-run" /etc/sv/crabwalld/log/run
	mkdir -p "$SVC"
	ln -sfn /etc/sv/crabwalld "$SVC/crabwalld"
	echo "==> linked /etc/sv/crabwalld -> $SVC/crabwalld"
	echo "Run 'sv status crabwalld' to check."
}

do_openrc() {
	install -m 0755 "$HERE/openrc/crabwalld" /etc/init.d/crabwalld
	rc-update add crabwalld default
	if [ "$NO_START" -eq 0 ]; then
		rc-service crabwalld start
	fi
}

do_s6() {
	echo "s6 scandirs vary by distro; set SCANDIR or pass --no-build and copy manually:"
	echo "  cp -r $HERE/s6/crabwalld \${SCANDIR:-/run/s6/services}/crabwalld"
	if [ -n "${SCANDIR:-}" ]; then
		mkdir -p "$SCANDIR/crabwalld"
		install -m 0755 "$HERE/s6/crabwalld/run" "$SCANDIR/crabwalld/run"
		echo "==> installed to $SCANDIR/crabwalld (s6-svscan picks it up)"
	fi
}

do_sysvinit() {
	install -m 0755 "$HERE/sysvinit/crabwalld" /etc/init.d/crabwalld
	if command -v update-rc.d >/dev/null 2>&1; then
		update-rc.d crabwalld defaults
	elif command -v chkconfig >/dev/null 2>&1; then
		chkconfig --add crabwalld
	fi
	if [ "$NO_START" -eq 0 ]; then
		service crabwalld start || /etc/init.d/crabwalld start
	fi
}

uninstall_all() {
	rm -f "$PREFIX/bin/crabwalld" "$PREFIX/bin/crabwall"
	rm -f "$PREFIX/share/man/man1/crabwall.1" "$PREFIX/share/man/man8/crabwalld.8"
	rm -f /etc/systemd/system/crabwalld.service
	rm -rf /etc/sv/crabwalld
	for d in /run/runit/service /var/service /service; do
		rm -f "$d/crabwalld"
	done
	rm -f /etc/init.d/crabwalld
	if [ -n "${SCANDIR:-}" ]; then
		rm -rf "$SCANDIR/crabwalld"
	fi
	command -v systemctl >/dev/null 2>&1 && systemctl daemon-reload || true
	echo "Binaries and service definitions removed. Config/logs kept."
}

if [ "$ACTION" = "uninstall" ]; then
	if [ "$(id -u)" -ne 0 ]; then
		echo "Run as root." >&2
		exit 1
	fi
	uninstall_all
	exit 0
fi

# --- install: build as the user, install as root -----------------------
check_toolchain() {
	command -v cargo >/dev/null 2>&1 && return 0
	if command -v rustup >/dev/null 2>&1; then
		echo "rustup found but no default toolchain. Run: rustup default stable" >&2
	else
		echo "cargo not found. Install Rust from https://rustup.rs/," >&2
		echo "then run: rustup default stable" >&2
	fi
	echo "(fish users: fish_add_path ~/.cargo/bin)" >&2
	return 1
}

build_bins() {
	if [ "$NO_BUILD" -eq 1 ] || [ "$SERVICES_ONLY" -eq 1 ]; then
		return 0
	fi
	if [ "$(id -u)" -eq 0 ] && [ "${SUDO_USER:-root}" != root ]; then
		user_home=$(getent passwd "$SUDO_USER" | cut -d: -f6)
		echo "==> building as $SUDO_USER (root has no toolchain, and root builds poison target/)"
		sudo -u "$SUDO_USER" env "HOME=$user_home" \
			"PATH=$user_home/.cargo/bin:/usr/local/bin:/usr/bin:/bin" \
			sh -c 'command -v cargo >/dev/null || { echo "cargo not found for $USER"; exit 1; }; cargo build --release -p crabwalld -p crabwall' \
			|| exit 1
		return 0
	fi
	check_toolchain || exit 1
	echo "==> cargo build --release -p crabwalld -p crabwall"
	cargo build --release -p crabwalld -p crabwall
}

if [ "$(id -u)" -ne 0 ]; then
	if [ "$ESCALATED" -eq 1 ]; then
		echo "escalation failed: still uid $(id -u) after sudo; check sudo configuration." >&2
		exit 1
	fi
	build_bins
	echo "==> install needs root; re-running under sudo"
	exec sudo "$0" --escalated --no-build "$@"
fi

# Root path: build as the invoking user when there is one (root almost
# never has a toolchain, and root builds poison target/ ownership).
build_bins

if [ "$SERVICES_ONLY" -eq 0 ]; then
	install_bins
fi
INIT="$(detect_init)"
echo "==> detected init: $INIT"
case "$INIT" in
systemd) do_systemd ;;
runit) do_runit ;;
openrc) do_openrc ;;
s6) do_s6 ;;
sysvinit) do_sysvinit ;;
none)
	echo "No supported init detected."
	echo "Run the daemon manually: $PREFIX/bin/crabwalld"
	;;
esac

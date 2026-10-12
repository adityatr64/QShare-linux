PREFIX ?= /usr/local
BIN_NAME := QShare-linux
DESKTOP_ID := com.google.QuickShare

.PHONY: all build clean test install install-user uninstall firewall check-network

all: build

build:
	cargo build --release

test:
	cargo test

check-network:
	@echo "Checking network connectivity and dependencies..."
	@which avahi-browse >/dev/null 2>&1 && echo "[OK] avahi-browse installed" || echo "[WARN] avahi-browse missing"
	@which bluetoothctl >/dev/null 2>&1 && echo "[OK] bluetoothctl installed" || echo "[WARN] bluetoothctl missing"
	@echo "Checking mDNS port 5353/udp..."
	@ss -lun | grep 5353 >/dev/null 2>&1 && echo "[OK] mDNS socket active" || echo "[WARN] No active mDNS socket"

firewall:
	./scripts/setup-firewall.sh

install: build
	./install.sh --system --skip-build

install-user: build
	./install.sh --user --skip-build

uninstall:
	./install.sh --uninstall

clean:
	cargo clean

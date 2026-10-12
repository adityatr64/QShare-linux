#!/usr/bin/env bash
# Quick Share Linux - Network and Firewall Configuration Script
# Configures local firewall rules for mDNS (5353/UDP) and Quick Share TCP (8765-8815/TCP).

set -euo pipefail

# Ensure elevated privileges if modifying system firewall
check_root() {
    if [ "$(id -u)" -ne 0 ]; then
        if command -v sudo >/dev/null 2>&1; then
            echo "[INFO] Elevating privileges via sudo..."
            exec sudo "$0" "$@"
        else
            echo "[ERROR] Root privileges required to configure system firewall." >&2
            exit 1
        fi
    fi
}

detect_and_apply_firewall() {
    local applied=0

    # 1. UFW (Uncomplicated Firewall)
    if command -v ufw >/dev/null 2>&1 && ufw status | grep -qw "active"; then
        echo "[INFO] Detected active UFW firewall. Applying rules..."
        ufw allow 5353/udp comment "Quick Share mDNS Discovery"
        ufw allow 8765:8815/tcp comment "Quick Share File Transfers"
        ufw reload
        echo "[SUCCESS] UFW rules successfully added."
        applied=1
    fi

    # 2. Firewalld
    if command -v firewall-cmd >/dev/null 2>&1 && systemctl is-active --quiet firewalld 2>/dev/null; then
        echo "[INFO] Detected active firewalld. Applying rules..."
        firewall-cmd --permanent --add-service=mdns
        firewall-cmd --permanent --add-port=8765-8815/tcp
        firewall-cmd --reload
        echo "[SUCCESS] firewalld rules successfully added."
        applied=1
    fi

    # 3. nftables
    if [ "$applied" -eq 0 ] && command -v nft >/dev/null 2>&1 && systemctl is-active --quiet nftables 2>/dev/null; then
        echo "[INFO] Detected active nftables. Appending rules to inet filter table..."
        if nft list tables | grep -q "table inet filter"; then
            nft add rule inet filter input udp dport 5353 ip daddr 224.0.0.251 accept comment "Quick Share mDNS" 2>/dev/null || true
            nft add rule inet filter input tcp dport 8765-8815 ct state new,established accept comment "Quick Share TCP" 2>/dev/null || true
            echo "[SUCCESS] nftables rules added to inet filter table."
            applied=1
        fi
    fi

    # 4. Fallback: iptables
    if [ "$applied" -eq 0 ] && command -v iptables >/dev/null 2>&1; then
        echo "[INFO] Adding fallback iptables rules..."
        iptables -C INPUT -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p udp --dport 5353 -d 224.0.0.251 -j ACCEPT
        iptables -C INPUT -p tcp --dport 8765:8815 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT 2>/dev/null || \
            iptables -A INPUT -p tcp --dport 8765:8815 -m conntrack --ctstate NEW,ESTABLISHED -j ACCEPT
        echo "[SUCCESS] iptables rules applied."
        applied=1
    fi

    if [ "$applied" -eq 0 ]; then
        echo "[WARN] No active firewall management daemon detected or rules could not be applied automatically."
        echo "[INFO] Ensure ports 5353/UDP and 8765-8815/TCP are accessible on your local network."
    fi
}

check_services() {
    echo "[INFO] Checking supporting system daemons..."

    # Check Avahi (mDNS)
    if command -v systemctl >/dev/null 2>&1; then
        if systemctl list-unit-files | grep -qw "avahi-daemon.service"; then
            if ! systemctl is-active --quiet avahi-daemon.service; then
                echo "[INFO] Starting avahi-daemon.service..."
                systemctl enable --now avahi-daemon.service || true
            else
                echo "[OK] avahi-daemon.service is active."
            fi
        else
            echo "[WARN] avahi-daemon not found. Ensure Avahi or an mDNS responder is installed."
        fi

        # Check Bluetooth (BlueZ)
        if systemctl list-unit-files | grep -qw "bluetooth.service"; then
            if ! systemctl is-active --quiet bluetooth.service; then
                echo "[INFO] Starting bluetooth.service..."
                systemctl enable --now bluetooth.service || true
            else
                echo "[OK] bluetooth.service is active."
            fi
        fi
    fi
}

main() {
    check_root "$@"
    echo "=================================================="
    echo " Quick Share Linux: Network and Firewall Setup"
    echo "=================================================="
    detect_and_apply_firewall
    check_services
    echo "=================================================="
    echo " Network configuration complete."
    echo "=================================================="
}

main "$@"

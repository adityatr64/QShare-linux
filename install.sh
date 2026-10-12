#!/usr/bin/env bash
# Quick Share Linux - System and Desktop Installer
# Installs quickshare-receiver binary, desktop entry, scalable application icon,
# systemd user service, and configures local firewall rules.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BIN_NAME="QShare-linux"
SERVICE_NAME="qshare-linux"
DESKTOP_ID="com.google.QuickShare"

MODE="auto"
SKIP_BUILD=0
SKIP_FIREWALL=0
UNINSTALL=0

usage() {
    cat <<EOF
Usage: $0 [OPTIONS]

Options:
  --system         Install system-wide to /usr/local (requires root / sudo)
  --user           Install to user environment (~/.local)
  --uninstall      Uninstall Quick Share from the system
  --skip-build     Use existing binary in target/release without rebuilding
  --skip-firewall  Do not modify firewall rules during installation
  --help           Display this help message

Examples:
  sudo ./install.sh              # System-wide installation with automated firewall setup
  ./install.sh --user            # Per-user desktop installation
  sudo ./install.sh --uninstall  # Clean removal
EOF
    exit 0
}

while [ $# -gt 0 ]; do
    case "$1" in
        --system) MODE="system"; shift ;;
        --user) MODE="user"; shift ;;
        --uninstall) UNINSTALL=1; shift ;;
        --skip-build) SKIP_BUILD=1; shift ;;
        --skip-firewall) SKIP_FIREWALL=1; shift ;;
        --help|-h) usage ;;
        *) echo "[ERROR] Unknown option: $1" >&2; usage ;;
    esac
done

if [ "$MODE" = "auto" ]; then
    if [ "$(id -u)" -eq 0 ]; then
        MODE="system"
    else
        MODE="user"
    fi
fi

if [ "$MODE" = "system" ]; then
    PREFIX="/usr/local"
    BIN_DIR="${PREFIX}/bin"
    APP_DIR="${PREFIX}/share/applications"
    ICON_DIR="${PREFIX}/share/icons/hicolor/scalable/apps"
    PIXMAP_DIR="/usr/share/pixmaps"
    SYSTEMD_USER_DIR="${PREFIX}/lib/systemd/user"
else
    PREFIX="${HOME}/.local"
    BIN_DIR="${PREFIX}/bin"
    APP_DIR="${PREFIX}/share/applications"
    ICON_DIR="${PREFIX}/share/icons/hicolor/scalable/apps"
    PIXMAP_DIR="${HOME}/.local/share/pixmaps"
    SYSTEMD_USER_DIR="${HOME}/.config/systemd/user"
fi

do_uninstall() {
    echo "[INFO] Uninstalling QShare Linux ($MODE)..."
    rm -f "${BIN_DIR}/${BIN_NAME}"
    rm -f "${BIN_DIR}/qshare-linux"
    rm -f "${APP_DIR}/${DESKTOP_ID}.desktop"
    rm -f "${ICON_DIR}/${DESKTOP_ID}.svg"
    rm -f "${PIXMAP_DIR}/${DESKTOP_ID}.svg"
    rm -f "${SYSTEMD_USER_DIR}/${SERVICE_NAME}.service"

    if command -v update-desktop-database >/dev/null 2>&1; then
        update-desktop-database "${APP_DIR}" 2>/dev/null || true
    fi
    if command -v gtk-update-icon-cache >/dev/null 2>&1 && [ "$MODE" = "system" ]; then
        gtk-update-icon-cache -q -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
    fi

    echo "[SUCCESS] Quick Share uninstalled successfully."
    exit 0
}

if [ "$UNINSTALL" -eq 1 ]; then
    do_uninstall
fi

echo "=================================================="
echo " Quick Share Linux Installer ($MODE mode)"
echo "=================================================="

# 1. Build release binary if requested
if [ "$SKIP_BUILD" -eq 0 ]; then
    if [ ! -f "${SCRIPT_DIR}/target/release/${BIN_NAME}" ]; then
        echo "[INFO] Compiling release binary with Cargo..."
        if ! command -v cargo >/dev/null 2>&1; then
            echo "[ERROR] Cargo (Rust toolchain) is not installed. Please install Rust or pass --skip-build." >&2
            exit 1
        fi
        cargo build --manifest-path "${SCRIPT_DIR}/Cargo.toml" --release
    else
        echo "[INFO] Existing binary found at target/release/${BIN_NAME}."
    fi
fi

if [ ! -f "${SCRIPT_DIR}/target/release/${BIN_NAME}" ]; then
    echo "[ERROR] Binary target/release/${BIN_NAME} not found. Build failed." >&2
    exit 1
fi

# 2. Create required directory hierarchy
mkdir -p "${BIN_DIR}" "${APP_DIR}" "${ICON_DIR}" "${PIXMAP_DIR}" "${SYSTEMD_USER_DIR}"

# 3. Install binary
echo "[INFO] Installing binary to ${BIN_DIR}/${BIN_NAME}..."
install -Dm755 "${SCRIPT_DIR}/target/release/${BIN_NAME}" "${BIN_DIR}/${BIN_NAME}"
ln -sf "${BIN_NAME}" "${BIN_DIR}/qshare-linux"

# 4. Install Desktop Entry
echo "[INFO] Installing desktop file to ${APP_DIR}/${DESKTOP_ID}.desktop..."
install -Dm644 "${SCRIPT_DIR}/data/${DESKTOP_ID}.desktop" "${APP_DIR}/${DESKTOP_ID}.desktop"

# 5. Install Scalable Application Icon
echo "[INFO] Installing SVG application icon to ${ICON_DIR}/${DESKTOP_ID}.svg..."
install -Dm644 "${SCRIPT_DIR}/data/icons/hicolor/scalable/apps/${DESKTOP_ID}.svg" "${ICON_DIR}/${DESKTOP_ID}.svg"
install -Dm644 "${SCRIPT_DIR}/data/icons/hicolor/scalable/apps/${DESKTOP_ID}.svg" "${PIXMAP_DIR}/${DESKTOP_ID}.svg" 2>/dev/null || true

# 6. Install systemd user service
echo "[INFO] Installing systemd user service unit..."
install -Dm644 "${SCRIPT_DIR}/systemd/${SERVICE_NAME}.service" "${SYSTEMD_USER_DIR}/${SERVICE_NAME}.service"
sed -i "s|ExecStart=.*|ExecStart=${BIN_DIR}/${BIN_NAME} --headless|" "${SYSTEMD_USER_DIR}/${SERVICE_NAME}.service"

# 7. Update desktop database and icon caches
if command -v update-desktop-database >/dev/null 2>&1; then
    echo "[INFO] Updating desktop database..."
    update-desktop-database "${APP_DIR}" 2>/dev/null || true
fi
if command -v gtk-update-icon-cache >/dev/null 2>&1; then
    echo "[INFO] Updating icon cache..."
    gtk-update-icon-cache -q -t "${PREFIX}/share/icons/hicolor" 2>/dev/null || true
fi

# 8. Firewall & Network Setup
if [ "$SKIP_FIREWALL" -eq 0 ]; then
    echo "[INFO] Configuring networking and firewall ports..."
    if [ "$(id -u)" -eq 0 ]; then
        "${SCRIPT_DIR}/scripts/setup-firewall.sh"
    else
        if command -v sudo >/dev/null 2>&1; then
            echo "[INFO] Running firewall setup with sudo..."
            sudo "${SCRIPT_DIR}/scripts/setup-firewall.sh" || {
                echo "[WARN] Automatic firewall configuration skipped or failed. Run scripts/setup-firewall.sh manually."
            }
        else
            echo "[WARN] Cannot configure firewall automatically without root privileges."
            echo "[INFO] Run '${SCRIPT_DIR}/scripts/setup-firewall.sh' as root to open TCP 8765-8815 and UDP 5353."
        fi
    fi
fi

echo "=================================================="
echo " Installation Complete!"
echo " Binary Location:     ${BIN_DIR}/${BIN_NAME}"
echo " Desktop Launcher:    ${APP_DIR}/${DESKTOP_ID}.desktop"
echo " Systemd Unit:        ${SYSTEMD_USER_DIR}/${SERVICE_NAME}.service"
echo ""
echo " You can now launch QShare directly from your application runner"
echo " (GNOME Dash, KDE KRunner, Rofi, Wofi, etc.) or run: ${BIN_NAME}"
echo "=================================================="

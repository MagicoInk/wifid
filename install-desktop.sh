#!/bin/sh
# Installs a desktop launcher (menu icon) for the wifi-deauth GUI into the current
# user's application menu. Paths are derived from this script's location, so it works
# wherever the project lives. Run it as your normal user (NOT with sudo).
set -e
DIR=$(cd "$(dirname "$0")" && pwd)
APPS="${XDG_DATA_HOME:-$HOME/.local/share}/applications"
mkdir -p "$APPS"

chmod +x "$DIR/wifi-deauth-gui.sh"

cat > "$APPS/wifi-deauth.desktop" <<EOF
[Desktop Entry]
Type=Application
Version=1.0
Name=WiFi Deauth GUI
GenericName=WiFi scanner & deauth toolkit
Comment=Escaneo WiFi, de-auth, radar de distancia e integración con Kismet
Exec=$DIR/wifi-deauth-gui.sh
Icon=$DIR/wifi_deauth/assets/wifi-deauth.png
Terminal=true
Categories=Network;Security;
Keywords=wifi;deauth;kismet;wireless;monitor;scanner;
StartupNotify=true
EOF

chmod +x "$APPS/wifi-deauth.desktop"
gio set "$APPS/wifi-deauth.desktop" metadata::trusted true 2>/dev/null || true
update-desktop-database "$APPS" 2>/dev/null || true

echo "Instalado. Búscalo como 'WiFi Deauth GUI' en el menú de aplicaciones."
echo "Entrada: $APPS/wifi-deauth.desktop"

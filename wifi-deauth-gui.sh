#!/bin/sh
# Launcher for the wifi-deauth GUI.
# The GUI needs root (scapy uses raw sockets to sniff/inject), so it runs under sudo
# and forwards the X display so the window appears in the user's session.
DIR=$(cd "$(dirname "$0")" && pwd)
exec sudo env DISPLAY="$DISPLAY" XAUTHORITY="${XAUTHORITY:-$HOME/.Xauthority}" \
    PYTHONPATH="$DIR" python3 -m wifi_deauth.gui "$@"

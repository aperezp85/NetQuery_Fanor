#!/bin/bash
LOG="/var/log/vpn-check.log"
VPN_IP="200.27.43.18"
VPN_USER="clarogp"
VPN_PASS="claro.171"

if ! ip link show tun0 > /dev/null 2>&1; then
    echo "[$(date)] VPN caida. Reconectando..." >> "$LOG"
    pkill openconnect 2>/dev/null
    sleep 2
    echo "$VPN_PASS" | sudo openconnect --protocol=gp --user="$VPN_USER" --passwd-on-stdin --background --servercert pin-sha256:i02HSCjIBEJbd9XbgZy2W/ZbEhcGRT7/Y18oBxVA3hA= "$VPN_IP" >> "$LOG" 2>&1
    sleep 5
    if ip link show tun0 > /dev/null 2>&1; then
        echo "[$(date)] VPN reconectada OK" >> "$LOG"
    else
        echo "[$(date)] ERROR: No se pudo reconectar la VPN" >> "$LOG"
    fi
else
    echo "[$(date)] VPN activa OK" >> "$LOG"
fi

#!/bin/bash
set -euo pipefail

BASE_DIR=$(dirname "$(readlink -f "$0")")
LOGFILE="$BASE_DIR/ampdefend.log"
ALERTFILE="$BASE_DIR/ampdefend_alerts.log"
BLOCKED_IPS="$BASE_DIR/blocked_ips.txt"
OFFSET_FILE="$BASE_DIR/.ampdefend.offset"

LED_PIN=17           # GPIO17 = physical pin 11
TEST_MODE=true       # true = don't really block; false = block with nftables
POLL_INTERVAL=2      # seconds
LED_PULSE_SEC=2      # LED on-time per new event

touch "$LOGFILE" "$ALERTFILE" "$BLOCKED_IPS"
[ -f "$OFFSET_FILE" ] || echo 0 > "$OFFSET_FILE"

# gpiod setup
CHIP="gpiochip0"   # adjust if your board uses a different chip
gpiodetect | grep -q "$CHIP" || { echo "GPIO chip $CHIP not found"; exit 1; }

# Initialize LED (set as output, low)
gpioset "$CHIP" "$LED_PIN"=0

# nftables base (idempotent)
if ! nft list tables | grep -q "inet filter"; then
  nft add table inet filter
fi
if ! nft list chain inet filter input >/dev/null 2>&1; then
  nft add chain inet filter input { type filter hook input priority 0\; policy accept\; }
fi

# Start honeypots if not running
for H in modbus_honeypot.py ocpp_honeypot.py iec104_honeypot.py; do
  if ! pgrep -f "$BASE_DIR/$H" >/dev/null; then
    echo "$(date) - Starting $H..." | tee -a "$LOGFILE"
    python3 "$BASE_DIR/$H" >> "$LOGFILE" 2>&1 &
  fi
done

echo "$(date) - AMPDefend manager started (TEST_MODE=$TEST_MODE)" | tee -a "$LOGFILE"

PATTERN='New OCPP connection|Received from|IEC104 Interrogation|Modbus Read|Modbus Write'

while true; do
  SIZE=$(stat -c%s "$LOGFILE" 2>/dev/null || echo 0)
  LAST=$(cat "$OFFSET_FILE" 2>/dev/null || echo 0)

  if [ "$SIZE" -gt "$LAST" ]; then
    NEW="$(tail -c +$((LAST+1)) "$LOGFILE")"
    echo "$SIZE" > "$OFFSET_FILE"

    if echo "$NEW" | grep -Eiq "$PATTERN"; then
      echo "$(date) - ALERT: Intrusion detected!" | tee -a "$ALERTFILE"
      
      # Turn LED on
      gpioset "$CHIP" "$LED_PIN"=1

      ATTACKER_IP=$(echo "$NEW" | grep -oE '([0-9]{1,3}\.){3}[0-9]{1,3}' | tail -n1 || true)
      if [ -n "${ATTACKER_IP:-}" ]; then
        if ! grep -qx "$ATTACKER_IP" "$BLOCKED_IPS"; then
          if [ "$TEST_MODE" = false ]; then
            nft add rule inet filter input ip saddr $ATTACKER_IP drop || true
            echo "$(date) - Blocked IP $ATTACKER_IP" | tee -a "$ALERTFILE"
          else
            echo "$(date) - [TEST MODE] Would have blocked IP $ATTACKER_IP" | tee -a "$ALERTFILE"
          fi
          echo "$ATTACKER_IP" >> "$BLOCKED_IPS"
        fi

        # simple VPN likelihood (heuristic)
        if [[ $ATTACKER_IP =~ ^(3\.|13\.|18\.|34\.|35\.|40\.|44\.|52\.|54\.) ]]; then
          VPN_LIKELIHOOD=80
        else
          VPN_LIKELIHOOD=20
        fi
        echo "$(date) - Estimated VPN likelihood: $VPN_LIKELIHOOD%" | tee -a "$ALERTFILE"
      fi

      sleep "$LED_PULSE_SEC"
      
      # Turn LED off
      gpioset "$CHIP" "$LED_PIN"=0
    fi
  fi

  sleep "$POLL_INTERVAL"
done

    

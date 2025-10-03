#!/usr/bin/env bash
set -euo pipefail

# USO: ./run_monkey.sh 1    # 1 = SSH scenario
#      ./run_monkey.sh 2    # 2 = LOG4SHELL scenario

if [[ "${1:-}" != "1" && "${1:-}" != "2" ]]; then
  echo "Usage: $0 <1|2>   (1=SSH, 2=LOG4SHELL)"
  exit 2
fi
SCEN="$1"

# ===== CONFIG =====
MONKEY_HOST="monkey.com:5000"
RESOLVE_IP="127.0.0.1"
USER="admin"
PASS="password"
TMPDIR="/tmp/monkey_setup"
TMP_REG="$TMPDIR/monkey_reg.json"
TMP_LOGIN="$TMPDIR/monkey_login.json"
TMP_OTP="$TMPDIR/monkey_otp.json"
TMP_AGENT="$TMPDIR/monkey-linux-64"
KALI_CONTAINER_FILTER="kali"
R5_CONTAINER_FILTER="r5"
mkdir -p "$TMPDIR"

CURL_BASE=(curl -s -k --resolve "${MONKEY_HOST%%:*}:5000:$RESOLVE_IP")

# ===== scenario-specific paths =====
# default (SSH scenario)
MONKEY_CONF="/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/monkey/config/SSH/monkey.conf"
CREDENTIALS_JSON="/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/monkey/config/SSH/credentials.json"
DATASET_BASE_PATH="/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset"

PLUGIN_PAYLOADS_SSH=(
  '{"plugin_type":"Exploiter","name":"SSH","version":"1.0.0"}'
  '{"plugin_type":"Payload","name":"Ransomware","version":"1.0.0"}'
)
PLUGIN_PAYLOADS_LOG4J=(
  '{"plugin_type":"Exploiter","name":"Log4Shell","version":"2.0.0"}'
  '{"plugin_type":"Payload","name":"Ransomware","version":"1.0.0"}'
)

if [[ "$SCEN" == "2" ]]; then
  MONKEY_CONF="/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/monkey/config/LOG4J/monkey.conf"
  CREDENTIALS_JSON=""   # signal to skip
  SCENARIO_NAME="scenario2_LOG4J_ransomware"
else
  SCENARIO_NAME="scenario1_SSH_ransomware"
fi

PCAP_SAVE_DIR="$DATASET_BASE_PATH/$SCENARIO_NAME/pcap"
EVENTS_SAVE_DIR="$DATASET_BASE_PATH/$SCENARIO_NAME/monkey_events"

# ===== helpers =====
require_cmd() { command -v "$1" >/dev/null 2>&1 || { echo "Missing $1"; exit 1; } }
require_cmd curl
require_cmd jq
require_cmd docker

# Crea le directory di destinazione se non esistono
mkdir -p "$PCAP_SAVE_DIR"
mkdir -p "$EVENTS_SAVE_DIR"

echo "[*] registration-status..."
REG_STAT=$("${CURL_BASE[@]}" "https://${MONKEY_HOST}/api/registration-status")
NEEDS_REG=$(echo "$REG_STAT" | jq -r '.needs_registration // false')

TOKEN=""
CSRF=""

if [[ "$NEEDS_REG" == "true" ]]; then
  echo "[*] registering..."
  "${CURL_BASE[@]}" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    "https://${MONKEY_HOST}/api/register" -o "$TMP_REG"
  TOKEN=$(jq -r '.response.user.authentication_token // empty' "$TMP_REG")
  CSRF=$(jq -r '.response.csrf_token // empty' "$TMP_REG")
else
  echo "[*] logging in..."
  "${CURL_BASE[@]}" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    "https://${MONKEY_HOST}/api/login" -o "$TMP_LOGIN" || true
  TOKEN=$(jq -r '.response.user.authentication_token // empty' "$TMP_LOGIN" 2>/dev/null || true)
  CSRF=$(jq -r '.response.csrf_token // empty' "$TMP_LOGIN" 2>/dev/null || true)
fi

# fallback: try login if empty
if [[ -z "$TOKEN" ]]; then
  echo "[!] no token yet, retrying login..."
  "${CURL_BASE[@]}" -X POST -H "Content-Type: application/json" \
    -d "{\"username\":\"$USER\",\"password\":\"$PASS\"}" \
    "https://${MONKEY_HOST}/api/login" -o "$TMP_LOGIN"
  TOKEN=$(jq -r '.response.user.authentication_token // empty' "$TMP_LOGIN")
  CSRF=$(jq -r '.response.csrf_token // empty' "$TMP_LOGIN")
fi

if [[ -z "$TOKEN" ]]; then
  echo "[!!] Authentication failed, no token. Check creds/registration."
  cat "$TMP_LOGIN" "$TMP_REG" 2>/dev/null || true
  exit 1
fi
echo "[OK] token len=$(echo -n "$TOKEN" | wc -c)"

# small stabilization pause
sleep 1

# ===== install plugins (no check pre-availability) =====
echo "[*] Installing plugins for scenario $SCEN..."
if [[ "$SCEN" == "1" ]]; then
  PLUGINS=("${PLUGIN_PAYLOADS_SSH[@]}")
else
  PLUGINS=("${PLUGIN_PAYLOADS_LOG4J[@]}")
fi

for p in "${PLUGINS[@]}"; do
  echo "[*] install -> $p"
  "${CURL_BASE[@]}" -X PUT \
    -H "Content-Type: application/json" \
    -H "Authentication-Token: $TOKEN" \
    -H "X-CSRF-Token: $CSRF" \
    -H "Referer: https://monkey.com:5000/marketplace" \
    -d "$p" \
    "https://${MONKEY_HOST}/api/install-agent-plugin" | jq . || true
  sleep 1
done

# ===== upload agent configuration =====
if [[ -f "$MONKEY_CONF" ]]; then
  echo "[*] uploading agent configuration $MONKEY_CONF ..."
  "${CURL_BASE[@]}" -X PUT \
    -H "Content-Type: application/json" \
    -H "Authentication-Token: $TOKEN" \
    -H "X-CSRF-Token: $CSRF" \
    -H "Referer: https://monkey.com:5000/configure" \
    --data-binary @"$MONKEY_CONF" \
    "https://${MONKEY_HOST}/api/agent-configuration" | jq . || true
else
  echo "[ ] monkey.conf not found at $MONKEY_CONF - skipping"
fi

# ===== upload credentials (only for SSH scenario) =====
if [[ -n "${CREDENTIALS_JSON:-}" && -f "$CREDENTIALS_JSON" ]]; then
  echo "[*] uploading credentials..."
  "${CURL_BASE[@]}" -X PUT \
    -H "Content-Type: application/json" \
    -H "Authentication-Token: $TOKEN" \
    -H "X-CSRF-Token: $CSRF" \
    -H "Referer: https://monkey.com:5000/configure" \
    --data-binary @"$CREDENTIALS_JSON" \
    "https://${MONKEY_HOST}/api/propagation-credentials/configured-credentials" | jq . || true
else
  echo "[ ] credentials upload skipped (not required or missing)"
fi

sleep 1

# ===== request OTP =====
echo "[*] requesting agent OTP..."
"${CURL_BASE[@]}" -H "Content-Type: application/json" \
  -H "Authentication-Token: $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Referer: https://monkey.com:5000/run-monkey" \
  "https://${MONKEY_HOST}/api/agent-otp" -o "$TMP_OTP" || true

MONKEY_OTP=$(jq -r '.otp // empty' "$TMP_OTP" 2>/dev/null || true)
if [[ -n "$MONKEY_OTP" ]]; then
  echo "[OK] OTP obtained (len=$(echo -n "$MONKEY_OTP" | wc -c))"
else
  echo "[ ] No OTP in response; please get it from $TMP_OTP manually if needed."
fi

# ===== find r5 container and start tcpdump =====
R5_CTR_ID=$(docker ps -qf "name=$R5_CONTAINER_FILTER" | head -n1 || true)
if [[ -z "$R5_CTR_ID" ]]; then
  echo "[!] Could not find r5 container (filter='$R5_CONTAINER_FILTER'). Skipping tcpdump."
else
  echo "[OK] r5 container: $R5_CTR_ID"
  echo "[*] Starting tcpdump inside r5..."
  docker exec -d "$R5_CTR_ID" /bin/sh -c "nohup tcpdump -i any -s 0 -w /home/snorty/s1-data.pcap 2>/dev/null &"
  echo "[OK] tcpdump started in background."
fi

# ===== find kali container =====
CTR_ID=$(docker ps -qf "name=$KALI_CONTAINER_FILTER" | head -n1 || true)
if [[ -z "$CTR_ID" ]]; then
  echo "[!] Could not find Kali container (filter='$KALI_CONTAINER_FILTER'). Skipping agent download/start."
  exit 0
fi
echo "[OK] Kali container: $CTR_ID"

# ===== download agent inside kali container and launch =====
echo "[*] downloading agent inside Kali and launching..."
if [[ -n "$MONKEY_OTP" ]]; then
  docker exec -d "$CTR_ID" /bin/sh -c \
    "curl -k -sS https://192.168.0.11:5000/api/agent-binaries/linux -o /root/monkey-linux-64 && \
     chmod +x /root/monkey-linux-64 && \
     MONKEY_OTP='$MONKEY_OTP' /root/monkey-linux-64 m0nk3y -s 192.168.0.11:5000"
else
  docker exec -d "$CTR_ID" /bin/sh -c \
    "curl -k -sS https://192.168.0.11:5000/api/agent-binaries/linux -o /root/monkey-linux-64 && \
     chmod +x /root/monkey-linux-64 && \
     /root/monkey-linux-64 m0nk3y -s 192.168.0.11:5000"
fi
echo "[OK] Infection Monkey agent launched."

# ===== Impostazioni per il polling con timeout e stop tcpdump =====
POLLING_INTERVAL=5        # Tempo tra una verifica e l'altra (secondi)
TIMEOUT_THRESHOLD=10      # Tempo in cui gli eventi non devono cambiare per considerare la fine (secondi)


if [[ -n "$R5_CTR_ID" ]]; then
  echo "[*] Polling Infection Monkey API for agent activity completion (timeout if no new events for ${TIMEOUT_THRESHOLD}s)..."
  
  LAST_EVENT_COUNT=0
  STABLE_COUNT_CYCLES=0
  
  while true; do
    sleep "$POLLING_INTERVAL"
    
    # Ottieni il numero totale di eventi
    CURRENT_EVENT_COUNT=$("${CURL_BASE[@]}" \
      -H "Content-Type: application/json" \
      -H "Authentication-Token: $TOKEN" \
      -H "X-CSRF-Token: $CSRF" \
      -H "Referer: https://monkey.com/infection/events" \
      "https://${MONKEY_HOST}/api/agent-events" | jq '. | length // 0') # Usiamo . | length per contare gli elementi dell'array

    if [[ "$CURRENT_EVENT_COUNT" -gt "$LAST_EVENT_COUNT" ]]; then
      # Gli eventi sono cambiati (aumentati), resetta il contatore di stabilità
      STABLE_COUNT_CYCLES=0
      LAST_EVENT_COUNT=$CURRENT_EVENT_COUNT
    elif [[ "$CURRENT_EVENT_COUNT" -eq "$LAST_EVENT_COUNT" ]]; then
      # Gli eventi non sono cambiati
      STABLE_COUNT_CYCLES=$((STABLE_COUNT_CYCLES + 1))
    fi

    # Controlla se abbiamo raggiunto il numero di cicli di stabilità necessari per il timeout
    if [[ "$STABLE_COUNT_CYCLES" -ge $((TIMEOUT_THRESHOLD / POLLING_INTERVAL)) ]]; then
      echo "[OK] No new events detected for ${TIMEOUT_THRESHOLD} seconds. Assuming Infection Monkey activity completed."
      break # Esci dal loop
    fi
  done

  # Trova PID di tcpdump e termina
  TCPDUMP_PID=$(docker exec "$R5_CTR_ID" ps aux | grep '[t]cpdump -i any' | grep -v 'sh -c' | awk '{print $2}' || true)
  if [[ -n "$TCPDUMP_PID" ]]; then
    docker exec "$R5_CTR_ID" kill "$TCPDUMP_PID"
    sleep 2
    echo "[OK] tcpdump stopped."
  else
    echo "[!] Could not find running tcpdump process in r5 container."
  fi

  docker cp "$R5_CTR_ID":/home/snorty/s1-data.pcap "$PCAP_SAVE_DIR/s1-data.pcap"
  echo "[OK] pcap file saved to $PCAP_SAVE_DIR/s1-data.pcap"
else
  echo "[ ] tcpdump was not started, skipping polling and pcap saving."
fi

# ===== Save all agent events after attack termination =====
echo "[*] Saving all monkey events..."
"${CURL_BASE[@]}" \
  -H "Content-Type: application/json" \
  -H "Authentication-Token: $TOKEN" \
  -H "X-CSRF-Token: $CSRF" \
  -H "Referer: https://monkey.com/infection/events" \
  "https://${MONKEY_HOST}/api/agent-events" | jq . > "$EVENTS_SAVE_DIR/events.json"

echo "[*] Saving all the agents and machines involved in the simulation..."
"${CURL_BASE[@]}" \
  -H "Content-type: application/json" \
  -H "Authentication-Token: $TOKEN" \
  "https://${MONKEY_HOST}/api/machines" -o "$EVENTS_SAVE_DIR/machines.json"

"${CURL_BASE[@]}" \
  -H "Content-type: application/json" \
  -H "Authentication-Token: $TOKEN" \
  "https://${MONKEY_HOST}/api/agents" -o "$EVENTS_SAVE_DIR/agents.json"


echo "[OK] monkey events saved to $EVENTS_SAVE_DIR/events.json"

echo "[DONE] full flow completed. Check UI, container logs, and saved files to confirm."

#!/usr/bin/env bash
set -euo pipefail

# ============
# Config base
# ============
PROJECT_ROOT="/home/void/Uni/Tirocinio/KathaRange/lab_light"
DATASET_ROOT="$PROJECT_ROOT/shared/dataset"
DOCKER_IMAGE_ZEEK="zeek/zeek:latest"

# Path allo script che crea la struttura delle cartelle (delega)
CREATE_SCRIPT="${CREATE_SCRIPT:-$PROJECT_ROOT/shared/scripts/create_dataset_dirs.sh}"

# tshark deve stare sull'host
TSHARK_BIN="${TSHARK_BIN:-tshark}"

# Colori
BLUE="\033[34m"; YELLOW="\033[33m"; RED="\033[31m"; RESET="\033[0m"

# ==========================
# Usage
# ==========================
usage() {
  cat <<EOF
Uso:
  $(basename "$0") PATH/AL/FILE.pcap

Note:
  - Lo script deduce lo scenario dal nome del file:
      s1_*  -> scenario1_SSH_ransomware
      s2_*  -> scenario2_LOG4J_ransomware
  - Output:
      dataset/<scenario>/{pcap,traffic/packet,traffic/flow/zeek-logs}
  - La creazione delle directory viene delegata a:
      $CREATE_SCRIPT
EOF
}

# ==========================
# Helpers
# ==========================
log()   { printf "${BLUE}[INFO]${RESET} %s\n" "$*"; }
warn()  { printf "${YELLOW}[WARN]${RESET} %s\n" "$*" >&2; }
die()   { printf "${RED}[ERR]${RESET} %s\n" "$*" >&2; exit 1; }
require_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Comando richiesto non trovato: $1"
}

# ==========================
# Parse args
# ==========================
PCAP_PATH=""

for arg in "$@"; do
  case "$arg" in
    -h|--help) usage; exit 0 ;;
    *)
      if [[ -z "$PCAP_PATH" ]]; then
        PCAP_PATH="$arg"
      else
        die "Argomento sconosciuto: $arg"
      fi
      ;;
  esac
done

[[ -n "$PCAP_PATH" ]] || { usage; exit 1; }
[[ -f "$PCAP_PATH" ]] || die "PCAP inesistente: $PCAP_PATH"

PCAP_BASENAME="$(basename -- "$PCAP_PATH")"

# ==========================
# Scenario detection
# ==========================
detect_scenario() {
  local name="$1"
  shopt -s nocasematch
  if [[ "$name" =~ ^s1[_-] ]]; then
    echo "scenario1_SSH_ransomware"
  elif [[ "$name" =~ ^s2[_-] ]]; then
    echo "scenario2_LOG4J_ransomware"
  else
    local stem="${name%.*}"
    echo "scenario_custom_${stem}"
  fi
  shopt -u nocasematch

}

SCENARIO_DIR="$(detect_scenario "$PCAP_BASENAME")"
log "Scenario rilevato: $SCENARIO_DIR"

# ==========================
# Paths di output (non creo più le cartelle qui)
# ==========================
SCENARIO_ROOT="$DATASET_ROOT/$SCENARIO_DIR"
PCAP_DIR="$SCENARIO_ROOT/pcap"
PKT_DIR="$SCENARIO_ROOT/traffic/packet"
FLOW_DIR="$SCENARIO_ROOT/traffic/flow"
ZEEK_LOGS_DIR="$FLOW_DIR/zeek-logs"

# ============================
# Creazione struttura dataset
# ============================
if [[ ! -x "$CREATE_SCRIPT" ]]; then
  die "Script per creare la struttura delle directory non trovato o non eseguibile: $CREATE_SCRIPT
Crea il file e rendilo eseguibile (es. chmod +x $CREATE_SCRIPT)."
fi

log "Creo la struttura delle directory (delegato a $CREATE_SCRIPT)"
# Passo DATASET_ROOT così lo script crea root/dataset/...
"$CREATE_SCRIPT" "$DATASET_ROOT"

# ==========================
# Copia il pcap dentro la cartella scenario/pcap
# ==========================
TARGET_PCAP="$PCAP_DIR/$PCAP_BASENAME"
if [[ ! -f "$TARGET_PCAP" ]]; then
  log "Copio il PCAP in $TARGET_PCAP"
  cp -f "$PCAP_PATH" "$TARGET_PCAP"
else
  log "PCAP già presente in $TARGET_PCAP"
fi

PKT_CSV="$PKT_DIR/packet-level.csv"

# ==========================
# Check dipendenze
# ==========================
require_cmd docker
require_cmd "$TSHARK_BIN"

# ==========================
# Step 1: Tshark → packet-level CSV
# ==========================
run_tshark() {
  log "Estraggo packet-level CSV con tshark → $PKT_CSV"

  # TCP (header incluso)
  "$TSHARK_BIN" -r "$TARGET_PCAP" -T fields \
    -e frame.time_epoch -e ip.src -e ip.dst \
    -e tcp.srcport -e tcp.dstport -e tcp.flags \
    -e ip.proto -e frame.len -E header=y -E separator=, > "$PKT_CSV" \
    || warn "tshark TCP extraction ha restituito codice non-zero, continuo comunque"

  log "Creato: $PKT_CSV"
}

run_tshark

# ==========================
# Step 2: Zeek (via Docker)
#   - Log in ZEEK_LOGS_DIR
# ==========================
run_zeek() {
  log "Eseguo Zeek sul PCAP (log in zeek-logs/)"
  docker run --rm \
    -v "$PCAP_DIR":/pcap \
    -v "$ZEEK_LOGS_DIR":/zeek-logs \
    -w /zeek-logs \
    "$DOCKER_IMAGE_ZEEK" \
    zeek -C -r "/pcap/$PCAP_BASENAME"
  local rc=$?
  (( rc == 0 )) || die "Errore durante l'esecuzione di Zeek (rc=$rc)"
}
run_zeek

# ==========================
# Step 2.1: Zeek conn.log (TSV) -> CSV
# ==========================
zeek_conn_to_csv() {
  local IN="$ZEEK_LOGS_DIR/conn.log"
  local OUT="$FLOW_DIR/flow_level.csv"

  if [[ ! -f "$IN" ]]; then
    warn "Manca $IN, salto conversione."
    return 0
  fi

  log "Converto Zeek conn.log -> $OUT (selezione dei campi con zeek-cut)"
  
  local IN_BN OUT_BN
  IN_BN="$(basename "$IN")"
  OUT_BN="$(basename "$OUT")"

  docker run --rm \
    -v "$ZEEK_LOGS_DIR":/logs \
    -v "$FLOW_DIR":/out \
    -w /logs \
    "$DOCKER_IMAGE_ZEEK" \
    sh -c "awk -v FS='\\t' -v OFS=',' '\
      function F(name,   k){ k = idx[name]; return (k && k<=NF) ? \$k : \"\" }\
      BEGIN { print \"ts,id.orig_h,id.orig_p,id.resp_h,id.resp_p,proto,duration,orig_bytes,resp_bytes\" }\
      \$1 == \"#fields\" { for (i=2; i<=NF; i++) idx[\$i] = i-1; next }\
      \$1 ~ /^#/ { next }\
      { print F(\"ts\"), F(\"id.orig_h\"), F(\"id.orig_p\"), F(\"id.resp_h\"), F(\"id.resp_p\"), F(\"proto\"), F(\"duration\"), F(\"orig_bytes\"), F(\"resp_bytes\") }' /logs/$IN_BN > /out/$OUT_BN"
  local rc=$?
  (( rc == 0 )) || die "Errore durante la conversione Zeek conn.log (rc=$rc)"
  log "Creato: $OUT"
}

zeek_conn_to_csv



log "=== FATTO ==="
log "PCAP:              $TARGET_PCAP"
log "Flow-level CSV:    $FLOW_DIR/flow-level.csv"
log "Packet-level CSV:  $PKT_CSV"


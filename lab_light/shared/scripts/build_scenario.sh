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
  $(basename "$0") <path/al/file.pcap> <scenario_number>

Argomenti:
  <path/al/file.pcap>    : Il percorso completo del file PCAP da processare.
  <scenario_number>      : Il numero dello scenario (1 o 2).
                           1 -> scenario1_SSH_ransomware
                           2 -> scenario2_LOG4J_ransomware

Note:
  - Output:
      dataset/<scenario>/{pcap,traffic/packet,traffic/flow/zeek-logs}
  - La creazione delle directory viene delegata a:
      $CREATE_SCRIPT
EOF
  exit 1
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
SCENARIO_NUM=""

if [[ "$#" -ne 2 ]]; then
  usage
fi

PCAP_PATH="$1"
SCENARIO_NUM="$2"

# Validazione PCAP
[[ -f "$PCAP_PATH" ]] || die "PCAP inesistente: $PCAP_PATH"
PCAP_BASENAME="$(basename -- "$PCAP_PATH")"

# Validazione scenario number
if [[ "$SCENARIO_NUM" != "1" && "$SCENARIO_NUM" != "2" ]]; then
  die "Numero di scenario non valido: $SCENARIO_NUM. Deve essere 1 o 2."
fi

# ==========================
# Scenario detection (non più dal nome del file, ma dall'argomento)
# ==========================
SCENARIO_NAME=""
if [[ "$SCENARIO_NUM" == "1" ]]; then
  SCENARIO_NAME="scenario1_SSH_ransomware"
elif [[ "$SCENARIO_NUM" == "2" ]]; then
  SCENARIO_NAME="scenario2_LOG4J_ransomware"
fi

log "Scenario selezionato: $SCENARIO_NAME (numero $SCENARIO_NUM)"

# ==========================
# Paths di output
# ==========================
SCENARIO_ROOT="$DATASET_ROOT/$SCENARIO_NAME"
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

log "Creo la struttura delle directory per lo scenario '$SCENARIO_NAME' (delegato a $CREATE_SCRIPT)"
"$CREATE_SCRIPT" "$SCENARIO_NUM"

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

  # Assicurati che la directory di destinazione esista
  mkdir -p "$PKT_DIR"
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
  # Assicurati che la directory di destinazione esista
  mkdir -p "$ZEEK_LOGS_DIR"
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

  # Assicurati che la directory di destinazione esista
  mkdir -p "$FLOW_DIR"

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
log "Flow-level CSV:    $FLOW_DIR/flow_level.csv"
log "Packet-level CSV:  $PKT_CSV"

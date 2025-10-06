#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./create_dataset_dirs.sh 1              # crea ./dataset/scenario1_SSH_ransomware/...
#   ./create_dataset_dirs.sh 2              # crea ./dataset/scenario2_LOG4J_ransomware/...
#   ./create_dataset_dirs.sh                # default a scenario1 se nessun argomento valido

info(){ printf "\033[34m[INFO]\033[0m %s\n" "$*"; }
error(){ printf "\033[31m[ERROR]\033[0m %s\n" "$*" >&2; }

# Funzione per mostrare l'uso corretto e uscire
usage() {
  error "Uso: $0 [1|2]"
  error "  1: Crea directory per scenario1_SSH_ransomware"
  error "  2: Crea directory per scenario2_LOG4J_ransomware"
  exit 1
}

# --- Gestione dell'input ---
SCENARIO_NUM=""
if [[ "$#" -ge 1 ]]; then # Controlla se è stato fornito almeno un argomento
  if [[ "$1" == "1" || "$1" == "2" ]]; then
    SCENARIO_NUM="$1"
  else
    error "Argomento non valido: '$1'. Deve essere 1 o 2."
    usage
  fi
fi

# --- Definizione di ROOT in base allo scenario selezionato ---
BASE_DIR="./dataset"
SCENARIO_NAME=""

if [[ "$SCENARIO_NUM" == "1" ]]; then
  SCENARIO_NAME="scenario1_SSH_ransomware"
elif [[ "$SCENARIO_NUM" == "2" ]]; then
  SCENARIO_NAME="scenario2_LOG4J_ransomware"
fi

ROOT="$BASE_DIR/$SCENARIO_NAME"

# --- Funzione make_tree_for (semplificata per questo caso) ---
make_tree_for() {
  local base_path="$1" # Ora make_tree_for riceve direttamente il percorso base

  info "Creazione struttura: $base_path"

  mkdir -p "$base_path/monkey_events"
  mkdir -p "$base_path/pcap"
  mkdir -p "$base_path/traffic/flow/zeek-logs"
  mkdir -p "$base_path/traffic/packet"

  info "OK: $base_path"
}

# Esecuzione per lo scenario selezionato
make_tree_for "$ROOT"

info "Tutte le directory create sotto: $ROOT"

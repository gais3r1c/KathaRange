#!/usr/bin/env bash
set -euo pipefail

# Usage:
#   ./create_dataset_dirs.sh              # crea ./dataset/...
#   ./create_dataset_dirs.sh /path/root   # crea /path/root/dataset/...

ROOT="${1:-./dataset}"

info(){ printf "\033[34m[INFO]\033[0m %s\n" "$*"; }

make_tree_for() {
  local scen="$1"
  local base="$ROOT/$scen"

  info "Creazione struttura: $base"

  mkdir -p "$base/monkey_events"
  mkdir -p "$base/pcap"
  mkdir -p "$base/traffic/flow/zeek-logs"
  mkdir -p "$base/traffic/packet"
  mkdir -p "$base/wazuh"

  info "OK: $scen"
}

make_tree_for "scenario1_SSH_ransomware"
make_tree_for "scenario2_LOG4J_ransomware"

info "Tutte le directory create sotto: $ROOT"

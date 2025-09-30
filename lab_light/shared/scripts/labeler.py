import pandas as pd
import argparse
import logging
from datetime import datetime, timedelta

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')


def load_data(events_path, flows_path):
    return pd.read_csv(events_path), pd.read_csv(flows_path)

def preprocess_events(events_df, ip_mapping):
    logging.info('Pre-elaborazione df degli eventi..')

    # Normalizza nomi host a IP, sara' piu' comodo

def main():
    parser = argparse.ArgumentParser(description="Script per etichettare i flussi Zeek con gli eventi di Infection Monkey.")
    parser.add_argument('--events', type=str, required=True, help="Percorso al file CSV degli eventi di Infection Monkey.")
    parser.add_argument('--flows', type=str, required=True, help="Percorso al file CSV dei flussi di Zeek.")
    parser.add_argument('--output', type=str, default='labeled_flows.csv', help="Nome del file CSV di output per i flussi etichettati.")
    parser.add_argument('--time_window', type=int, default=5, help="Finestra temporale (in secondi) per il matching degli eventi ai flussi.")
    args = parser.parse_args()

    ip_mapping = {
        'kali':          '192.168.0.10',
        'apache2_1':     '192.168.3.10',
        'apache2_2':     '192.168.2.10',
        'tomcat2_2':     '192.168.2.20',
        'log4shell':     '192.168.3.20',
        'monkey_island': '192.168.0.11'
    }

    offset_time_sec = 2

    # CSV in DataFrame
    events_df, flow_df = load_data(args.events, args.flows)

    # Pre-elaborazione eventi IM

    # Pre-elaborazione flow-zeek

    # Labeling

    # Salvataggio





if __name__ == '__main__':
    main()


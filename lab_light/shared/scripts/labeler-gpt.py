import pandas as pd
import numpy as np
import logging
import argparse
from datetime import datetime, timedelta
import os

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(levelname)s - %(message)s')

def load_data(events_path, flows_path):
    """
    Carica i file CSV di Infection Monkey events e Zeek flows.
    """
    logging.info(f"Caricamento events da: {events_path}")
    events_df = pd.read_csv(events_path)
    logging.info(f"Caricamento flows da: {flows_path}")
    flows_df = pd.read_csv(flows_path)
    return events_df, flows_df

def preprocess_events(events_df, ip_map):
    """
    Pre-elabora il DataFrame degli eventi di Infection Monkey.
    """
    logging.info("Pre-elaborazione del DataFrame degli eventi...")

    # 1. Conversione del tempo
    events_df['Time'] = pd.to_datetime(events_df['Time'])
    
    # 2. Normalizzazione degli host (da nomi a IP)
    events_df['Source'] = events_df['Source'].replace(ip_map)
    events_df['Target'] = events_df['Target'].replace(ip_map)

    # Gestione di "Local system": sostituiamo con l'IP del Source quando Target è "Local system"
    # "Local system" rappresenta il sistema locale della macchina Source
    local_system_mask = events_df['Target'] == 'Local system'
    events_df.loc[local_system_mask, 'Target'] = events_df.loc[local_system_mask, 'Source']
    
    # Se Source è "Local system", impostiamo a None (caso molto raro)
    events_df.loc[events_df['Source'] == 'Local system', 'Source'] = None


    # 3. Estrazione/inferenza delle porte e preparazione delle etichette
    # Questo è un esempio, dovrai affinarlo in base alle tue esigenze.
    # Creiamo una colonna 'Inferred_Port' e 'Event_Label'
    def infer_port_and_label(row):
        port = None
        label = row['Type'] # Iniziamo con il Type come etichetta
        tags = str(row['Tags']).lower() if pd.notna(row['Tags']) else ''

        if 'ssh-exploiter' in tags:
            port = 22
            label = 'ssh_exploitation'
        elif 'log4shell-exploiter' in tags:
            # Qui dovresti usare le porte dal tuo config di monkey: 8000, 8080, 8983, 9600
            # Per ora mettiamo 8080 come esempio, ma idealmente dovresti avere una lista di porte log4shell
            # Potresti anche voler creare una lista di porte per ogni tipo di exploit.
            port = 8080 # Placeholder, da migliorare
            label = 'log4shell_exploitation'
        elif 'http-fingerprinter' in tags or row['Type'] == 'HTTPRequestEvent':
            port = 80 # Placeholder, potrebbero essere 443, 8008, 8080, 8983
            label = 'http_reconnaissance'
        elif 'ransomware-payload' in tags or row['Type'] == 'FileEncryptionEvent':
            # Ransomware è un'azione interna, non ha una porta di rete remota.
            # Lo etichettiamo ma non useremo la porta per il matching dei flussi esterni.
            port = None
            label = 'ransomware_activity'
        # Aggiungi altre logiche per inferire porte e affinare etichette

        # Se ci sono tags, potresti volerle aggiungere all'etichetta per specificità
        if tags and tags != 'nan':
             label = f"{label}_{tags.replace(' ', '_').replace(',', '-')}"

        return pd.Series([port, label])

    events_df[['Inferred_Port', 'Event_Label']] = events_df.apply(infer_port_and_label, axis=1)

    logging.info("Pre-elaborazione eventi completata.")
    return events_df

def preprocess_flows(flows_df, time_offset_seconds):
    """
    Pre-elabora il DataFrame dei flussi di Zeek.
    """
    logging.info("Pre-elaborazione del DataFrame dei flussi...")

    # 1. Normalizzazione del tempo (timestamp Unix a datetime, poi aggiunta offset)
    flows_df['ts_datetime'] = pd.to_datetime(flows_df['ts'], unit='s')
    flows_df['ts_datetime_norm'] = flows_df['ts_datetime'] + timedelta(seconds=time_offset_seconds)

    # Arrotondamento dei timestamp per facilitare il matching
    # Arrotondiamo al secondo più vicino
    flows_df['ts_datetime_norm_rounded'] = flows_df['ts_datetime_norm'].dt.round('S')

    # 2. Rinominare colonne per chiarezza
    flows_df.rename(columns={
        'id.orig_h': 'src_ip',
        'id.orig_p': 'src_port',
        'id.resp_h': 'dst_ip',
        'id.resp_p': 'dst_port'
    }, inplace=True)

    # 3. Inizializzazione delle etichette
    flows_df['Label'] = 'benign' # Etichetta predefinita
    flows_df['Event_IDs'] = '' # Per tenere traccia degli ID degli eventi che hanno etichettato il flusso

    logging.info("Pre-elaborazione flussi completata.")
    return flows_df

def calculate_time_offset(events_df, flows_df):
    """
    Calcola l'offset temporale tra i due dataset.
    Si assume che il primo evento di monkey e il primo flusso di zeek
    siano rappresentativi dell'inizio della simulazione.
    """
    min_event_time = events_df['Time'].min()
    min_flow_time = flows_df['ts_datetime'].min()

    # Calcola la differenza in secondi
    offset = (min_event_time - min_flow_time).total_seconds()
    logging.info(f"Offset temporale calcolato: {offset:.2f} secondi.")
    return offset

def label_flows(events_df, flows_df, time_window_seconds=5):
    """
    Esegue il matching e il labeling dei flussi.
    """
    logging.info("Inizio del processo di labeling dei flussi...")
    labeled_flows_df = flows_df.copy() # Lavoriamo su una copia

    # Itera sugli eventi di Infection Monkey
    for index, event in events_df.iterrows():
        event_time = event['Time']
        event_src_ip = event['Source']
        event_dst_ip = event['Target']
        event_port = event['Inferred_Port']
        event_label = event['Event_Label']

        if pd.isna(event_src_ip) or pd.isna(event_dst_ip):
            logging.debug(f"Evento {index} con IP non validi (Source: {event_src_ip}, Target_IP: {event_dst_ip}), saltato per matching.")
            continue # Salta eventi senza IP validi per matching di rete

        # Definizione della finestra temporale
        time_start = event_time - timedelta(seconds=time_window_seconds)
        time_end = event_time + timedelta(seconds=time_window_seconds)

        # Filtra i flussi nell'intervallo temporale
        potential_matches_idx = labeled_flows_df[
            (labeled_flows_df['ts_datetime_norm'] >= time_start) &
            (labeled_flows_df['ts_datetime_norm'] <= time_end)
        ].index

        if potential_matches_idx.empty:
            logging.debug(f"Nessun flusso potenziale per l'evento {index} ({event_label}) in finestra temporale.")
            continue

        # Ulteriore filtro per IP e porta (gestione bidirezionale)
        matched_flow_indices = []
        for flow_idx in potential_matches_idx:
            flow = labeled_flows_df.loc[flow_idx]
            match_found = False

            # Match IP (Source/Target vs src_ip/dst_ip del flow)
            # Scenario 1: Source -> Target
            if (str(event_src_ip) == str(flow['src_ip']) and str(event_dst_ip) == str(flow['dst_ip'])):
                match_found = True
            # Scenario 2: Target -> Source (flusso inverso)
            elif (str(event_src_ip) == str(flow['dst_ip']) and str(event_dst_ip) == str(flow['src_ip'])):
                 match_found = True

            # Se abbiamo un match IP e una porta inferita, controlliamo anche la porta
            if match_found and pd.notna(event_port):
                # Controlla se la porta inferita è la porta di destinazione o di origine del flusso
                if event_port == flow['dst_port'] or event_port == flow['src_port']:
                    matched_flow_indices.append(flow_idx)
                else:
                    match_found = False # Reset se la porta non corrisponde
            elif match_found and pd.isna(event_port):
                # Se non c'è una porta specifica nell'evento, l'IP match è sufficiente
                matched_flow_indices.append(flow_idx)


        # Applica l'etichetta ai flussi corrispondenti
        if matched_flow_indices:
            logging.debug(f"Trovati {len(matched_flow_indices)} flussi per l'evento {index} ({event_label})")
            # Un flusso può essere etichettato da più eventi.
            # Potresti voler appendere le etichette o mantenere solo l'ultima/più specifica.
            # Qui semplicemente sovrascriviamo, ma si potrebbe gestire come lista.
            for idx in matched_flow_indices:
                current_labels = labeled_flows_df.at[idx, 'Label']
                current_event_ids = labeled_flows_df.at[idx, 'Event_IDs']

                if event_label not in current_labels:
                    labeled_flows_df.at[idx, 'Label'] = event_label # O concatena le etichette
                labeled_flows_df.at[idx, 'Event_IDs'] = (current_event_ids + f',{index}').strip(',')


    logging.info("Processo di labeling completato.")
    return labeled_flows_df

def load_wazuh_events(wazuh_csv_path):
    """
    Carica gli eventi di Wazuh dal CSV esportato.
    """
    if not wazuh_csv_path or not os.path.exists(wazuh_csv_path):
        logging.info("File Wazuh non trovato, continuando senza eventi Wazuh")
        return pd.DataFrame()
    
    logging.info(f"Caricamento eventi Wazuh da: {wazuh_csv_path}")
    wazuh_df = pd.read_csv(wazuh_csv_path)
    
    logging.info(f"Caricati {len(wazuh_df)} eventi Wazuh")
    return wazuh_df

def preprocess_wazuh_events(wazuh_df, ip_map):
    """
    Pre-elabora gli eventi di Wazuh per renderli compatibili con il formato Monkey.
    """
    if wazuh_df.empty:
        return pd.DataFrame()
    
    logging.info("Pre-elaborazione eventi Wazuh...")
    
    # Crea DataFrame nel formato compatibile con Monkey
    processed_events = []
    
    for index, event in wazuh_df.iterrows():
        # Converti timestamp Wazuh a datetime
        # Format: "Sep 16, 2025 @ 18:27:29.832"
        timestamp_str = event['timestamp'].replace('@', '').strip()
        try:
            # Parsing del timestamp Wazuh
            event_time = pd.to_datetime(timestamp_str, format='%b %d, %Y %H:%M:%S.%f')
        except:
            try:
                event_time = pd.to_datetime(timestamp_str)
            except:
                logging.warning(f"Impossibile parsare timestamp: {timestamp_str}")
                continue
        
        # Mappa nome agent a IP
        agent_name = event['agent.name']
        source_ip = ip_map.get(agent_name, agent_name)
        
        # Determina il tipo di evento basato su path e azione
        event_type = determine_wazuh_event_type(event)
        
        # Genera tags basati sul contenuto
        tags = generate_wazuh_tags(event)
        
        processed_event = {
            'Time': event_time,
            'Source': agent_name,  # Nome originale
            'Target': 'Local system',  # Eventi Wazuh sono sempre locali
            'Type': event_type,
            'Tags': tags,
            'Fields': f"path:{event['syscheck.path']}, action:{event['syscheck.event']}, rule_id:{event['rule.id']}",
            'Event_Source': 'Wazuh',
            'Wazuh_Rule_ID': event['rule.id'],
            'Wazuh_Rule_Level': event['rule.level'],
            'Wazuh_Description': event['rule.description'],
            'Wazuh_Path': event['syscheck.path'],
            'Wazuh_Event': event['syscheck.event']
        }
        
        processed_events.append(processed_event)
    
    if not processed_events:
        return pd.DataFrame()
    
    result_df = pd.DataFrame(processed_events)
    
    # Applica la mappatura IP come negli eventi Monkey
    result_df['Source'] = result_df['Source'].replace(ip_map)
    result_df['Target'] = result_df['Target'].replace(ip_map)
    
    # Gestione "Local system" come negli eventi Monkey
    local_system_mask = result_df['Target'] == 'Local system'
    result_df.loc[local_system_mask, 'Target'] = result_df.loc[local_system_mask, 'Source']
    
    logging.info(f"Pre-elaborati {len(result_df)} eventi Wazuh")
    return result_df

def determine_wazuh_event_type(event):
    """
    Determina il tipo di evento basato sui dati Wazuh.
    """
    path = event['syscheck.path'].lower()
    action = event['syscheck.event'].lower()
    
    # Pattern per file di ransomware
    ransomware_extensions = ['.m0nk3y', '.encrypted', '.locked', '.crypto', '.ransom']
    ransomware_files = ['readme.txt', 'ransom_note', 'decrypt_instruction']
    
    if any(ext in path for ext in ransomware_extensions):
        if action == 'added':
            return 'FileEncryptionEvent'
        elif action == 'deleted':
            return 'FilePreEncryptionEvent'  # File originale eliminato prima della crittografia
    
    if any(filename in path for filename in ransomware_files):
        return 'RansomNoteEvent'
    
    if action == 'added':
        return 'FileCreationEvent'
    elif action == 'modified':
        return 'FileModificationEvent'
    elif action == 'deleted':
        return 'FileDeletionEvent'
    
    return 'UnknownFileEvent'

def generate_wazuh_tags(event):
    """
    Genera tag appropriati per gli eventi Wazuh.
    """
    path = event['syscheck.path'].lower()
    action = event['syscheck.event'].lower()
    tags = []
    
    # Tag basati su estensioni sospette
    if '.m0nk3y' in path or '.encrypted' in path or '.locked' in path:
        tags.extend(['ransomware-payload', 'attack-t1486'])
    
    # Tag basati su file README di ransomware
    if 'readme.txt' in path and action == 'added':
        tags.extend(['ransomware-note', 'attack-t1486'])
    
    # Tag basati su directory
    if '/tmp/ransom' in path:
        tags.append('ransomware-activity')
    
    # Tag basati su livello di regola Wazuh
    rule_level = int(event['rule.level'])
    if rule_level >= 10:
        tags.append('high-severity')
    elif rule_level >= 7:
        tags.append('medium-severity')
    
    # Tag per azione file
    tags.append(f'file-{action}')
    
    return ', '.join(tags) if tags else ''

def merge_monkey_and_wazuh_events(monkey_events_df, wazuh_events_df):
    """
    Unisce gli eventi di Monkey e Wazuh in un unico DataFrame.
    """
    if wazuh_events_df.empty:
        monkey_events_df['Event_Source'] = 'InfectionMonkey'
        return monkey_events_df
    
    # Aggiungi colonna source per identificare l'origine
    monkey_events_df['Event_Source'] = 'InfectionMonkey'
    # wazuh_events_df ha già Event_Source = 'Wazuh'
    
    # Combina i DataFrame
    combined_df = pd.concat([monkey_events_df, wazuh_events_df], ignore_index=True)
    combined_df = combined_df.sort_values('Time').reset_index(drop=True)
    
    logging.info(f"Eventi combinati: {len(monkey_events_df)} Monkey + {len(wazuh_events_df)} Wazuh = {len(combined_df)} totali")
    
    return combined_df

def create_synthetic_flows_for_local_events(events_df, flows_df):
    """
    Crea flussi sintetici per eventi locali (sia Monkey che Wazuh).
    """
    synthetic_flows = []
    
    # Eventi locali che non generano traffico di rete
    local_event_types = [
        'FileEncryptionEvent', 'OSDiscoveryEvent', 'HostnameDiscoveryEvent', 
        'AgentShutdownEvent', 'FileModificationEvent', 'FileCreationEvent',
        'FileDeletionEvent', 'RansomNoteEvent', 'FilePreEncryptionEvent'
    ]
    
    for index, event in events_df.iterrows():
        if event['Type'] in local_event_types:
            source_ip = event['Source']
            
            if pd.notna(source_ip) and source_ip != 'Local system':
                # Determina porta fittizia basata sul tipo di evento
                port = determine_synthetic_port(event['Type'])
                
                synthetic_flow = {
                    'ts': event['Time'].timestamp(),
                    'id.orig_h': source_ip,
                    'id.orig_p': 0,
                    'id.resp_h': source_ip,  # Flusso interno
                    'id.resp_p': port,
                    'proto': 'local_activity',
                    'duration': 0,
                    'orig_bytes': 0,
                    'resp_bytes': 0,
                    'ts_datetime_norm': event['Time'],
                    'ts_datetime_norm_rounded': event['Time'].round('S'),
                    'Label': f"{event['Type']}_{event.get('Event_Source', 'Unknown')}",
                    'Event_IDs': str(index),
                    'Synthetic': True,
                    'Event_Source': event.get('Event_Source', 'Unknown'),
                    'Event_Type': event['Type'],
                    'Tags': event.get('Tags', ''),
                    'Wazuh_Path': event.get('Wazuh_Path', ''),
                    'Wazuh_Rule_Level': event.get('Wazuh_Rule_Level', '')
                }
                synthetic_flows.append(synthetic_flow)
    
    if synthetic_flows:
        synthetic_df = pd.DataFrame(synthetic_flows)
        combined_flows = pd.concat([flows_df, synthetic_df], ignore_index=True)
        logging.info(f"Creati {len(synthetic_flows)} flussi sintetici per eventi locali")
        return combined_flows.sort_values('ts_datetime_norm')
    
    return flows_df

def determine_synthetic_port(event_type):
    """
    Assegna porte fittizie specifiche per tipo di evento per facilitare l'analisi.
    """
    port_mapping = {
        'FileEncryptionEvent': 65001,
        'FilePreEncryptionEvent': 65002,
        'RansomNoteEvent': 65003,
        'FileCreationEvent': 65004,
        'FileModificationEvent': 65005,
        'FileDeletionEvent': 65006,
        'OSDiscoveryEvent': 65010,
        'HostnameDiscoveryEvent': 65011,
        'AgentShutdownEvent': 65020
    }
    return port_mapping.get(event_type, 65535)

# Modifica la funzione main per includere Wazuh
def main():
    parser = argparse.ArgumentParser(description="Script per etichettare i flussi Zeek con eventi di Infection Monkey e Wazuh.")
    parser.add_argument('--events', type=str, required=True, help="Percorso al file CSV degli eventi di Infection Monkey.")
    parser.add_argument('--flows', type=str, required=True, help="Percorso al file CSV dei flussi di Zeek.")
    parser.add_argument('--wazuh', type=str, help="Percorso al file CSV degli eventi di Wazuh.")
    parser.add_argument('--output', type=str, default='labeled_flows.csv', help="Nome del file CSV di output.")
    parser.add_argument('--time_window', type=int, default=5, help="Finestra temporale per il matching in secondi.")
    parser.add_argument('--offset', type=int, default=0, help="Offset temporale tra eventi e flussi in secondi.")
    
    args = parser.parse_args()
    
    # Mappatura IP (aggiorna con i tuoi IP corretti)
    ip_mapping = {
        'apache2_1': '192.168.3.10',
        'apache2_2': '192.168.2.10',
        'webapp': '192.168.3.20',
        'tomcat2_2': '192.168.2.20',
        'kali': '192.168.0.10',
        'monkey_island': '192.168.0.11',
        # Aggiungi altri nomi host/IP se ce ne sono nei tuoi eventi
    }
    
    # Carica dati
    events_df, flows_df = load_data(args.events, args.flows)
    wazuh_events_df = load_wazuh_events(args.wazuh) if args.wazuh else pd.DataFrame()
    
    # Pre-elabora eventi Monkey
    events_df = preprocess_events(events_df, ip_mapping)
    
    # Pre-elabora eventi Wazuh
    if not wazuh_events_df.empty:
        wazuh_events_df = preprocess_wazuh_events(wazuh_events_df, ip_mapping)
        combined_events_df = merge_monkey_and_wazuh_events(events_df, wazuh_events_df)
    else:
        combined_events_df = events_df
        combined_events_df['Event_Source'] = 'InfectionMonkey'
    
    # Pre-elabora flussi
    flows_df = preprocess_flows(flows_df, args.offset)
    
    # Crea flussi sintetici per eventi locali
    enhanced_flows_df = create_synthetic_flows_for_local_events(combined_events_df, flows_df)
    
    # Esegui labeling (devi completare questa funzione)
    labeled_flows_df = label_flows(combined_events_df, enhanced_flows_df, args.time_window)
    
    # Salva risultato
    labeled_flows_df.to_csv(args.output, index=False)
    
    # Statistiche finali
    logging.info("=== STATISTICHE FINALI ===")
    logging.info(f"Eventi totali processati: {len(combined_events_df)}")
    logging.info(f"- Eventi Monkey: {len(combined_events_df[combined_events_df['Event_Source'] == 'InfectionMonkey'])}")
    logging.info(f"- Eventi Wazuh: {len(combined_events_df[combined_events_df['Event_Source'] == 'Wazuh'])}")
    logging.info(f"Flussi totali: {len(labeled_flows_df)}")
    logging.info(f"- Flussi reali: {len(labeled_flows_df[labeled_flows_df.get('Synthetic', False) == False])}")
    logging.info(f"- Flussi sintetici: {len(labeled_flows_df[labeled_flows_df.get('Synthetic', False) == True])}")
    logging.info(f"File di output: {args.output}")
    
    logging.info("Operazione completata!")

if __name__ == "__main__":
    main()

import pandas as pd
import os

def label_network_flows_simplified(flows_filepath, monkey_events_filepath, output_dir): # Rimosso wazuh_events_filepath
    """
    Etichetta i flussi di rete basandosi sugli eventi di Infection Monkey,
    con una logica semplificata e vettorializzata, senza l'uso diretto di Wazuh per l'etichettatura dei flussi.

    Args:
        flows_filepath (str): Percorso al file CSV contenente i flussi di rete.
        monkey_events_filepath (str): Percorso al file CSV contenente gli eventi di Infection Monkey.
        output_dir (str): Percorso della directory dove salvare il file CSV etichettato.
    """
    print("Caricamento e pre-elaborazione dei dati...")

    # Carica i dati dei flussi
    flows_df = pd.read_csv(flows_filepath)
    flows_df['Label'] = 'benign' # Inizializza tutti i flussi come benigni

    # Converti colonne a tipo numerico, gestendo errori
    flows_df['ts'] = flows_df['ts'].astype(float)
    flows_df['orig_bytes'] = pd.to_numeric(flows_df['orig_bytes'], errors='coerce').fillna(0)
    flows_df['resp_bytes'] = pd.to_numeric(flows_df['resp_bytes'], errors='coerce').fillna(0)
    flows_df['duration'] = pd.to_numeric(flows_df['duration'], errors='coerce').fillna(0)
    flows_df['id.resp_p'] = pd.to_numeric(flows_df['id.resp_p'], errors='coerce')

    # Carica i dati degli eventi di Infection Monkey
    monkey_events_df = pd.read_csv(monkey_events_filepath)
    monkey_events_df['Time'] = monkey_events_df['Time'].astype(float) # Già epoch

    # --- Definizione Finestra Temporale e Priorità ---
    delta_time = 3  # secondi, finestra temporale per la correlazione

    event_priority = {
        'FileEncryptionEvent': 1,
        'ExploitationEvent': 2,
        'PropagationEvent': 3,
        'FingerprintingEvent': 4,
        'TCPScanEvent': 5,
        'PingScanEvent': 6,
        'OSDiscoveryEvent': 7,
        'HostnameDiscoveryEvent': 8,
        'HTTPRequestEvent': 9,
        'AgentShutdownEvent': 10
    }
    
    # Pre-calcola la priorità per gli eventi di Monkey
    monkey_events_df['priority'] = monkey_events_df['Type'].astype(str).map(event_priority)
    # Ordina gli eventi di Monkey per priorità (dal più alto al più basso) e poi per tempo
    monkey_events_df = monkey_events_df.sort_values(by=['priority', 'Time'], ascending=[True, True]).reset_index(drop=True)

    print("Etichettatura basata su eventi Infection Monkey (vettorializzata e con priorità)...")
    # --- Etichettatura Flussi basata su Eventi Infection Monkey (Vettorializzata) ---
    
    for _, event in monkey_events_df.iterrows():
        event_time = event['Time']
        event_source = event['Source']
        event_target = event['Target']
        event_type = event['Type']
        
        # Condizioni di base per la finestra temporale e sorgente
        base_condition = (
            (flows_df['ts'] >= event_time - delta_time) &
            (flows_df['ts'] <= event_time + delta_time) &
            (flows_df['id.orig_h'] == event_source) # L'host che genera l'evento
        )
        
        # Gestione del target specifico per vari tipi di eventi
        is_target_specific = pd.notna(event_target) and str(event_target).strip() != ''

        # --- LOGICA SPECIFICA PER FileEncryptionEvent ---
        if event_type == 'FileEncryptionEvent':
            # Poiché la cifratura è un evento locale e il Target è vuoto,
            # etichettiamo solo i flussi dove l'IP sorgente corrisponde all'host che ha cifrato.
            label_condition = base_condition & (flows_df['Label'] == 'benign')
            flows_df.loc[label_condition, 'Label'] = event_type
            if label_condition.any():
                num_labeled = flows_df.loc[label_condition].shape[0]
                print(f"Debug **MONKEY**: Etichettati {num_labeled} flussi come 'FileEncryptionEvent' per sorgente {event_source} al tempo {event_time}.")
            continue # Passa al prossimo evento Monkey, FileEncryptionEvent è gestito.
        # --- FINE LOGICA SPECIFICA PER FileEncryptionEvent ---

        # Logica per altri eventi Monkey (come prima)
        if event_type in ['PingScanEvent', 'TCPScanEvent', 'ExploitationEvent', 'PropagationEvent', 'HTTPRequestEvent', 'FingerprintingEvent']:
            if is_target_specific:
                base_condition = base_condition & (flows_df['id.resp_h'] == event_target)
        
        # Etichettiamo solo se il flusso è attualmente 'benign'
        label_condition = base_condition & (flows_df['Label'] == 'benign')
        
        if label_condition.any(): # Controlla se ci sono flussi da etichettare
            # Esegui l'etichettatura basata sul tipo di evento Monkey
            if event_type == 'PingScanEvent':
                flows_df.loc[label_condition & (flows_df['proto'] == 'icmp'), 'Label'] = event_type
            
            elif event_type == 'TCPScanEvent':
                flows_df.loc[
                    label_condition &
                    (flows_df['proto'] == 'tcp') &
                    (flows_df['duration'] < 0.1) &
                    (flows_df['orig_bytes'] == 0) & (flows_df['resp_bytes'] == 0),
                    'Label'
                ] = event_type

            elif event_type in ['OSDiscoveryEvent', 'HostnameDiscoveryEvent', 'FingerprintingEvent']:
                # Per questi tipi, il filtro base_condition è stato costruito senza target se non specifico.
                # Qui riconsideriamo il filtro per questi tipi specifici
                discovery_filter = (
                    (flows_df['ts'] >= event_time - delta_time) &
                    (flows_df['ts'] <= event_time + delta_time) &
                    (flows_df['id.orig_h'] == event_source)
                )
                if is_target_specific:
                    discovery_filter = discovery_filter & (flows_df['id.resp_h'] == event_target)

                label_condition_discovery = discovery_filter & (flows_df['Label'] == 'benign')

                if event_type == 'OSDiscoveryEvent':
                    flows_df.loc[
                        label_condition_discovery & 
                        ((flows_df['proto'] == 'icmp') | 
                         ((flows_df['proto'] == 'tcp') & (flows_df['id.resp_p'].isin([135, 445, 3389, 5985, 5986])))),
                        'Label'
                    ] = event_type
                elif event_type == 'HostnameDiscoveryEvent':
                    flows_df.loc[
                        label_condition_discovery & 
                        ((flows_df['proto'] == 'udp') & (flows_df['id.resp_p'].isin([53, 137, 138]))),
                        'Label'
                    ] = event_type
                elif event_type == 'FingerprintingEvent':
                     flows_df.loc[
                        label_condition_discovery & 
                        (flows_df['proto'].isin(['tcp', 'udp', 'icmp'])),
                        'Label'
                    ] = event_type

            elif event_type == 'HTTPRequestEvent':
                flows_df.loc[
                    label_condition &
                    (flows_df['proto'] == 'tcp') &
                    (flows_df['id.resp_p'].isin([80, 443])),
                    'Label'
                ] = event_type

            elif event_type in ['ExploitationEvent', 'PropagationEvent']:
                flows_df.loc[
                    label_condition &
                    (flows_df['proto'].isin(['tcp', 'udp'])) &
                    ((flows_df['orig_bytes'] > 0) | (flows_df['resp_bytes'] > 0)),
                    'Label'
                ] = event_type
            
            elif event_type == 'AgentShutdownEvent':
                flows_df.loc[label_condition, 'Label'] = event_type


    # Costruisci il percorso completo del file di output
    output_filepath = os.path.join(output_dir, 'labeled_flows.csv')
    flows_df.to_csv(output_filepath, index=False)
    print(f"Etichettatura completata. File salvato in: {output_filepath}")
    
    # Aggiungi un controllo finale per le etichette
    print("\n--- Conteggio finale delle etichette ---")
    print(flows_df['Label'].value_counts())
    print("--------------------------------------\n")
    
    return flows_df

# Path scenario1
# flows = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/traffic/flow/flow_level.csv'
# monkey_evs = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/monkey_events/events_monkey.csv'
# output_directory = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware'


# Path scenario2
flows = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario2_LOG4J_ransomware/traffic/flow/flow_level.csv'
monkey_evs = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario2_LOG4J_ransomware/monkey_events/events_monkey.csv'
output_directory = '/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario2_LOG4J_ransomware'

# --- Esecuzione dello script ---
labeled_df = label_network_flows_simplified(flows, monkey_evs, output_directory)

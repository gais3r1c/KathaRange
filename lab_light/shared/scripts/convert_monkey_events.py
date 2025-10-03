import json
import csv
import re

def load_api_data(agents_filepath, machines_filepath):
    """
    Carica i dati dagli endpoint API di Infection Monkey per creare le mappature
    necessarie per ricavare gli IP da machine_id.
    
    Restituisce:
        tuple: (agent_id_to_machine_id, machine_id_to_ip)
    """
    agent_id_to_machine_id = {}
    machine_id_to_ip = {}
    
    # Carica dati agenti (necessario per mappare agent_id a machine_id)
    try:
        with open(agents_filepath, 'r') as f:
            agents_data = json.load(f)
            for agent in agents_data:
                agent_id_to_machine_id[agent['id']] = agent['machine_id']
    except FileNotFoundError:
        print(f"Errore: File agenti non trovato a {agents_filepath}")
        return {}, {}
    except json.JSONDecodeError:
        print(f"Errore: Impossibile decodificare il file JSON agenti a {agents_filepath}")
        return {}, {}

    # Carica dati macchine (necessario per mappare machine_id a IP)
    try:
        with open(machines_filepath, 'r') as f:
            machines_data = json.load(f)
            for machine in machines_data:
                m_id = machine['id']
                # Prende il primo IP valido delle interfacce di rete
                main_ip = None
                for iface in machine.get('network_interfaces', []):
                    # Estrae solo l'IP, ignora la maschera (es. "192.168.0.11/24" -> "192.168.0.11")
                    ip_match = re.match(r'(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})', iface)
                    if ip_match:
                        main_ip = ip_match.group(1)
                        break # Prende il primo IP trovato
                machine_id_to_ip[m_id] = main_ip if main_ip else ""
    except FileNotFoundError:
        print(f"Errore: File macchine non trovato a {machines_filepath}")
        return {}, {}
    except json.JSONDecodeError:
        print(f"Errore: Impossibile decodificare il file JSON macchine a {machines_filepath}")
        return {}, {}

    return agent_id_to_machine_id, machine_id_to_ip

def convert_events_json_to_csv_minimal(
    json_filepath, 
    csv_filepath, 
    agent_id_to_machine_id, 
    machine_id_to_ip
):
    """
    Converte un file JSON di eventi da Infection Monkey in un file CSV minimale,
    con soli i campi richiesti: Time (Epoch), Source IP, Target IP, Type, Tags.
    
    Args:
        json_filepath (str): Percorso del file JSON di input degli eventi.
        csv_filepath (str): Percorso del file CSV di output.
        agent_id_to_machine_id (dict): Mappatura da agent_id a machine_id.
        machine_id_to_ip (dict): Mappatura da machine_id a IP.
    """
    
    events_data = []
    try:
        with open(json_filepath, 'r') as f:
            events_data = json.load(f)
    except FileNotFoundError:
        print(f"Errore: Il file JSON degli eventi non trovato a {json_filepath}")
        return
    except json.JSONDecodeError:
        print(f"Errore: Impossibile decodificare il file JSON degli eventi a {json_filepath}. Assicurati che sia un JSON valido.")
        return

    # Definizione delle colonne del CSV con solo i campi richiesti
    csv_headers = ["Time", "Source", "Target", "Type", "Tags"] 

    with open(csv_filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        writer.writerow(csv_headers) # Scrive l'intestazione
        
        for event in events_data:
            # Time: Solo Epoch (dal JSON)
            epoch_time = event.get('timestamp', '')

            # Source IP
            source_uuid = event.get('source', '')
            source_ip = ""
            if source_uuid:
                source_machine_id = agent_id_to_machine_id.get(source_uuid)
                source_ip = machine_id_to_ip.get(source_machine_id, '') if source_machine_id else ''

            # Target IP
            target = event.get('target', '') if event.get('target') is not None else ""
            target_ip = ""
            
            # Se il target nell'evento è un IP valido
            if re.match(r'\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', target):
                target_ip = target
            # Se il target nell'evento è un UUID (potrebbe essere un altro agente)
            elif target in agent_id_to_machine_id:
                target_machine_id = agent_id_to_machine_id.get(target)
                target_ip = machine_id_to_ip.get(target_machine_id, '') if target_machine_id else ''
            
            # Event Type
            event_type = event.get('type', '')

            # Tags
            tags = ", ".join(event.get('tags', []))
            
            writer.writerow([
                epoch_time, 
                source_ip,
                target_ip,
                event_type, 
                tags
            ])

    print(f"Conversione minimale completata: {json_filepath} -> {csv_filepath}")

# --- Esempio di utilizzo completo ---
agents_api_path = "/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/monkey_events/agents.json" 
machines_api_path = "/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/monkey_events/machines.json"

# Carica i dati API
agent_id_to_machine_id, machine_id_to_ip = load_api_data(agents_api_path, machines_api_path)

# Definisci i percorsi per gli eventi
json_input_path = "/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/monkey_events/events.json"
#json_input_path = "/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/prova.json"
csv_output_path = "/home/void/Uni/Tirocinio/KathaRange/lab_light/shared/dataset/scenario1_SSH_ransomware/monkey_events/events_monkey.csv"

# Converti gli eventi, usando i dati API
convert_events_json_to_csv_minimal(
    json_input_path, 
    csv_output_path, 
    agent_id_to_machine_id, 
    machine_id_to_ip
)

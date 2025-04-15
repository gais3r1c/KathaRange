# -------------------------------------------------------------
# Dockerfile: monkey_island con MongoDB integrato via symlink
# -------------------------------------------------------------
FROM infectionmonkey/monkey-island:latest

USER root

RUN apt-get update && apt-get install -y iproute2 net-tools

# Installiamo wget e gnupg (necessari per aggiungere il repo ufficiale di Mongo)
RUN apt-get update && apt-get install -y wget gnupg

# Scarichiamo la chiave GPG di MongoDB 6.0 e la aggiungiamo al keyring
RUN wget -qO - https://www.mongodb.org/static/pgp/server-6.0.asc | apt-key add -

# Aggiungiamo il repository ufficiale di MongoDB 6.0 per Debian Bullseye
RUN echo "deb [ arch=amd64 ] https://repo.mongodb.org/apt/debian bullseye/mongodb-org/6.0 main" \
    | tee /etc/apt/sources.list.d/mongodb-org-6.0.list

# Installiamo il pacchetto mongodb-org
RUN apt-get update && apt-get install -y mongodb-org

# Creiamo /data/db (cartella dati di Mongo), assegnandola all'utente monkey-island
RUN mkdir -p /data/db && chown -R monkey-island:monkey-island /data/db

# -------------------------------------------
# SYMLINK: dove Infection Monkey cerca mongod
# -------------------------------------------
RUN mkdir -p /monkey/monkey_island/bin/mongodb/bin
RUN ln -s /usr/bin/mongod /monkey/monkey_island/bin/mongodb/bin/mongod

# Copiamo il server_config.json personalizzato (con "start_mongodb": true)
COPY server_config.json /monkey/monkey_island/cc/server_config.json

# Usiamo l’entrypoint ufficiale di Infection Monkey
ENTRYPOINT ["/monkey/entrypoint.sh", "--server-config", "/monkey/monkey_island/cc/server_config.json"]


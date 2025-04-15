FROM ubuntu:22.04

SHELL ["/bin/bash", "-c"]

ARG TZ="UTC"
RUN ln -snf /usr/share/zoneinfo/$TZ /etc/localtime && \
    echo $TZ > /etc/timezone

WORKDIR /usr/src/app

# Aggiungiamo tutto il contenuto (incluso caldera e i suoi plugin)
ADD . .

# Verifica ricorsività del clone (plugin stockpile)
RUN if [ -z "$(ls plugins/stockpile)" ]; then \
    echo "stockpile plugin not downloaded - please ensure you recursively cloned the caldera git repository and try again."; \
    exit 1; \
fi

RUN apt-get update && \
    apt-get -y install python3 python3-pip python3-venv git curl golang-go vim

#WIN_BUILD is used to enable windows build in sandcat plugin
ARG WIN_BUILD=false
RUN if [ "$WIN_BUILD" = "true" ] ; then apt-get -y install mingw-w64; fi

# Set up python virtualenv
ENV VIRTUAL_ENV=/opt/venv/caldera
RUN python3 -m venv $VIRTUAL_ENV
ENV PATH="$VIRTUAL_ENV/bin:$PATH"

# Install pip requirements
RUN pip3 install --no-cache-dir -r requirements.txt

# Set up config file and disable atomic by default
RUN python3 -c "import app; import app.utility.config_generator; app.utility.config_generator.ensure_local_config();"

# Install Go dependencies and build sandcat agents
WORKDIR /usr/src/app/plugins/sandcat/gocat
RUN go mod tidy && go mod download

WORKDIR /usr/src/app/plugins/sandcat
RUN if [ "$WIN_BUILD" = "true" ] ; then cp ./update-agents.sh ./update-agents-copy.sh && tr -d '\15\32' < ./update-agents-copy.sh > ./update-agents.sh && rm ./update-agents-copy.sh; fi
RUN ./update-agents.sh

# Test building gocat extensions
RUN mkdir /tmp/gocatextensionstest
RUN cp -R ./gocat /tmp/gocatextensionstest/gocat && \
    cp -R ./gocat-extensions/* /tmp/gocatextensionstest/gocat/ && \
    cp ./update-agents.sh /tmp/gocatextensionstest/update-agents.sh

WORKDIR /tmp/gocatextensionstest
RUN mkdir /tmp/gocatextensionstest/payloads
RUN ./update-agents.sh

# Clone atomic red team repo for atomic plugin if not present
WORKDIR /usr/src/app
RUN if [ ! -d "plugins/atomic/data/atomic-red-team" ]; then \
    git clone --depth 1 https://github.com/redcanaryco/atomic-red-team.git plugins/atomic/data/atomic-red-team; \
fi

WORKDIR /usr/src/app/plugins/emu
# If emu is enabled, complete necessary installation steps
RUN if [ $(grep -c "\- emu" ../../conf/local.yml) != 0 ]; then \
    apt-get -y install zlib1g unzip && \
    pip3 install -r requirements.txt && \
    ./download_payloads.sh; \
fi

WORKDIR /usr/src/app

# Install a more recent Node.js and npm from NodeSource
RUN apt-get update && apt-get install -y curl
RUN curl -fsSL https://deb.nodesource.com/setup_16.x | bash - && \
    apt-get install -y nodejs iproute2 net-tools

# Verifica la presenza della cartella magma
RUN ls -la plugins/magma

# Installa le dipendenze e builda il front-end separatamente
WORKDIR /usr/src/app/plugins/magma
RUN npm install
RUN npm run build

# Rimuovi nodejs e npm per alleggerire l'immagine
WORKDIR /usr/src/app
RUN apt-get remove -y nodejs && \
    apt-get autoremove -y && \
    apt-get clean && \
    rm -rf /var/lib/apt/lists/* /tmp/* /var/tmp/*

STOPSIGNAL SIGINT

# Default HTTP port for web interface and agent beacons over HTTP
EXPOSE 8888

# Default HTTPS port for web interface and agent beacons over HTTPS (requires SSL plugin to be enabled)
EXPOSE 8443

# TCP and UDP contact ports
EXPOSE 7010
EXPOSE 7011/udp

# Websocket contact port
EXPOSE 7012

# Default port to listen for DNS requests for DNS tunneling C2 channel
EXPOSE 8853

# Default port to listen for SSH tunneling requests
EXPOSE 8022

# Default FTP port for FTP C2 channel
EXPOSE 2222


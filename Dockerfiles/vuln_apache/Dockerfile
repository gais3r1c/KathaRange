# NOTE: This Docker image uses Apache version 2.4.49, which is known to have vulnerabilities.
# Specifically, this version is affected by CVE-2021-41773 and CVE-2021-42013, which allow path traversal and remote code execution.
# It is recommended to use a more recent version for production environments.

FROM httpd:2.4.49

# Aggiorna i repository APT verso archive.debian.org per Debian Buster
RUN printf 'deb http://archive.debian.org/debian buster main contrib non-free\n' > /etc/apt/sources.list \
    && printf 'deb http://archive.debian.org/debian buster-updates main contrib non-free\n' >> /etc/apt/sources.list \
    && printf 'deb http://archive.debian.org/debian-security buster/updates main contrib non-free\n' >> /etc/apt/sources.list \
    && printf 'Acquire::Check-Valid-Until "false";\n' > /etc/apt/apt.conf.d/99no-check-valid-until

# Installa pacchetti di utilità e OpenSSH-server
RUN apt-get update --allow-releaseinfo-change \
    && apt-get install -y \
       iproute2 lsb-release vim procps curl syslog-ng netcat wget \
       openssh-server \
    && rm -rf /var/lib/apt/lists/*

# Configura SSH: abilita login root e password authentication
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config

# Crea utente 'monkey' con password Monkey123!
RUN useradd -m monkey \
    && echo 'monkey:Monkey123!' | chpasswd

# Copia configurazione Apache personalizzata
COPY ./httpd.conf /usr/local/apache2/conf/

# Espone porte SSH e HTTP
EXPOSE 22 80

# All'avvio, lancia Apache in foreground e il demone ssh
CMD ["/bin/bash", "-c", "/usr/local/apache2/bin/httpd -D FOREGROUND & /usr/sbin/sshd -D"]


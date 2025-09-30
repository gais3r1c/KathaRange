FROM kathara/base

RUN apt-get update --allow-releaseinfo-change && \
    DEBIAN_FRONTEND=noninteractive apt-get install -y openssh-server && \
    rm -rf /var/lib/apt/lists/*

# Permetti login con password (se vuoi)
RUN mkdir -p /var/run/sshd \
    && sed -i 's/^#PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^PasswordAuthentication no/PasswordAuthentication yes/' /etc/ssh/sshd_config
EXPOSE 22
CMD ["/usr/sbin/sshd","-D"]

# Víctima: servidor SSH real que reenvía sus logs de auth a Wazuh por syslog.
FROM debian:12-slim

# openssh-server = el SSH real; rsyslog = para reenviar los logs a Wazuh manager.
RUN apt-get update \
    && apt-get install -y --no-install-recommends openssh-server rsyslog \
    && rm -rf /var/lib/apt/lists/*

# Habilitamos login root por password y password auth, para que los intentos
# fallidos del atacante queden logueados como "Failed password for root".
RUN sed -i 's/^#\?PermitRootLogin.*/PermitRootLogin yes/' /etc/ssh/sshd_config \
    && sed -i 's/^#\?PasswordAuthentication.*/PasswordAuthentication yes/' /etc/ssh/sshd_config \
    && mkdir -p /run/sshd \
    # Usuario normal del lab + root con password aleatorio largo (imposible de adivinar).
    && useradd -m -s /bin/bash labuser \
    && echo "labuser:SuperSecret123" | chpasswd \
    && echo "root:$(head -c 24 /dev/urandom | base64)" | chpasswd

# Regla de reenvío de logs a Wazuh manager.
COPY services/victim/rsyslog-forward.conf /etc/rsyslog.d/60-wazuh.conf
COPY services/victim/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

EXPOSE 22
CMD ["/entrypoint.sh"]

#!/bin/sh
# Arranca rsyslog (para capturar y reenviar los logs de sshd) y luego sshd en foreground.
set -e

# Levantamos rsyslog en segundo plano. Ignora el warning de imklog en contenedor.
rsyslogd 2>/dev/null || true

echo "[victim] sshd + rsyslog listos. Reenviando auth logs a wazuh.manager:514"
# sshd en foreground (-D) para que el contenedor quede vivo.
exec /usr/sbin/sshd -D

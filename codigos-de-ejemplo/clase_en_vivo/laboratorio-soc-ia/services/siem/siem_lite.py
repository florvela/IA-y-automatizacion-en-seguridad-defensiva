"""
siem-lite: detector mínimo de fuerza bruta SSH (stand-in de Wazuh).

# ¿Por qué existe? Para que el lab CORRA EN CUALQUIER LAPTOP sin los ~8GB que
# pide Wazuh. Hace lo mínimo que hace un SIEM: leer logs, aplicar una regla y
# emitir una alerta. En el perfil "siem" esto lo reemplaza Wazuh de verdad,
# y ambos leen EXACTAMENTE el mismo log real de sshd.
#
# La alerta que emite tiene el MISMO formato que manda Wazuh, así el SOAR-bridge
# no nota la diferencia. Eso es diseñar contra un contrato, no contra una herramienta.
"""
from __future__ import annotations

import os
import re
import time
from collections import defaultdict, deque

import requests

LOG_PATH = os.getenv("AUTH_LOG", "/logs/auth.log")
SOAR_URL = os.getenv("SOAR_URL", "http://soar-bridge:9000/webhook/wazuh")
WINDOW_SECONDS = int(os.getenv("WINDOW_SECONDS", "60"))
THRESHOLD = int(os.getenv("THRESHOLD", "5"))  # intentos fallidos para gatillar

# Regex del log de sshd: "Failed password for [invalid user] <user> from <ip> port <n>"
FAILED_RE = re.compile(
    r"Failed password for (?:invalid user )?(?P<user>\S+) from (?P<ip>\d{1,3}(?:\.\d{1,3}){3})"
)


def build_wazuh_alert(ip: str, user: str, count: int) -> dict:
    """Arma un JSON con el MISMO formato que el integrator de Wazuh."""
    return {
        "id": f"siemlite-{int(time.time())}-{ip}",
        "timestamp": time.strftime("%Y-%m-%dT%H:%M:%S%z"),
        "rule": {
            "id": "5712",
            "description": "SSHD brute force trying to get access to the system.",
            "level": 10,
        },
        "data": {"srcip": ip, "dstuser": user},
        "agent": {"name": "victim"},
        "full_log": f"{count} intentos fallidos de SSH desde {ip} (usuario {user})",
    }


def tail(path: str):
    """Generador que sigue un archivo tipo 'tail -f', esperando si aún no existe."""
    while not os.path.exists(path):
        print(f"[siem-lite] esperando el log en {path}...")
        time.sleep(2)
    with open(path, "r") as f:
        f.seek(0, os.SEEK_END)  # arrancamos desde el final (solo eventos nuevos)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.3)
                continue
            yield line


def main() -> None:
    print(f"[siem-lite] vigilando {LOG_PATH} | regla: {THRESHOLD} fallos / {WINDOW_SECONDS}s")
    # Ventana deslizante de timestamps por IP.
    windows: dict[str, deque] = defaultdict(deque)
    last_user: dict[str, str] = {}
    alerted: dict[str, float] = {}  # anti-spam: no re-alertar la misma IP enseguida

    for line in tail(LOG_PATH):
        m = FAILED_RE.search(line)
        if not m:
            continue
        ip, user = m.group("ip"), m.group("user")
        now = time.time()
        last_user[ip] = user

        # Mantenemos solo los intentos dentro de la ventana.
        dq = windows[ip]
        dq.append(now)
        while dq and now - dq[0] > WINDOW_SECONDS:
            dq.popleft()

        print(f"[siem-lite] fallo SSH: user={user} ip={ip} (en ventana: {len(dq)})")

        # ¿Se pasó del umbral y no alertamos hace poco?
        if len(dq) >= THRESHOLD and now - alerted.get(ip, 0) > WINDOW_SECONDS:
            alerted[ip] = now
            alert = build_wazuh_alert(ip, last_user[ip], len(dq))
            if not SOAR_URL:
                print(f"[siem-lite] ALERTA (solo log, SOAR_URL vacío): {ip} x{len(dq)}")
                continue
            try:
                r = requests.post(SOAR_URL, json=alert, timeout=10)
                print(f"[siem-lite] ALERTA enviada al SOAR ({ip}) -> HTTP {r.status_code}: {r.text[:120]}")
            except Exception as exc:  # noqa: BLE001
                print(f"[siem-lite] error enviando alerta: {exc}")


if __name__ == "__main__":
    main()

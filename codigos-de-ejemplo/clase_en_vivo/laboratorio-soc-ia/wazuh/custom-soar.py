#!/usr/bin/env python3
"""
Integración custom de Wazuh -> SOC worker (enrichment) -> soar-bridge.

Flujo: Wazuh POSTea aquí; el worker enriquece la IP y dispara el playbook en el bridge.
Si el worker no responde, fallback directo al bridge (la demo no se cae en vivo).
"""
import json
import sys
import urllib.error
import urllib.request

DEFAULT_WORKER_URL = "http://soc-worker:9100/webhook/wazuh"
FALLBACK_URL = "http://soar-bridge:9000/webhook/wazuh"


def _post(url: str, data: bytes) -> int:
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as resp:
        return resp.status


def _resolve_hook_url() -> str:
    for arg in sys.argv[2:]:
        if arg.startswith("http"):
            return arg
    return DEFAULT_WORKER_URL


def main() -> None:
    alert_file = sys.argv[1]
    hook_url = _resolve_hook_url()

    with open(alert_file, "r") as f:
        alert = json.load(f)

    data = json.dumps(alert).encode("utf-8")

    try:
        status = _post(hook_url, data)
        print(f"custom-soar: enviado a worker {hook_url} -> HTTP {status}")
        return
    except Exception as exc:  # noqa: BLE001
        print(f"custom-soar: worker falló ({exc}); fallback a soar-bridge", file=sys.stderr)

    try:
        status = _post(FALLBACK_URL, data)
        print(f"custom-soar: fallback enviado a {FALLBACK_URL} -> HTTP {status}")
    except Exception as exc:  # noqa: BLE001
        print(f"custom-soar: error en fallback -> {exc}", file=sys.stderr)
        sys.exit(1)


if __name__ == "__main__":
    main()

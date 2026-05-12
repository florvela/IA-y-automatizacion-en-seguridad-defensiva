#!/usr/bin/env python3
"""
trigger_alert.py — Dispara una alerta SSH al webhook de Shuffle.

Uso:
    # Ver el payload sin enviar nada
    python trigger_alert.py --dry-run

    # Enviar alerta real al webhook de Shuffle
    python trigger_alert.py --url https://shuffler.io/api/v1/hooks/webhook-id

    # Personalizar la alerta
    python trigger_alert.py --url <url> --ip 45.33.32.156 --intentos 120 --usuario admin

El webhook URL se obtiene en Shuffle:
    Workflow → Triggers → Webhook → copiar la URL
"""

import json
import sys
import argparse
from datetime import datetime, timezone
from pathlib import Path

# ── intentar importar requests ──────────────────────────────────────────────
try:
    import requests
    REQUESTS_OK = True
except ImportError:
    REQUESTS_OK = False


# ── alerta por defecto (datos del módulo 02) ────────────────────────────────
DEFAULT_ALERT = {
    "id": f"ALT-{datetime.now(timezone.utc).strftime('%Y%m%d-%H%M%S')}",
    "tipo": "fuerza_bruta_ssh",
    "ip_origen": "173.234.31.186",
    "usuario": "root",
    "intentos": 47,
    "puerto": 22,
    "primera_vez": "2024-01-25T19:30:11Z",
    "ultima_vez": datetime.now(timezone.utc).isoformat(),
    "severidad": "HIGH",
    "fuente": "SIEM",
    "hostname_victima": "srv-bastion-01",
}


def imprimir_payload(alerta: dict):
    print("\n── Payload de la alerta ──────────────────────────────")
    print(json.dumps(alerta, indent=2, ensure_ascii=False))
    print("──────────────────────────────────────────────────────")


def enviar_alerta(url: str, alerta: dict) -> bool:
    if not REQUESTS_OK:
        print("[ERROR] Instalá requests: pip install requests")
        return False

    print(f"\n→ Enviando alerta al webhook de Shuffle...")
    print(f"  URL: {url}")

    try:
        response = requests.post(
            url,
            json=alerta,
            headers={"Content-Type": "application/json"},
            timeout=10,
        )
        response.raise_for_status()
        print(f"\n✓ Alerta enviada correctamente")
        print(f"  HTTP {response.status_code}")
        if response.text:
            try:
                data = response.json()
                print(f"  Respuesta: {json.dumps(data, indent=2)}")
            except Exception:
                print(f"  Respuesta: {response.text[:200]}")
        return True

    except requests.exceptions.ConnectionError:
        print(f"\n✗ No se pudo conectar a {url}")
        print("  Verificá que Shuffle esté corriendo: docker compose up -d")
        return False
    except requests.exceptions.HTTPError as e:
        print(f"\n✗ Error HTTP: {e}")
        print("  Verificá que el webhook esté habilitado en Shuffle (botón ON en el trigger)")
        return False
    except Exception as e:
        print(f"\n✗ Error inesperado: {e}")
        return False


def main():
    parser = argparse.ArgumentParser(
        description="Dispara una alerta SSH al webhook de Shuffle",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )
    parser.add_argument(
        "--url",
        help="URL del webhook de Shuffle (Workflow → Triggers → Webhook)",
        default=None,
    )
    parser.add_argument(
        "--ip",
        help="IP atacante (default: 173.234.31.186)",
        default=DEFAULT_ALERT["ip_origen"],
    )
    parser.add_argument(
        "--intentos",
        help="Número de intentos (default: 47)",
        type=int,
        default=DEFAULT_ALERT["intentos"],
    )
    parser.add_argument(
        "--usuario",
        help="Usuario atacado (default: root)",
        default=DEFAULT_ALERT["usuario"],
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Mostrar el payload sin enviar nada",
    )
    parser.add_argument(
        "--from-file",
        help="Cargar alerta desde un archivo JSON (ej: sample_alert.json)",
        default=None,
    )

    args = parser.parse_args()

    # Construir alerta
    if args.from_file:
        ruta = Path(args.from_file)
        if not ruta.exists():
            print(f"[ERROR] Archivo no encontrado: {args.from_file}")
            sys.exit(1)
        alerta = json.loads(ruta.read_text())
    else:
        alerta = DEFAULT_ALERT.copy()
        alerta["ip_origen"] = args.ip
        alerta["intentos"] = args.intentos
        alerta["usuario"] = args.usuario
        # Actualizar severidad basada en intentos
        if args.intentos > 100:
            alerta["severidad"] = "CRITICAL"
        elif args.intentos > 20:
            alerta["severidad"] = "HIGH"
        else:
            alerta["severidad"] = "MEDIUM"

    print(f"\n{'='*55}")
    print(f" TRIGGER — Alerta SSH Fuerza Bruta")
    print(f"{'='*55}")
    print(f" IP origen  : {alerta['ip_origen']}")
    print(f" Usuario    : {alerta['usuario']}")
    print(f" Intentos   : {alerta['intentos']}")
    print(f" Severidad  : {alerta['severidad']}")

    if args.dry_run:
        print("\n[DRY RUN] No se envía nada. Payload que se enviaría:")
        imprimir_payload(alerta)
        print("\nPara enviar de verdad: python trigger_alert.py --url <webhook-url>")
        return

    if not args.url:
        print("\n[ERROR] Necesitás la URL del webhook.")
        print("  Obtenerla en Shuffle: Workflow → Triggers → Webhook → copiar URL")
        print("\n  Para ver el payload sin enviar: python trigger_alert.py --dry-run")
        sys.exit(1)

    imprimir_payload(alerta)
    exito = enviar_alerta(args.url, alerta)
    sys.exit(0 if exito else 1)


if __name__ == "__main__":
    main()

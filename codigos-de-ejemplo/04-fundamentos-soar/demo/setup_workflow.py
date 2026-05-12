#!/usr/bin/env python3
"""
setup_workflow.py — Crea el workflow de SSH Brute Force en Shuffle via API.

Uso:
    python setup_workflow.py
    python setup_workflow.py --url http://localhost:3001 --user admin --password password

El script:
  1. Hace login en Shuffle
  2. Crea el workflow con todos los nodos y conexiones
  3. Imprime la URL del webhook para usar con trigger_alert.py
"""

import json
import sys
import argparse
import uuid
import requests

# ── configuración por defecto ────────────────────────────────────────────────
DEFAULT_URL  = "http://localhost:3001"
DEFAULT_USER = "admin"
DEFAULT_PASS = "password123"


def make_condition(source_value, operator, dest_value):
    """Construye una condición en el formato que Shuffle espera."""
    cid = str(uuid.uuid4())
    return {
        "condition": {
            "name": "condition",
            "value": operator,
            "id": cid,
            "configuration": True,
        },
        "source": {
            "name": "source",
            "value": source_value,
            "variant": "STATIC_VALUE",
            "action_field": "",
            "id": cid,
        },
        "destination": {
            "name": "destination",
            "value": dest_value,
            "variant": "STATIC_VALUE",
            "action_field": "",
            "id": cid,
        },
    }


def login(base_url, username, password):
    session = requests.Session()
    r = session.post(
        f"{base_url}/api/v1/users/login",
        json={"username": username, "password": password},
        timeout=10,
    )
    data = r.json()
    if not data.get("success"):
        print(f"✗ Login fallido: {data.get('reason')}")
        sys.exit(1)
    # Shuffle devuelve el token en el body Y lo setea como cookie
    token = next(
        (c["value"] for c in data.get("cookies", []) if c["key"] == "session_token"),
        None,
    )
    if token:
        session.cookies.set("session_token", token)
        session.cookies.set("__session", token)
    print(f"✓ Login OK — usuario: {username}")
    return session


def get_shuffle_tools_id(base_url, session):
    """Obtiene el app_id real de Shuffle Tools en esta instalación."""
    r = session.get(f"{base_url}/api/v1/apps", timeout=10)
    apps = r.json() if r.ok else []
    if isinstance(apps, list):
        for app in apps:
            if isinstance(app, dict) and app.get("name") == "Shuffle Tools":
                return app.get("id")
    return None


def crear_workflow(base_url, session, app_id):
    """Crea el workflow completo via API."""

    workflow = {
        "name": "SSH Brute Force — Respuesta Automática",
        "description": "Playbook de respuesta a ataques de fuerza bruta SSH. 5 pasos del runbook.",
        "tags": ["ssh", "brute-force"],
        "status": "production",
        "workflow_variables": [],
        "execution_variables": [],
        "actions": [
            {
                "id": "11111111-1111-1111-1111-111111111111",
                "name": "repeat_back_to_me",
                "label": "Paso 1 — Recolectar datos",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "IP: $exec.ip_origen | Usuario: $exec.usuario | Intentos: $exec.intentos | Severidad: $exec.severidad", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 450, "y": 100},
                "environment": "Shuffle",
                "is_valid": True,
                "isStartNode": True,
            },
            {
                "id": "22222222-2222-2222-2222-222222222222",
                "name": "repeat_back_to_me",
                "label": "Paso 2 — Verificar CMDB",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "CMDB: IP $exec.ip_origen — IP externa, no pertenece a la org", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 450, "y": 300},
                "environment": "Shuffle",
                "is_valid": True,
            },
            {
                "id": "33333333-3333-3333-3333-333333333333",
                "name": "repeat_back_to_me",
                "label": "Paso 3 — Mitigar",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "MITIGACIÓN: IP $exec.ip_origen bloqueada en firewall | Password reset para $exec.usuario", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 450, "y": 500},
                "environment": "Shuffle",
                "is_valid": True,
            },
            {
                "id": "44444444-4444-4444-4444-444444444444",
                "name": "repeat_back_to_me",
                "label": "Paso 4 — Investigar",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "SIEM: 0 accesos exitosos desde $exec.ip_origen en 24h — ataque contenido", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 450, "y": 700},
                "environment": "Shuffle",
                "is_valid": True,
            },
            {
                "id": "55555555-5555-5555-5555-555555555555",
                "name": "repeat_back_to_me",
                "label": "Paso 5 — Ticket Jira",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "TICKET: [ALTO] Fuerza bruta SSH desde $exec.ip_origen | $exec.intentos intentos | Usuario: $exec.usuario | Estado: RESUELTO", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 450, "y": 900},
                "environment": "Shuffle",
                "is_valid": True,
            },
            {
                "id": "66666666-6666-6666-6666-666666666666",
                "name": "repeat_back_to_me",
                "label": "Falso Positivo — Cerrar",
                "app_name": "Shuffle Tools",
                "app_version": "1.2.0",
                "app_id": app_id,
                "action": "repeat_back_to_me",
                "parameters": [{"name": "call", "value": "FALSO POSITIVO: IP $exec.ip_origen es interna — caso cerrado sin acción", "variant": "STATIC_VALUE", "configuration": False}],
                "position": {"x": 900, "y": 500},
                "environment": "Shuffle",
                "is_valid": True,
            },
        ],
        # Sin condiciones en el POST — Shuffle las descarta si van en el POST inicial
        "branches": [
            {"id": "b1", "source_id": "11111111-1111-1111-1111-111111111111", "destination_id": "22222222-2222-2222-2222-222222222222", "label": "", "has_errors": False, "conditions": [], "decorator": False, "source_parent": ""},
            {"id": "b2", "source_id": "22222222-2222-2222-2222-222222222222", "destination_id": "33333333-3333-3333-3333-333333333333", "label": "IP externa", "has_errors": False, "conditions": [], "decorator": False, "source_parent": ""},
            {"id": "b3", "source_id": "22222222-2222-2222-2222-222222222222", "destination_id": "66666666-6666-6666-6666-666666666666", "label": "IP interna", "has_errors": False, "conditions": [], "decorator": False, "source_parent": ""},
            {"id": "b4", "source_id": "33333333-3333-3333-3333-333333333333", "destination_id": "44444444-4444-4444-4444-444444444444", "label": "", "has_errors": False, "conditions": [], "decorator": False, "source_parent": ""},
            {"id": "b5", "source_id": "44444444-4444-4444-4444-444444444444", "destination_id": "55555555-5555-5555-5555-555555555555", "label": "", "has_errors": False, "conditions": [], "decorator": False, "source_parent": ""},
        ],
    }

    r = session.post(
        f"{base_url}/api/v1/workflows",
        json=workflow,
        timeout=15,
    )

    if not r.ok:
        print(f"✗ Error creando workflow: HTTP {r.status_code}")
        print(f"  {r.text[:300]}")
        sys.exit(1)

    data = r.json()
    workflow_id = data.get("id") if isinstance(data, dict) else None
    if not workflow_id:
        workflow_id = data if isinstance(data, str) else None

    if not workflow_id:
        print(f"✗ No se obtuvo el workflow ID. Respuesta: {str(data)[:200]}")
        sys.exit(1)

    print(f"✓ Workflow creado — ID: {workflow_id}")
    return workflow_id


def agregar_condiciones(base_url, session, workflow_id):
    """GET del workflow ya creado → agrega condiciones a b2 y b3 → PUT."""
    r = session.get(f"{base_url}/api/v1/workflows/{workflow_id}", timeout=10)
    if not r.ok:
        print(f"⚠ No se pudo leer el workflow para agregar condiciones (HTTP {r.status_code})")
        return

    data = r.json()
    branches = data.get("branches", [])

    # Shuffle puede reemplazar los IDs "b2"/"b3" con UUIDs propios,
    # así que identificamos las branches por source_id + destination_id.
    PASO2 = "22222222-2222-2222-2222-222222222222"
    PASO3 = "33333333-3333-3333-3333-333333333333"
    FP    = "66666666-6666-6666-6666-666666666666"

    actualizadas = 0
    for b in branches:
        src, dst = b.get("source_id", ""), b.get("destination_id", "")
        if src == PASO2 and dst == PASO3:
            b["conditions"] = [make_condition("$exec.ip_origen", "!startswith", "10.")]
            actualizadas += 1
        elif src == PASO2 and dst == FP:
            b["conditions"] = [make_condition("$exec.ip_origen", "startswith", "10.")]
            actualizadas += 1

    if actualizadas < 2:
        print(f"⚠ Solo se encontraron {actualizadas}/2 branches para actualizar")
        print(f"  Branches disponibles: {[(b.get('source_id','')[-4:], b.get('destination_id','')[-4:]) for b in branches]}")

    r2 = session.put(
        f"{base_url}/api/v1/workflows/{workflow_id}",
        json=data,
        timeout=15,
    )

    if not r2.ok:
        print(f"⚠ No se pudieron agregar condiciones (HTTP {r2.status_code}): {r2.text[:200]}")
        return

    print(f"✓ Condiciones agregadas ({actualizadas}/2 branches) — !startswith '10.' | startswith '10.'")


def verificar_condiciones(base_url, session, workflow_id):
    """Lee el workflow de vuelta y muestra qué guardó Shuffle para las condiciones."""
    r = session.get(f"{base_url}/api/v1/workflows/{workflow_id}", timeout=10)
    if not r.ok:
        print(f"⚠ No se pudo leer el workflow (HTTP {r.status_code})")
        return
    data = r.json()
    branches = data.get("branches", [])
    branches_con_cond = [b for b in branches if b.get("conditions")]
    if not branches_con_cond:
        print("⚠ CONDICIONES: Shuffle no guardó ninguna condición — formato incorrecto")
        print("  → Mirá el output de debug abajo para saber el formato real:")
        sample = next((b for b in branches), None)
        if sample:
            print(f"  Branch sample: {json.dumps(sample, ensure_ascii=False)}")
        return
    print(f"✓ Condiciones guardadas en {len(branches_con_cond)} branch(es):")
    for b in branches_con_cond:
        print(f"  [{b.get('label', b['id'])}]: {json.dumps(b['conditions'], ensure_ascii=False)}")


def crear_webhook(base_url, session, workflow_id):
    """Agrega el trigger webhook al workflow."""
    trigger = {
        "workflow_id": workflow_id,
        "id": "webhook-trigger-001",
        "name": "Webhook SSH Alert",
        "type": "webhook",
        "status": "running",
        "start": "11111111-1111-1111-1111-111111111111",
    }

    r = session.post(
        f"{base_url}/api/v1/workflows/{workflow_id}/triggers",
        json=trigger,
        timeout=10,
    )

    if not r.ok:
        print(f"⚠ No se pudo crear el webhook via API (HTTP {r.status_code})")
        print(f"  Agregalo manualmente: Triggers → Webhook → conectar al Paso 1 → ON")
        return None

    data = r.json()
    print(f"✓ Webhook creado")
    return data


def main():
    parser = argparse.ArgumentParser(description="Crea el workflow SSH en Shuffle via API")
    parser.add_argument("--url",      default=DEFAULT_URL,  help="URL de Shuffle (default: http://localhost:3001)")
    parser.add_argument("--user",     default=DEFAULT_USER, help="Usuario (default: admin)")
    parser.add_argument("--password", default=DEFAULT_PASS, help="Contraseña (default: password)")
    args = parser.parse_args()

    base_url = args.url.rstrip("/")

    print(f"\n{'='*55}")
    print(f" Setup — Workflow SSH Brute Force en Shuffle")
    print(f"{'='*55}\n")

    # 1. Login
    session = login(base_url, args.user, args.password)

    # 2. Obtener app_id de Shuffle Tools
    app_id = get_shuffle_tools_id(base_url, session)
    if app_id:
        print(f"✓ Shuffle Tools app_id: {app_id}")
    else:
        app_id = "a524a018-7a4f-447c-a664-22b54afa473d"
        print(f"⚠ No se pudo obtener app_id via API — usando: {app_id}")

    # 3. Crear workflow (sin condiciones en el POST)
    workflow_id = crear_workflow(base_url, session, app_id)

    # 4. Agregar condiciones via PUT (Shuffle las ignora en el POST inicial)
    agregar_condiciones(base_url, session, workflow_id)

    # 5. Intentar crear webhook
    crear_webhook(base_url, session, workflow_id)

    print(f"\n{'='*55}")
    print(f" Listo")
    print(f"{'='*55}")
    print(f"\n Abrir en Shuffle:")
    print(f"  {base_url}/workflows/{workflow_id}")
    print(f"\n Si el webhook no se creó automáticamente:")
    print(f"  Triggers → Webhook → arrastrá → conectar al Paso 1 → ON → copiar URL")
    print(f"\n Una vez que tengas la URL del webhook:")
    print(f"  python trigger_alert.py --url <WEBHOOK_URL>")
    print()


if __name__ == "__main__":
    main()

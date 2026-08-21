"""
Servidor MCP con tools, resources y prompts.

# MCP = Model Context Protocol. Expone capacidades a un LLM/cliente:
# Transporte: streamable-http, así los otros contenedores se conectan por red.
#
# Tools de INVESTIGACIÓN (lectura, seguras -> el LLM las usa libremente):
#   - check_ip_reputation
#   - get_user_login_history
#   - geolocate_ip
#   - create_incident_ticket
#
# Tool de ACCIÓN (irreversible -> NO se le da al LLM, exige approved=True):
#   - block_ip
#
# Resources (datos de solo lectura, URI):
#   - soc://lab/blacklist
#
# Prompts (plantillas reutilizables):
#   - investigate_ssh_alert
"""
from __future__ import annotations

import json
import os
import uuid
from datetime import datetime, timezone
from pathlib import Path

# mcp >= 2.0: la clase de alto nivel es MCPServer (antes se llamaba FastMCP).
from mcp.server.mcpserver import MCPServer

from soc.enrichment import geolocate_ip_offline, lookup_ip_reputation

# Carpetas: datos semilla (solo lectura) y estado compartido (escritura).
SEED_DIR = Path(os.getenv("SOC_SEED_DIR", "/app/data"))
STATE_DIR = Path(os.getenv("SOC_STATE_DIR", "/data/state"))

# En mcp 2.0 el host/port se pasan en .run(), no en el constructor.
mcp = MCPServer(name="soc-tools")


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ── Resources ────────────────────────────────────────────────────────


@mcp.resource(
    "soc://lab/blacklist",
    name="lab_blacklist",
    description="Blacklist semilla del laboratorio (solo lectura).",
    mime_type="text/plain",
)
def lab_blacklist() -> str:
    """Devuelve el contenido de data/blacklist.txt."""
    path = SEED_DIR / "blacklist.txt"
    if not path.exists():
        return "# blacklist vacía\n"
    return path.read_text(encoding="utf-8")


# ── Prompts ──────────────────────────────────────────────────────────


@mcp.prompt(
    name="investigate_ssh_alert",
    description="Plantilla para investigar una alerta SSH / brute force.",
)
def investigate_ssh_alert(src_ip: str, user: str) -> str:
    """Prompt parametrizado; el cliente MCP lo pide con get_prompt()."""
    return (
        f"Investigá posible brute force SSH desde {src_ip} contra el usuario '{user}'. "
        "Usá el contexto PRE-IA del ticket y tools de historial/ticket si hace falta. "
        "No ejecutes bloqueos; devolvé un análisis breve en español y next steps."
    )


# ── Tools ─────────────────────────────────────────────────────────────


@mcp.tool()
def check_ip_reputation(ip: str) -> str:
    """Consulta la reputación de una IP contra la blacklist interna y devuelve un score 0-100."""
    return json.dumps(lookup_ip_reputation(ip))


@mcp.tool()
def get_user_login_history(user: str) -> str:
    """Devuelve el historial de logins conocido de un usuario (para dar contexto)."""
    f = SEED_DIR / "users.json"
    users = json.loads(f.read_text()) if f.exists() else {}
    hist = users.get(user, {"user": user, "known": False, "note": "usuario sin historial previo"})
    return json.dumps(hist)


@mcp.tool()
def geolocate_ip(ip: str) -> str:
    """Geolocalización aproximada de una IP (offline, para la demo)."""
    return json.dumps(geolocate_ip_offline(ip))


@mcp.tool()
def create_incident_ticket(title: str, severity: str, summary: str) -> str:
    """Crea un ticket de incidente y lo guarda. Devuelve el ticket_id."""
    tickets_dir = STATE_DIR / "tickets"
    tickets_dir.mkdir(parents=True, exist_ok=True)
    ticket_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    ticket = {
        "ticket_id": ticket_id,
        "title": title,
        "severity": severity,
        "summary": summary,
        "created_at": _now(),
        "status": "open",
    }
    (tickets_dir / f"{ticket_id}.json").write_text(json.dumps(ticket, indent=2, ensure_ascii=False))
    return json.dumps({"ticket_id": ticket_id, "status": "created"})


@mcp.tool()
def block_ip(ip: str, approved: bool = False) -> str:
    """
    Bloquea una IP en el firewall. ACCIÓN IRREVERSIBLE.

    # Guardarraíl clave del lab: si approved != True, la tool se NIEGA a ejecutar.
    # Así, aunque el LLM intente bloquear, no pasa nada sin humano.
    """
    if not approved:
        return json.dumps(
            {
                "status": "requires_approval",
                "ip": ip,
                "message": "Acción bloqueante: requiere aprobación humana (approved=True).",
            }
        )

    # Simulamos el bloqueo escribiéndolo a una blocklist (en real: firewall / active-response).
    blocklist_dir = STATE_DIR / "blocklist"
    blocklist_dir.mkdir(parents=True, exist_ok=True)
    (blocklist_dir / f"{ip.replace('.', '_')}.json").write_text(
        json.dumps({"ip": ip, "blocked_at": _now(), "by": "human-approved"}, indent=2)
    )
    return json.dumps({"status": "blocked", "ip": ip, "blocked_at": _now()})


if __name__ == "__main__":
    # Levanta el servidor MCP en http://0.0.0.0:8080/mcp
    mcp.run(transport="streamable-http", host="0.0.0.0", port=8080)

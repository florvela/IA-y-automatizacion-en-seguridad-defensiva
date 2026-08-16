"""
Servidor MCP con herramientas de seguridad.

Las tres primitivas de MCP:
  TOOLS      : el LLM ejecuta acciones
    - check_ip_reputation   : consulta VirusTotal
    - create_incident_ticket: crea ticket de incidente
    - propose_host_isolation: propone aislar un host (requiere aprobación)
  RESOURCES  : el LLM lee datos (solo lectura, como un GET)
    - soc://config          : umbrales y política del SOC
    - soc://runbooks/{tipo} : el runbook para un tipo de incidente
    - soc://tickets         : tickets de incidente abiertos
  PROMPTS    : plantillas reutilizables
    - triage_alerta         : instrucciones para clasificar una alerta
    - reporte_incidente     : estructura para redactar el reporte final
"""

import glob
import json
import logging
import os
import datetime
import requests
from mcp.server.fastmcp import FastMCP

logging.getLogger("mcp").setLevel(logging.WARNING)

mcp = FastMCP("SOC Security Tools")

VIRUSTOTAL_API_KEY = os.getenv("VIRUSTOTAL_API_KEY", "")


@mcp.tool()
def check_ip_reputation(ip: str) -> str:
    """
    Verifica la reputación de una IP en VirusTotal.
    Usar cuando se necesita saber si una IP destino es maliciosa.

    Args:
        ip: Dirección IP a consultar

    Returns:
        JSON con cantidad de motores que la marcan como maliciosa y veredicto final
    """
    if not VIRUSTOTAL_API_KEY:
        # Mock para demo sin API key — datos reales de 185.220.101.47
        return json.dumps({
            "ip": ip,
            "malicious": 45,
            "suspicious": 12,
            "harmless": 8,
            "total_engines": 89,
            "country": "NL",
            "asn": "AS200052 - Tor Exit Node",
            "tags": ["tor-exit-node", "proxy", "anonymizer"],
            "verdict": "MALICIOUS"
        })

    try:
        url = f"https://www.virustotal.com/api/v3/ip_addresses/{ip}"
        headers = {"x-apikey": VIRUSTOTAL_API_KEY}
        response = requests.get(url, headers=headers, timeout=10)
        data = response.json()
        stats = data["data"]["attributes"]["last_analysis_stats"]
        return json.dumps({
            "ip": ip,
            "malicious":     stats.get("malicious", 0),
            "suspicious":    stats.get("suspicious", 0),
            "harmless":      stats.get("harmless", 0),
            "total_engines": sum(stats.values()),
            "verdict": "MALICIOUS" if stats.get("malicious", 0) > 5 else "CLEAN"
        })
    except Exception as e:
        return json.dumps({"error": str(e), "ip": ip})


@mcp.tool()
def create_incident_ticket(
    title: str,
    severity: str,
    affected_host: str,
    affected_user: str,
    description: str,
    iocs: list[str],
    recommended_actions: list[str]
) -> str:
    """
    Crea un ticket de incidente de seguridad.
    Usar cuando se confirma un incidente que requiere seguimiento y documentación.

    Args:
        title: Título descriptivo del incidente
        severity: CRITICAL, HIGH, MEDIUM o LOW
        affected_host: Hostname del equipo comprometido
        affected_user: Usuario afectado
        description: Descripción técnica del incidente
        iocs: Lista de indicadores de compromiso
        recommended_actions: Acciones recomendadas para contención

    Returns:
        ID del ticket creado
    """
    ticket_id = f"INC-{datetime.datetime.now().strftime('%Y%m%d-%H%M%S')}"
    ticket = {
        "id": ticket_id,
        "title": title,
        "severity": severity,
        "status": "OPEN",
        "affected_host": affected_host,
        "affected_user": affected_user,
        "description": description,
        "iocs": iocs,
        "recommended_actions": recommended_actions,
        "created_at": datetime.datetime.now().isoformat(),
        "created_by": "SOC-AI-Agent"
    }
    os.makedirs("tickets", exist_ok=True)
    with open(f"tickets/{ticket_id}.json", "w") as f:
        json.dump(ticket, f, indent=2)

    return json.dumps({
        "success": True,
        "ticket_id": ticket_id,
        "message": f"Ticket {ticket_id} creado — severidad {severity}"
    })


@mcp.tool()
def propose_host_isolation(hostname: str, reason: str, severity: str) -> str:
    """
    Propone aislar un host de la red. REQUIERE APROBACIÓN HUMANA.
    No ejecuta el aislamiento — solo lo propone para que el analista decida.

    Args:
        hostname: Nombre del host a aislar
        reason: Justificación técnica del aislamiento
        severity: Nivel de urgencia (CRITICAL, HIGH, MEDIUM)

    Returns:
        Propuesta pendiente de aprobación humana
    """
    return json.dumps({
        "action":   "HOST_ISOLATION",
        "hostname": hostname,
        "reason":   reason,
        "severity": severity,
        "status":   "PENDING_HUMAN_APPROVAL",
        "warning":  "Esta acción requiere aprobación explícita del analista.",
        "impact":   f"{hostname} quedará sin acceso a la red hasta reversión manual."
    })


# ─────────────────────────────────────────────────────────────
# RESOURCES — datos que el LLM puede LEER (solo lectura, como un GET)
# ─────────────────────────────────────────────────────────────

# Runbooks internos del SOC, indexados por tipo de incidente
RUNBOOKS = {
    "DATA_EXFILTRATION": (
        "RUNBOOK — Exfiltración de datos\n"
        "1. Confirmar el volumen y destino del tráfico saliente.\n"
        "2. Verificar la reputación de la IP destino (VirusTotal).\n"
        "3. Si es maliciosa: crear ticket y proponer aislar el host.\n"
        "4. Preservar evidencia y notificar al responsable del activo."
    ),
    "BRUTE_FORCE": (
        "RUNBOOK — Fuerza bruta\n"
        "1. Registrar IP origen, usuario e intentos.\n"
        "2. Verificar si la IP es conocida/interna.\n"
        "3. Bloquear la IP y forzar cambio de contraseña.\n"
        "4. Escalar si hubo acceso exitoso."
    ),
}


@mcp.resource("soc://config")
def soc_config() -> str:
    """Configuración y política del SOC: umbrales de decisión y modo de operación."""
    return json.dumps({
        "umbral_ip_maliciosa": 5,          # motores de VT para considerar MALICIOUS
        "auto_aislar": False,              # el aislamiento SIEMPRE requiere humano
        "severidades": ["LOW", "MEDIUM", "HIGH", "CRITICAL"],
        "human_in_the_loop": ["propose_host_isolation"],
    }, indent=2)


@mcp.resource("soc://runbooks/{tipo}")
def runbook(tipo: str) -> str:
    """Devuelve el runbook interno para un tipo de incidente (ej: DATA_EXFILTRATION)."""
    return RUNBOOKS.get(tipo.upper(), f"No hay runbook para el tipo '{tipo}'.")


@mcp.resource("soc://tickets")
def tickets_abiertos() -> str:
    """Lista los tickets de incidente creados (leídos de la carpeta tickets/)."""
    ticks = []
    for ruta in sorted(glob.glob("tickets/*.json")):
        with open(ruta) as f:
            t = json.load(f)
        ticks.append({"id": t["id"], "severity": t["severity"],
                      "status": t["status"], "title": t["title"]})
    return json.dumps({"total": len(ticks), "tickets": ticks}, indent=2)


# ─────────────────────────────────────────────────────────────
# PROMPTS — plantillas reutilizables para tareas frecuentes
# ─────────────────────────────────────────────────────────────

@mcp.prompt()
def triage_alerta(evento: str) -> str:
    """Plantilla de triage: pide clasificar una alerta con salida estructurada."""
    return (
        "Sos un analista de un SOC. Clasificá la siguiente alerta y devolvé un JSON con:\n"
        '  {"tipo": "...", "severidad": "LOW|MEDIUM|HIGH|CRITICAL",\n'
        '   "falso_positivo_probable": true/false, "razonamiento": "...",\n'
        '   "accion_recomendada": "..."}\n'
        "Verificá la reputación de las IPs con las herramientas disponibles antes de decidir.\n\n"
        f"Alerta:\n{evento}"
    )


@mcp.prompt()
def reporte_incidente(tipo: str) -> str:
    """Plantilla para redactar el reporte final de un incidente ya investigado."""
    return (
        f"Redactá el reporte del incidente de tipo {tipo} con esta estructura fija:\n"
        "1. Resumen ejecutivo\n2. Línea de tiempo\n3. Análisis técnico\n"
        "4. Impacto\n5. IOCs\n6. Acciones tomadas\n7. Recomendaciones\n\n"
        "Usá únicamente la información recolectada durante la investigación; "
        "no inventes IOCs ni datos que no puedas verificar."
    )


if __name__ == "__main__":
    mcp.run()

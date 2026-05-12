"""
Paso 5 — MCP Tools: enriquecimiento automático.
Llama a las tools del servidor MCP para obtener
contexto adicional y documentar el incidente.
"""

import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_server import check_ip_reputation, create_incident_ticket
from pipeline.evento import EVENT

console = Console()


def _consultar_virustotal() -> dict:
    """Llama a check_ip_reputation y devuelve el resultado parseado."""
    console.print("  [cyan]→ Llamando tool: check_ip_reputation[/cyan]")
    console.print(f"  [dim]   ip = \"{EVENT['dst_ip']}\"[/dim]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Consultando VirusTotal...", total=None)
        time.sleep(1.0)
        result = json.loads(check_ip_reputation(EVENT["dst_ip"]))

    console.print(Panel(
        f"IP            : [bold]{result['ip']}[/bold]\n"
        f"Maliciosos    : [bold red]{result['malicious']}/{result['total_engines']} motores[/bold red]\n"
        f"ASN           : {result.get('asn', 'N/A')}\n"
        f"Tags          : {', '.join(result.get('tags', []))}\n"
        f"Veredicto     : [bold red]{result['verdict']}[/bold red]",
        title="[cyan]VirusTotal Response[/cyan]",
        border_style="cyan"
    ))
    console.print()
    return result


def _crear_ticket() -> dict:
    """Llama a create_incident_ticket y devuelve el resultado parseado."""
    console.print("  [cyan]→ Llamando tool: create_incident_ticket[/cyan]")
    console.print(f"  [dim]   severity = \"CRITICAL\"  |  host = \"{EVENT['hostname']}\"[/dim]")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Creando ticket de incidente...", total=None)
        time.sleep(0.6)
        result = json.loads(create_incident_ticket(
            title=f"Posible exfiltración de datos — {EVENT['hostname']}",
            severity="CRITICAL",
            affected_host=EVENT["hostname"],
            affected_user=EVENT["user"],
            description=(
                f"Transferencia de 271MB a IP maliciosa ({EVENT['dst_ip']}) "
                f"clasificada como Tor Exit Node. Detectada a las 3am desde laptop de RRHH."
            ),
            iocs=[EVENT["dst_ip"], f"port:{EVENT['dst_port']}"],
            recommended_actions=["Aislar host", "Preservar evidencia forense", "Notificar RRHH y Legal"]
        ))

    console.print(f"  [green]✓[/green] Ticket creado: [bold yellow]{result['ticket_id']}[/bold yellow] — CRITICAL")
    console.print(f"  [dim]   Guardado en tickets/{result['ticket_id']}.json[/dim]\n")
    return result


def enriquecer() -> None:
    """Ejecuta todas las MCP tools de enriquecimiento en secuencia."""
    console.rule("[bold cyan]PASO 5 — MCP Tools: enriquecimiento automático[/bold cyan]")
    console.print()

    _consultar_virustotal()
    _crear_ticket()

    time.sleep(0.5)

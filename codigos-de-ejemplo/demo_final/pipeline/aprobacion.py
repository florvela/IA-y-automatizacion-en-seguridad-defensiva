"""
Paso 6 — Human-in-the-Loop: aprobación requerida.
Propone el aislamiento del host y espera confirmación del analista.
También contiene el resumen final del pipeline.
"""

import json
import time
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from mcp_server import propose_host_isolation
from pipeline.evento import EVENT

console = Console()


def solicitar_aprobacion() -> bool:
    """
    Propone aislar el host mediante MCP y espera aprobación del analista.
    Retorna True si fue aprobado.
    """
    console.rule("[bold red]PASO 6 — Human-in-the-Loop: aprobación requerida[/bold red]")
    console.print()

    console.print("  [cyan]→ Llamando tool: propose_host_isolation[/cyan]")
    console.print(f"  [dim]   hostname = \"{EVENT['hostname']}\"  |  severity = \"CRITICAL\"[/dim]\n")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Preparando propuesta...", total=None)
        time.sleep(0.5)
        proposal = json.loads(propose_host_isolation(
            hostname=EVENT["hostname"],
            reason=(
                f"Host enviando 271MB a Tor exit node ({EVENT['dst_ip']}) a las 3am. "
                "Alta probabilidad de exfiltración activa."
            ),
            severity="CRITICAL"
        ))

    console.print(Panel(
        f"[bold red]ACCIÓN PROPUESTA: AISLAMIENTO DE HOST[/bold red]\n\n"
        f"Host     : [bold]{proposal['hostname']}[/bold]\n"
        f"Razón    : {proposal['reason']}\n"
        f"Impacto  : [yellow]{proposal['impact']}[/yellow]\n\n"
        f"[bold yellow]⚠  Esta acción requiere aprobación explícita del analista[/bold yellow]",
        border_style="red"
    ))
    console.print()

    approved = Confirm.ask("  [bold]¿Aprobar aislamiento del host?[/bold]")
    console.print()

    if approved:
        with Progress(SpinnerColumn(), TextColumn("[red]{task.description}"), TimeElapsedColumn(), transient=True) as p:
            p.add_task("Ejecutando aislamiento...", total=None)
            time.sleep(1.2)

        console.print(Panel(
            "[bold green]✓  HOST AISLADO[/bold green]\n\n"
            f"[bold]{EVENT['hostname']}[/bold] removido de la red.\n"
            "Evidencia forense preservada.\n"
            "Notificación enviada a RRHH y Legal.",
            border_style="green"
        ))
    else:
        console.print(Panel(
            f"[yellow]Aislamiento rechazado.[/yellow]\n"
            f"{EVENT['hostname']} continúa monitoreado.",
            border_style="yellow"
        ))

    console.print()
    return approved


def resumen() -> None:
    """Muestra el resumen final del pipeline."""
    console.rule("[bold]FIN DEL DEMO[/bold]")
    console.print()
    console.print(Panel(
        "Lo que acaba de pasar:\n\n"
        "[blue]ML  (Isolation Forest)[/blue]   Detectó comportamiento anómalo en el tráfico\n"
        "[magenta]NLP (TF-IDF + LR)     [/magenta]   Clasificó el evento como DATA_EXFILTRATION\n"
        "[green]LLM (Ollama local)    [/green]   Razonó sobre el contexto sin salir de tu red\n"
        "[cyan]MCP Tools             [/cyan]   Consultó VirusTotal y documentó el incidente\n"
        "[red]Human-in-the-Loop     [/red]   El analista tomó la decisión crítica final",
        title="[bold]Resumen del pipeline[/bold]",
        border_style="white"
    ))
    console.print()

"""
Orquestador de la demo.
Corre el pipeline completo paso a paso.
"""

import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ── Imports con feedback visual ───────────────────────────
with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
    p.add_task("Cargando módulos del pipeline...", total=None)
    from pipeline import evento
    from pipeline import anomalia
    from pipeline import clasificacion
    from pipeline import agente
    from pipeline import aprobacion
    time.sleep(0.3)

console.print("[green]✓[/green] Módulos cargados\n")


def main():
    console.print()
    console.print(Panel.fit(
        "[bold red]SOC AI PIPELINE[/bold red]\n"
        "[dim]ML · NLP · LLM local · MCP · Human-in-the-Loop[/dim]",
        border_style="red"
    ))
    console.print()

    input("  Presioná Enter para comenzar...\n")

    # Paso 1 — Mostrar evento
    evento.mostrar()
    input("  [Enter para continuar...]\n")

    # Paso 2 — Isolation Forest
    es_anomalia = anomalia.evaluar()
    if not es_anomalia:
        return
    input("  [Enter para continuar...]\n")

    # Paso 3 — Clasificador NLP
    tipo_evento = clasificacion.clasificar()
    input("  [Enter para continuar...]\n")

    # Pasos 4+5 — LLM + MCP real (tool-calling loop)
    agente.ejecutar(tipo_evento)
    input("  [Enter para continuar...]\n")

    # Paso 6 — Human approval + resumen
    aprobacion.solicitar_aprobacion()
    aprobacion.resumen()


if __name__ == "__main__":
    main()

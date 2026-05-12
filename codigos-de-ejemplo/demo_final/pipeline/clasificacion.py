"""
Paso 3 — Clasificador NLP: ¿qué tipo de evento?
Carga el modelo entrenado y clasifica la descripción del evento.
"""

import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from training.nlp_classifier import load
from pipeline.evento import EVENT_DESCRIPTION

console = Console()


def clasificar() -> str:
    """
    Carga el clasificador, predice la categoría del evento y muestra
    la tabla de probabilidades. Retorna la categoría predicha.
    """
    console.rule("[bold magenta]PASO 3 — Clasificador NLP: ¿qué tipo de evento?[/bold magenta]")
    console.print()

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Cargando clasificador NLP...", total=None)
        clf = load()
        time.sleep(0.4)

    console.print("  [green]✓[/green] Modelo cargado\n")
    console.print("  [dim]Descripción del evento:[/dim]")
    console.print(Panel(f"[italic]{EVENT_DESCRIPTION}[/italic]", border_style="dim"))
    console.print()

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Clasificando evento...", total=None)
        prediction = clf.predict([EVENT_DESCRIPTION])[0]
        probs      = clf.predict_proba([EVENT_DESCRIPTION])[0]
        classes    = clf.classes_
        confidence = max(probs)
        time.sleep(0.4)

    # Tabla con barras de probabilidad
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    table.add_column("Categoría",  style="cyan", width=28)
    table.add_column("Confianza",  justify="right", width=10)
    table.add_column("",           width=22)

    for cls, prob in sorted(zip(classes, probs), key=lambda x: x[1], reverse=True):
        is_top    = cls == prediction
        style     = "bold red" if is_top else "dim"
        bar_len   = int(prob * 20)
        bar       = "█" * bar_len + "░" * (20 - bar_len)
        bar_color = "red" if is_top else "dim"
        table.add_row(
            f"[{style}]{cls}[/{style}]",
            f"[{style}]{prob:.1%}[/{style}]",
            f"[{bar_color}]{bar}[/{bar_color}]"
        )

    console.print(table)
    console.print(f"\n  → Clasificación: [bold red]{prediction}[/bold red]  (confianza: {confidence:.0%})")
    console.print()
    time.sleep(0.5)

    return prediction

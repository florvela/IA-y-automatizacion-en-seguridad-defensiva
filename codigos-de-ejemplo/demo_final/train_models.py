"""
Orquestador de entrenamiento.
Entrena el Isolation Forest y el clasificador NLP en secuencia.

Requiere haber generado el dataset primero:
  python generate_data.py   ← genera CSV / NDJSON / Parquet
  python train_models.py    ← lee el Parquet y entrena
  python demo.py            ← corre el pipeline completo
"""

import time
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn

console = Console()

# ── Imports con feedback visual ───────────────────────────
with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
    p.add_task("Cargando librerías...", total=None)
    from training import isolation_forest
    from training import nlp_classifier

console.print("[green]✓[/green] Librerías cargadas\n")


if __name__ == "__main__":
    console.print()
    console.print(Panel.fit(
        "[bold white]ENTRENAMIENTO DE MODELOS[/bold white]\n"
        "[dim]SOC AI Demo — Isolation Forest + Clasificador NLP[/dim]",
        border_style="white"
    ))
    console.print()

    isolation_forest.run()
    nlp_classifier.run()

    console.print(Panel(
        "[bold green]✓  Modelos listos[/bold green]\n\n"
        "  models/isolation_forest.pkl\n"
        "  models/nlp_classifier.pkl\n\n"
        "Siguiente paso: [bold]python demo.py[/bold]",
        border_style="green"
    ))
    console.print()
    console.print()

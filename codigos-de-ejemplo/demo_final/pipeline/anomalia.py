"""
Paso 2 — Isolation Forest: ¿es una anomalía?
Carga el modelo entrenado y evalúa el evento actual.
"""

import time
import numpy as np
from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn

from data.network_traffic import FEATURES
from training.isolation_forest import load
from pipeline.evento import EVENT

console = Console()


def _event_to_features() -> np.ndarray:
    """Convierte el evento global en el vector de features que espera el modelo."""
    return np.array([[
        EVENT["bytes_sent"],
        EVENT["bytes_recv"],
        EVENT["duration"],
        EVENT["dst_port"],
        EVENT["packets_sent"],
        EVENT["packets_recv"],
        EVENT["bytes_sent"] / (EVENT["packets_sent"] + 1),
        EVENT["bytes_sent"] / (EVENT["bytes_recv"]  + 1),
    ]])


def evaluar() -> bool:
    """
    Carga el modelo, calcula el score de anomalía y muestra el resultado.
    Retorna True si el evento es anómalo.
    """
    console.rule("[bold blue]PASO 2 — Isolation Forest: ¿anomalía?[/bold blue]")
    console.print()

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Cargando modelo entrenado...", total=None)
        model = load() # carga el modelo entrenado

    console.print("  [green]✓[/green] Modelo cargado\n")

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Calculando score de anomalía...", total=None)
        x          = _event_to_features()
        score      = model.decision_function(x)[0]
        prediction = model.predict(x)[0]

    is_anomaly  = prediction == -1
    anomaly_pct = max(0, min(100, int((-score + 0.1) * 300))) # calcula el porcentaje de anomalía
    color       = "red"   if is_anomaly else "green"
    label       = "ANOMALÍA DETECTADA" if is_anomaly else "TRÁFICO NORMAL"

    # Barra visual
    filled    = int(anomaly_pct / 5)
    bar       = "█" * filled + "░" * (20 - filled)
    bar_color = "red" if anomaly_pct > 60 else "yellow" if anomaly_pct > 30 else "green"

    console.print(f"  Score de anomalía : [{bar_color}]{bar}[/{bar_color}] [bold {color}]{anomaly_pct}/100[/bold {color}]")
    console.print(f"  Veredicto         : [bold {color}]{'⚠  ' + label if is_anomaly else '✓  ' + label}[/bold {color}]")
    console.print()

    if not is_anomaly:
        console.print(Panel("[green]Pipeline detenido — tráfico normal.[/green]", border_style="green"))

    return is_anomaly

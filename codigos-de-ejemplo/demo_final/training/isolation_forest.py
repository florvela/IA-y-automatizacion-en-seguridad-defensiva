"""
Entrenamiento del modelo Isolation Forest para detección de anomalías
en tráfico de red.
"""

import os
import time
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from data.network_traffic import load_traffic, get_demo_event_features, FEATURES

console = Console()

MODEL_PATH   = "models/isolation_forest.pkl"
DATA_PATH    = "data/normal_traffic.parquet"


def build_model() -> IsolationForest:
    """Instancia el modelo con los hiperparámetros definidos."""
    return IsolationForest(
        n_estimators=200,
        contamination=0.05,
        random_state=42,
        n_jobs=-1
    )


def train(model: IsolationForest, df) -> IsolationForest:
    """Entrena el modelo sobre el dataframe de tráfico normal."""
    model.fit(df[FEATURES])
    return model


def evaluate(model: IsolationForest) -> dict:
    """
    Verifica el modelo con el evento de demo.
    Devuelve score y predicción.
    """
    sample     = get_demo_event_features()
    score      = model.decision_function(sample[FEATURES])[0]
    prediction = model.predict(sample[FEATURES])[0]
    return {"score": score, "is_anomaly": prediction == -1}


def save(model: IsolationForest, path: str = MODEL_PATH) -> None:
    """Guarda el modelo entrenado en disco."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(model, path)


def load(path: str = MODEL_PATH) -> IsolationForest:
    """Carga el modelo desde disco."""
    return joblib.load(path)


def run() -> IsolationForest:
    """
    Pipeline completo: genera datos → entrena → evalúa → guarda.
    Muestra progreso en consola.
    """
    console.rule("[bold blue]Isolation Forest[/bold blue]")
    console.print()

    # Cargar datos desde archivo Parquet
    if not os.path.exists(DATA_PATH):
        console.print(f"  [bold red]✗[/bold red] No se encontró [bold]{DATA_PATH}[/bold]")
        console.print("  Ejecutá primero: [bold]python generate_data.py[/bold]\n")
        raise FileNotFoundError(DATA_PATH)

    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task(f"Cargando dataset desde {DATA_PATH}...", total=None)
        normal = load_traffic(DATA_PATH)
        time.sleep(0.3)

    console.print(f"  [green]✓[/green] Dataset cargado desde [bold]{DATA_PATH}[/bold]: [bold]{len(normal):,} registros[/bold]")

    # Mostrar muestra
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan")
    for col in ['bytes_sent', 'bytes_recv', 'duration', 'dst_port', 'upload_ratio']:
        table.add_column(col, justify="right")
    for _, row in normal.head(5).iterrows():
        table.add_row(
            f"{row['bytes_sent']:,.0f}",
            f"{row['bytes_recv']:,.0f}",
            f"{row['duration']:.1f}s",
            str(int(row['dst_port'])),
            f"{row['upload_ratio']:.3f}",
        )
    console.print(table)
    console.print(f"  [dim]... y {len(normal) - 5:,} registros más[/dim]\n")

    # Entrenar
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Entrenando Isolation Forest (200 árboles)...", total=None)
        model = build_model()
        train(model, normal)
        time.sleep(0.3)

    console.print("  [green]✓[/green] Modelo entrenado")

    # Evaluar con evento de demo
    result = evaluate(model)
    label  = "[bold red]ANOMALÍA[/bold red]" if result["is_anomaly"] else "[bold green]NORMAL[/bold green]"
    console.print(f"  [green]✓[/green] Verificación con evento de demo:")
    console.print(f"      Score    : [bold]{result['score']:.4f}[/bold]  (negativo = más anómalo)")
    console.print(f"      Resultado: {label}\n")

    # Guardar
    save(model)
    console.print(f"  [green]✓[/green] Guardado en [bold]{MODEL_PATH}[/bold]\n")

    return model

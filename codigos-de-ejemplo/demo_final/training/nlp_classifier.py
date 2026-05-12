"""
Entrenamiento del clasificador NLP para categorización de eventos de seguridad.
Usa TF-IDF + Regresión Logística.
"""

import os
import time
import joblib
import numpy as np
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.pipeline import Pipeline
from sklearn.model_selection import train_test_split
from rich.console import Console
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

from data.security_events import get_training_data

console = Console()

MODEL_PATH = "models/nlp_classifier.pkl"


def build_pipeline() -> Pipeline:
    """Instancia el pipeline TF-IDF + LogisticRegression."""
    return Pipeline([
        ('tfidf', TfidfVectorizer(
            ngram_range=(1, 3),
            max_features=5000,
            sublinear_tf=True
        )),
        ('clf', LogisticRegression(
            max_iter=1000,
            C=1.0,
            random_state=42
        ))
    ])


def train(pipeline: Pipeline, texts: list, labels: list) -> tuple[Pipeline, dict]:
    """
    Entrena el pipeline y devuelve el modelo y métricas de evaluación.
    """
    X_train, X_test, y_train, y_test = train_test_split(
        texts, labels,
        test_size=0.2,
        random_state=42,
        stratify=labels
    )
    pipeline.fit(X_train, y_train)

    y_pred   = pipeline.predict(X_test)
    accuracy = (np.array(y_pred) == np.array(y_test)).mean()

    metrics = {
        "accuracy":  accuracy,
        "n_train":   len(X_train),
        "n_test":    len(X_test),
        "X_test":    X_test,
        "y_test":    y_test,
        "y_pred":    y_pred,
    }
    return pipeline, metrics


def save(pipeline: Pipeline, path: str = MODEL_PATH) -> None:
    """Guarda el pipeline entrenado en disco."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    joblib.dump(pipeline, path)


def load(path: str = MODEL_PATH) -> Pipeline:
    """Carga el pipeline desde disco."""
    return joblib.load(path)


def run() -> Pipeline:
    """
    Pipeline completo: carga datos → entrena → evalúa → guarda.
    Muestra progreso en consola.
    """
    console.rule("[bold magenta]Clasificador NLP[/bold magenta]")
    console.print()

    texts, labels = get_training_data()

    # Distribución del dataset
    dist  = Counter(labels)
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold magenta")
    table.add_column("Categoría", style="cyan")
    table.add_column("Ejemplos",  justify="right")
    for cat, count in sorted(dist.items()):
        table.add_row(cat, str(count))
    table.add_row("[bold]TOTAL[/bold]", f"[bold]{len(texts)}[/bold]")
    console.print(table)
    console.print()

    # Entrenar
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task("Vectorizando con TF-IDF y entrenando clasificador...", total=None)
        pipeline = build_pipeline()
        pipeline, metrics = train(pipeline, texts, labels)
        time.sleep(0.3)

    console.print(f"  [green]✓[/green] Train: [bold]{metrics['n_train']}[/bold] ejemplos  |  Test: [bold]{metrics['n_test']}[/bold] ejemplos")
    console.print(f"  [green]✓[/green] Accuracy: [bold green]{metrics['accuracy']:.0%}[/bold green]\n")

    # Muestra de predicciones
    console.print("  [dim]Ejemplos del test set:[/dim]")
    pred_table = Table(box=box.SIMPLE, show_header=True, header_style="dim")
    pred_table.add_column("Texto",    style="white", max_width=50)
    pred_table.add_column("Real",     style="cyan",  justify="center")
    pred_table.add_column("Predicho", justify="center")
    for text, real, pred in zip(metrics["X_test"][:5], metrics["y_test"][:5], metrics["y_pred"][:5]):
        color = "green" if real == pred else "red"
        pred_table.add_row(
            text[:50] + "...",
            real.replace("_", " "),
            f"[{color}]{pred.replace('_', ' ')}[/{color}]"
        )
    console.print(pred_table)
    console.print()

    # Guardar
    save(pipeline)
    console.print(f"  [green]✓[/green] Guardado en [bold]{MODEL_PATH}[/bold]\n")

    return pipeline

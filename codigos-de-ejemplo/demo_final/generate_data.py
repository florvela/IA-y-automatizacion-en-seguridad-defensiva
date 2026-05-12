"""
Generación del dataset de tráfico de red y guardado en múltiples formatos.

Demuestra el manejo de archivos grandes en entornos de seguridad:
  - CSV    : legible, portable, fácil de abrir en Excel o compartir
  - NDJSON : un JSON por línea — estándar en logs de SIEMs (Splunk, Elastic)
  - Parquet: columnar + comprimido — óptimo para ML y análisis de grandes volúmenes

Paso previo a train_models.py.
"""

import os
import time
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.progress import Progress, SpinnerColumn, TextColumn, TimeElapsedColumn
from rich import box

console = Console()

with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), transient=True) as p:
    p.add_task("Cargando librerías...", total=None)
    from data.network_traffic import (
        generate_normal_traffic,
        save_as_csv,
        save_as_ndjson,
        save_as_parquet,
    )

console.print("[green]✓[/green] Librerías cargadas\n")

N_RECORDS   = 5_000
CSV_PATH     = "data/normal_traffic.csv"
NDJSON_PATH  = "data/normal_traffic.ndjson"
PARQUET_PATH = "data/normal_traffic.parquet"


def _file_kb(path: str) -> str:
    size = os.path.getsize(path)
    if size < 1024:
        return f"{size} B"
    elif size < 1024 ** 2:
        return f"{size / 1024:.1f} KB"
    else:
        return f"{size / 1024**2:.1f} MB"


def run() -> None:
    console.rule("[bold blue]Generación de Dataset[/bold blue]")
    console.print()

    # ── Generar datos ────────────────────────────────────────
    with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
        p.add_task(f"Generando {N_RECORDS:,} registros de tráfico normal...", total=None)
        df = generate_normal_traffic(N_RECORDS)
        time.sleep(0.4)

    console.print(f"  [green]✓[/green] Dataset generado: [bold]{len(df):,} registros × {len(df.columns)} columnas[/bold]\n")

    # ── Preview ──────────────────────────────────────────────
    table = Table(box=box.SIMPLE, show_header=True, header_style="bold cyan", title="Primeras 5 filas")
    for col in df.columns:
        table.add_column(col, justify="right")
    for _, row in df.head(5).iterrows():
        table.add_row(*[f"{v:.2f}" if isinstance(v, float) else str(int(v)) for v in row])
    console.print(table)
    console.print()

    # ── Guardar en los tres formatos ─────────────────────────
    console.print("  Guardando en múltiples formatos...\n")

    formats = [
        ("CSV",     CSV_PATH,     save_as_csv,     "legible, portable, fácil de abrir con Excel"),
        ("NDJSON",  NDJSON_PATH,  save_as_ndjson,  "un JSON por línea — estándar en SIEMs (Splunk, Elastic)"),
        ("Parquet", PARQUET_PATH, save_as_parquet, "columnar + comprimido — óptimo para ML"),
    ]

    for fmt_name, path, save_fn, description in formats:
        with Progress(SpinnerColumn(), TextColumn("[cyan]{task.description}"), TimeElapsedColumn(), transient=True) as p:
            p.add_task(f"Escribiendo {fmt_name}...", total=None)
            save_fn(df, path)
            time.sleep(0.2)
        console.print(f"  [green]✓[/green] [bold]{fmt_name:7}[/bold]  {path}  [dim]({_file_kb(path)})[/dim]")
        console.print(f"           [dim]→ {description}[/dim]")

    # ── Comparación de tamaños ───────────────────────────────
    console.print()
    sizes = Table(box=box.SIMPLE, show_header=True, header_style="bold yellow", title="Comparación de tamaños")
    sizes.add_column("Formato",  style="bold")
    sizes.add_column("Tamaño",   justify="right")
    sizes.add_column("Caso de uso en seguridad")
    sizes.add_row("CSV",     _file_kb(CSV_PATH),     "exportar reportes, compartir con otros equipos")
    sizes.add_row("NDJSON",  _file_kb(NDJSON_PATH),  "ingestar logs de SIEM, streaming de eventos")
    sizes.add_row("Parquet", _file_kb(PARQUET_PATH), "entrenar modelos ML, análisis histórico")
    console.print(sizes)
    console.print()

    console.print(Panel(
        "[bold green]✓  Dataset listo[/bold green]\n\n"
        f"  data/normal_traffic.csv\n"
        f"  data/normal_traffic.ndjson\n"
        f"  data/normal_traffic.parquet\n\n"
        "Siguiente paso: [bold]python train_models.py[/bold]",
        border_style="green"
    ))
    console.print()


if __name__ == "__main__":
    console.print()
    console.print(Panel.fit(
        "[bold white]GENERACIÓN DE DATOS[/bold white]\n"
        "[dim]SOC AI Demo — Tráfico de red en CSV · NDJSON · Parquet[/dim]",
        border_style="white"
    ))
    console.print()
    run()

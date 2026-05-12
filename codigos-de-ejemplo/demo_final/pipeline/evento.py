"""
Paso 1 — Evento entrante.
Define el evento de demo y lo muestra en pantalla.
"""

import time
from rich.console import Console
from rich.table import Table
from rich import box

console = Console()

# ─────────────────────────────────────────────────────────
# Evento sospechoso — fuente de verdad compartida por todo el pipeline
# ─────────────────────────────────────────────────────────

EVENT = {
    "timestamp":    "2024-01-15 03:47:23",
    "src_ip":       "192.168.1.105",
    "dst_ip":       "185.220.101.47",
    "dst_port":     9001,
    "protocol":     "TCP",
    "bytes_sent":   284_739_200,   # ~271 MB outbound
    "bytes_recv":   1_024,
    "duration":     847,           # ~14 minutos
    "packets_sent": 189_340,
    "packets_recv": 12,
    "hostname":     "LAPTOP-HR-MARIA",
    "user":         "maria.garcia",
    "process":      "chrome.exe",
}

# Descripción textual para el clasificador NLP
EVENT_DESCRIPTION = (
    "Large outbound data transfer to external IP, 271MB sent in 14 minutes "
    "to unknown destination. Encrypted channel with very low inbound traffic. "
    "Connection at 3am from HR workstation to suspicious port 9001."
)

# Campos que se destacan en rojo por ser sospechosos
SUSPICIOUS_FIELDS = {"bytes_sent", "dst_ip", "dst_port", "duration", "timestamp"}


def mostrar() -> None:
    """Muestra el evento entrante en pantalla con campos sospechosos resaltados."""
    console.rule("[bold yellow]PASO 1 — Evento entrante[/bold yellow]")
    console.print()
    console.print("  [dim]Nuevo evento recibido del sensor de red...[/dim]")
    console.print()
    time.sleep(0.5)

    table = Table(box=box.ROUNDED, border_style="yellow", show_header=False)
    table.add_column("Campo", style="bold cyan", width=18)
    table.add_column("Valor", style="white")

    display = dict(EVENT)
    display["bytes_sent"] = f"{EVENT['bytes_sent']:,} bytes  (~{EVENT['bytes_sent'] / 1e6:.0f} MB)"

    for k, v in display.items():
        style = "bold red" if k in SUSPICIOUS_FIELDS else "white"
        table.add_row(k, f"[{style}]{v}[/{style}]")

    console.print(table)
    console.print()
    console.print("  [dim]Campos en rojo: fuera del patrón esperado[/dim]")
    console.print()
    time.sleep(0.5)

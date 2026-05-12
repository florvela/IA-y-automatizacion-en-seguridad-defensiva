"""
Paso 4 — LLM (Ollama local): análisis y razonamiento.
Construye el prompt con el contexto del evento y hace streaming
de la respuesta token por token.
"""

import ollama
from rich.console import Console
from rich.panel import Panel
from rich.live import Live

from pipeline.evento import EVENT

console = Console()

OLLAMA_MODEL = "llama3.2"


def _build_prompt(event_type: str) -> str:
    return f"""You are a SOC analyst. Analyze this security alert concisely.

Event type: {event_type}
Timestamp: {EVENT['timestamp']}
Source: {EVENT['src_ip']} ({EVENT['hostname']}, user: {EVENT['user']})
Destination: {EVENT['dst_ip']}:{EVENT['dst_port']}
Outbound: {EVENT['bytes_sent'] / 1e6:.0f}MB  |  Inbound: {EVENT['bytes_recv']} bytes
Duration: {EVENT['duration']}s  |  Process: {EVENT['process']}

Provide:
1. What likely happened (2 sentences)
2. Why this is suspicious (3 bullet points)
3. Immediate actions (2-3 items)

Be direct. No preamble."""


def analizar(event_type: str) -> str:
    """
    Llama a Ollama con el contexto del evento y hace streaming
    de la respuesta en pantalla. Retorna el texto completo generado.
    """
    console.rule("[bold green]PASO 4 — LLM Ollama (local): análisis y razonamiento[/bold green]")
    console.print()
    console.print(f"  [dim]{OLLAMA_MODEL} corriendo localmente — generando análisis...[/dim]\n")

    prompt    = _build_prompt(event_type)
    full_text = ""

    with Live(console=console, refresh_per_second=15) as live:
        stream = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[{"role": "user", "content": prompt}],
            options={"temperature": 0.1},
            stream=True
        )
        for chunk in stream:
            token      = chunk["message"]["content"]
            full_text += token
            live.update(Panel(
                full_text,
                title="[bold green]Análisis del LLM[/bold green]",
                border_style="green"
            ))

    console.print()
    return full_text

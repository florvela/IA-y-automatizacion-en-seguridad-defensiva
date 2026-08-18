"""
Pasos 4+5 — LLM + MCP real: el modelo decide qué tools llamar.

Flujo MCP real:
  1. mcp_server.py se levanta como subproceso (stdio transport)
  2. El cliente MCP se conecta y obtiene las tools disponibles
  3. Se convierten al formato de Ollama y se le pasan al LLM
  4. Ollama decide qué tools llamar según el contexto del evento
  5. Cada tool call se enruta al servidor MCP (no se llama directo)
  6. El resultado vuelve al LLM para continuar el razonamiento
  7. Cuando el LLM no llama más tools, devuelve el análisis final
"""

import asyncio
import json
import sys
from pathlib import Path

import ollama
from mcp import ClientSession, StdioServerParameters
from mcp.client.stdio import stdio_client
from rich.console import Console
from rich.panel import Panel

from pipeline.evento import EVENT

console = Console()

OLLAMA_MODEL  = "llama3.2"
MCP_SERVER    = str(Path(__file__).parent.parent / "mcp_server.py")

# propose_host_isolation la maneja aprobacion.py — no se la pasamos al LLM acá
EXCLUDED_TOOLS = {"propose_host_isolation"}


def _to_ollama_tool(tool) -> dict:
    """Convierte una tool MCP al formato que espera Ollama."""
    return {
        "type": "function",
        "function": {
            "name":        tool.name,
            "description": tool.description,
            "parameters":  tool.input_schema,
        },
    }


def _build_prompt(event_type: str) -> str:
    return f"""You are a SOC analyst investigating a security alert classified as {event_type}.

Use the available tools to:
1. Check the reputation of the destination IP
2. If it is malicious, create an incident ticket with all relevant details

Alert:
- Source  : {EVENT['src_ip']} ({EVENT['hostname']}, user: {EVENT['user']})
- Dest    : {EVENT['dst_ip']}:{EVENT['dst_port']}
- Outbound: {EVENT['bytes_sent'] / 1e6:.0f} MB in {EVENT['duration']}s
- Inbound : {EVENT['bytes_recv']} bytes
- Process : {EVENT['process']}
- Time    : {EVENT['timestamp']}

After using the tools, give a concise analysis (3-4 sentences) of what happened and why it is suspicious."""


async def _run(event_type: str) -> tuple[str, str | None]:
    """
    Levanta el servidor MCP, conecta el cliente, corre el loop de tool calling.
    Retorna (análisis_final, ticket_id | None).
    """
    server_params = StdioServerParameters(
        command=sys.executable,
        args=[MCP_SERVER],
    )

    async with stdio_client(server_params) as (read, write):
        async with ClientSession(read, write) as session:
            await session.initialize()

            # Obtener tools del servidor MCP y filtrar las que no corresponden a este paso
            mcp_tools   = (await session.list_tools()).tools
            tools       = [_to_ollama_tool(t) for t in mcp_tools if t.name not in EXCLUDED_TOOLS]

            console.print(f"  [green]✓[/green] Servidor MCP conectado — [bold]{len(tools)} tools disponibles[/bold]")
            for t in mcp_tools:
                if t.name not in EXCLUDED_TOOLS:
                    console.print(f"  [dim]   · {t.name}[/dim]")
            console.print()

            messages  = [{"role": "user", "content": _build_prompt(event_type)}]
            ticket_id = None

            # ── Tool-calling loop ────────────────────────────────────────────
            # El LLM llama tools hasta que no necesite más; entonces responde.
            while True:
                response = ollama.chat(
                    model=OLLAMA_MODEL,
                    messages=messages,
                    tools=tools,
                    options={"temperature": 0.1},
                )
                msg = response.message

                # Agregar respuesta del asistente al historial
                messages.append({
                    "role":       "assistant",
                    "content":    msg.content or "",
                    "tool_calls": [
                        {"function": {"name": tc.function.name, "arguments": tc.function.arguments}}
                        for tc in (msg.tool_calls or [])
                    ],
                })

                if not msg.tool_calls:
                    # Sin más tool calls → respuesta final del LLM
                    return msg.content or "", ticket_id

                # Ejecutar cada tool call via MCP
                for tc in msg.tool_calls:
                    name = tc.function.name
                    args = tc.function.arguments

                    console.print(f"  [cyan]→ LLM llama tool: [bold]{name}[/bold][/cyan]")
                    console.print(f"  [dim]   {json.dumps(args, ensure_ascii=False)}[/dim]")

                    mcp_result  = await session.call_tool(name, args)
                    result_text = mcp_result.content[0].text if mcp_result.content else "{}"

                    # Capturar ticket_id si lo hay
                    try:
                        if "ticket_id" in (parsed := json.loads(result_text)):
                            ticket_id = parsed["ticket_id"]
                    except Exception:
                        pass

                    preview = result_text[:120] + ("..." if len(result_text) > 120 else "")
                    console.print(f"  [dim]   ← {preview}[/dim]\n")

                    messages.append({"role": "tool", "content": result_text})

    return "", None


def ejecutar(event_type: str) -> tuple[str, str | None]:
    """
    Punto de entrada sincrónico para demo.py.
    Retorna (análisis_final, ticket_id).
    """
    console.rule("[bold green]PASOS 4+5 — LLM + MCP: el modelo decide qué tools llamar[/bold green]")
    console.print()
    console.print(f"  [dim]{OLLAMA_MODEL} + MCP server (stdio) — iniciando agente...[/dim]\n")

    analysis, ticket_id = asyncio.run(_run(event_type))

    if analysis:
        console.print(Panel(
            analysis,
            title="[bold green]Análisis del LLM[/bold green]",
            border_style="green",
        ))
        console.print()

    if ticket_id:
        console.print(f"  [green]✓[/green] Ticket creado: [bold yellow]{ticket_id}[/bold yellow]")
        console.print(f"  [dim]   Guardado en tickets/{ticket_id}.json[/dim]\n")

    return analysis, ticket_id

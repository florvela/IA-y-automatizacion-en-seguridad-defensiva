"""
Cliente MCP (Model Context Protocol) sobre streamable-http.

# MCP es un protocolo estándar para tools / resources / prompts.
# Nuestro servidor MCP corre como servicio aparte; acá nos conectamos como cliente.
# Sesión: list_tools(), call_tool(), read_resource(), get_prompt().
"""
from __future__ import annotations

from contextlib import asynccontextmanager

# mcp 2.0 trae un cliente de alto nivel (Client) que acepta la URL directo
# y ya hace connect + initialize por nosotros.
from mcp import Client

from .config import settings


@asynccontextmanager
async def mcp_session(url: str | None = None):
    """
    Context manager async que entrega un cliente MCP ya conectado.

    Uso:
        async with mcp_session() as session:
            tools = await session.list_tools()
            result = await session.call_tool("check_ip_reputation", {"ip": "1.2.3.4"})
    """
    target = url or settings.mcp_url
    async with Client(target) as client:
        yield client


def tool_to_openai_spec(tool) -> dict:
    """Convierte una tool MCP al formato de 'function calling' que esperan los LLMs."""
    # mcp 2.0 usa 'input_schema'; versiones 1.x usaban 'inputSchema'. Soportamos ambos.
    schema = getattr(tool, "input_schema", None) or getattr(tool, "inputSchema", None)
    return {
        "type": "function",
        "function": {
            "name": tool.name,
            "description": tool.description or "",
            "parameters": schema or {"type": "object", "properties": {}},
        },
    }


def result_text(call_result) -> str:
    """Extrae el texto de un CallToolResult MCP (que puede traer varios bloques)."""
    if not call_result.content:
        return "{}"
    parts = [c.text for c in call_result.content if getattr(c, "text", None)]
    return "\n".join(parts) if parts else "{}"


def resource_text(read_result) -> str:
    """Extrae texto de un ReadResourceResult."""
    parts: list[str] = []
    for c in getattr(read_result, "contents", None) or []:
        text = getattr(c, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def prompt_text(prompt_result) -> str:
    """Extrae el texto de un GetPromptResult (mensajes del prompt)."""
    parts: list[str] = []
    for msg in getattr(prompt_result, "messages", None) or []:
        content = getattr(msg, "content", None)
        if content is None and isinstance(msg, dict):
            content = msg.get("content")
        if isinstance(content, str):
            parts.append(content)
        elif content is not None:
            text = getattr(content, "text", None)
            if text:
                parts.append(text)
            elif isinstance(content, dict) and content.get("text"):
                parts.append(str(content["text"]))
    return "\n".join(parts)

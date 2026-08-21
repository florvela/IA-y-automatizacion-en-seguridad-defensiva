"""
Agente de investigación: el LLM decide qué tools MCP llamar.

# El enrichment de IP (VirusTotal sim) ya vino del worker SOC — la IA no lo repite.
# Solo interpreta el contexto y puede usar tools de historial / ticket.
# Además el agente pide 1 resource + 1 prompt MCP (el LLM no los “elige”: el código los carga).
"""
from __future__ import annotations

import asyncio
import json

from .config import settings
from .llm import LLMBackend, get_backend
from .mcp_client import mcp_session, prompt_text, resource_text, result_text, tool_to_openai_spec
from .models import Alert, Incident, IPReputation
from .pre_enrichment import ensure_pre_enrichment, format_pre_ia_context
from .scoring import apply_score_to_incident, format_score_section

ACTION_TOOLS = {"block_ip"}
SKIP_WHEN_PREENRICHED = {"check_ip_reputation", "geolocate_ip"}

MAX_STEPS = 6
MCP_BLACKLIST_URI = "soc://lab/blacklist"
MCP_INVESTIGATE_PROMPT = "investigate_ssh_alert"

SYSTEM_PROMPT = (
    "You are a SOC analyst assistant investigating a security alert. "
    "IP reputation and geolocation were ALREADY collected by the SOC worker "
    "before you — do NOT re-query them. Use the PRE-IA CONTEXT provided. "
    "Use remaining tools only if needed (user login history, incident ticket). "
    "Do not take any blocking action yourself; only investigate and report. "
    "When done, give a concise analysis in 3-4 sentences in Spanish."
)


def _build_user_prompt(alert: Alert, pre_ia_context: str, mcp_prompt: str = "") -> str:
    base = (
        f"Security alert to investigate:\n"
        f"- Rule: {alert.rule_id} ({alert.rule_description}), level {alert.level}\n"
        f"- Source IP: {alert.src_ip}\n"
        f"- Target host: {alert.dst_host}\n"
        f"- Target user: {alert.user}\n"
        f"- Time: {alert.timestamp}\n"
    )
    if mcp_prompt:
        base += f"\n--- MCP PROMPT ({MCP_INVESTIGATE_PROMPT}) ---\n{mcp_prompt}\n"
    if pre_ia_context:
        base += f"\n--- DATA RECIBIDA EN EL TICKET (pre-IA, determinista) ---\n{pre_ia_context}\n"
    return base


async def _fetch_mcp_context(session, alert: Alert, incident: Incident) -> str:
    """Resource + prompt MCP (no son tool-calls; el agente los pide explícito)."""
    mcp_prompt_body = ""
    try:
        res = await session.read_resource(MCP_BLACKLIST_URI)
        bl = resource_text(res)
        n_lines = len([ln for ln in bl.splitlines() if ln.strip() and not ln.strip().startswith("#")])
        incident.log(f"MCP resource {MCP_BLACKLIST_URI} leído ({n_lines} entradas)")
    except Exception as exc:  # noqa: BLE001
        incident.log(f"MCP resource {MCP_BLACKLIST_URI} no disponible: {exc}")

    try:
        pr = await session.get_prompt(
            MCP_INVESTIGATE_PROMPT,
            {"src_ip": alert.src_ip or "0.0.0.0", "user": alert.user or "unknown"},
        )
        mcp_prompt_body = prompt_text(pr)
        incident.log(f"MCP prompt {MCP_INVESTIGATE_PROMPT} aplicado")
    except Exception as exc:  # noqa: BLE001
        incident.log(f"MCP prompt {MCP_INVESTIGATE_PROMPT} no disponible: {exc}")
    return mcp_prompt_body


async def investigate(
    alert: Alert, incident: Incident | None = None, backend: LLMBackend | None = None
) -> Incident:
    incident = incident or Incident(id=alert.id, alert=alert)
    ensure_pre_enrichment(incident)

    backend = backend or get_backend()
    incident.log(f"Investigación automática iniciada (backend LLM: {settings.llm_backend})")

    has_pre_rep = incident.enrichment.ip_reputation is not None

    async with mcp_session() as session:
        mcp_prompt_body = await _fetch_mcp_context(session, alert, incident)

        mcp_tools = (await session.list_tools()).tools
        exposed = [t for t in mcp_tools if t.name not in ACTION_TOOLS]
        if has_pre_rep:
            exposed = [t for t in exposed if t.name not in SKIP_WHEN_PREENRICHED]
        tools_spec = [tool_to_openai_spec(t) for t in exposed]
        incident.log(
            f"MCP conectado — {len(exposed)} tools expuestas"
            + (" (reputación/geo omitidas: ya en ticket)" if has_pre_rep else "")
        )

        messages = [
            {"role": "system", "content": SYSTEM_PROMPT},
            {
                "role": "user",
                "content": _build_user_prompt(
                    alert, incident.pre_ia_context, mcp_prompt=mcp_prompt_body
                ),
            },
        ]
        context = {
            "alert": alert.model_dump(),
            "pre_enrichment": incident.enrichment.ip_reputation.model_dump()
            if incident.enrichment.ip_reputation
            else {},
            "pre_ia_context": incident.pre_ia_context,
        }

        for _ in range(MAX_STEPS):
            # chat() es sync (ollama/openai); no bloquear el event loop del bridge.
            resp = await asyncio.to_thread(backend.chat, messages, tools_spec, context)

            messages.append(
                {
                    "role": "assistant",
                    "content": resp.content or "",
                    "tool_calls": [
                        {"function": {"name": tc.name, "arguments": tc.arguments}}
                        for tc in resp.tool_calls
                    ],
                }
            )

            if not resp.tool_calls:
                incident.analysis = resp.content
                break

            for tc in resp.tool_calls:
                incident.log(f"LLM llama tool: {tc.name}({json.dumps(tc.arguments, ensure_ascii=False)})")
                call_result = await session.call_tool(tc.name, tc.arguments)
                text = result_text(call_result)
                _absorb_result(incident, tc.name, text)
                messages.append({"role": "tool", "content": text})

    # Scoring multi-señal (alerta+usuario+activo+contexto+intel) → decide la cola.
    score_result = apply_score_to_incident(incident)
    incident.pre_ia_context = (
        format_pre_ia_context(incident) + format_score_section(score_result)
    )

    if incident.proposed_action and not settings.auto_block_low_risk:
        incident.status = "awaiting_approval"
        incident.log(
            f"Acción propuesta: {incident.proposed_action} "
            f"(score {incident.risk_score}/100) — ESPERANDO APROBACIÓN HUMANA"
        )
    elif incident.proposed_action:
        incident.log(
            f"Acción propuesta: {incident.proposed_action} "
            f"(score {incident.risk_score}/100, auto-aprobación habilitada)"
        )
    else:
        incident.status = "closed"
        incident.log(
            f"Score {incident.risk_score}/100 (bajo) — sin acción bloqueante; cola diferida"
        )

    return incident


def _absorb_result(incident: Incident, tool_name: str, text: str) -> None:
    try:
        data = json.loads(text)
    except (json.JSONDecodeError, TypeError):
        incident.enrichment.notes.append(f"{tool_name}: {text[:200]}")
        return

    if tool_name == "check_ip_reputation":
        incident.enrichment.ip_reputation = IPReputation(**data)
    elif tool_name == "get_user_login_history":
        incident.enrichment.user_history = data
    elif tool_name == "create_incident_ticket":
        incident.ticket_id = data.get("ticket_id")

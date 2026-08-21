"""
Generación del reporte de incidente en Markdown.
"""
from __future__ import annotations

from .models import Incident


def build_report(incident: Incident) -> str:
    a = incident.alert
    rep = incident.enrichment.ip_reputation

    lines = [
        f"# Incidente {incident.id}",
        "",
        f"- **Estado:** {incident.status}",
        f"- **Riesgo:** {incident.risk.upper()}"
        + (f" (score {incident.risk_score}/100)" if incident.risk_score else ""),
        f"- **Ticket:** {incident.ticket_id or '—'}",
        "",
        "## DATA RECIBIDA EN EL TICKET",
        "",
        incident.pre_ia_context or _fallback_data_recibida(incident),
        "",
        "## RESOLUCION",
        "",
        incident.analysis or "_(sin análisis de IA)_",
        "",
    ]

    if incident.proposed_action:
        lines += [
            f"**Acción propuesta:** `{incident.proposed_action}`",
            "",
            "Estado HITL: **esperando aprobación humana**"
            if incident.status == "awaiting_approval"
            else f"Estado HITL: **{incident.status}**",
            "",
        ]
    elif incident.status == "actioned":
        lines += ["**Acción ejecutada** tras aprobación humana.", ""]

    if rep and not incident.pre_ia_context:
        lines += [
            "## Reputación de la IP",
            "",
            f"- Blacklisteada: **{'SÍ' if rep.blacklisted else 'no'}**",
            f"- Score: **{rep.score}/100**",
            "",
        ]

    if incident.enrichment.user_history:
        lines += ["## Historial de usuario (IA)", "", f"```\n{incident.enrichment.user_history}\n```", ""]

    lines += ["## Línea de tiempo", ""]
    for ev in incident.timeline:
        lines.append(f"- `{ev['ts']}` {ev['msg']}")

    return "\n".join(lines)


def build_closure_report(incident: Incident, approver: str = "analyst") -> str:
    base = build_report(incident)
    extra = [
        "",
        "## Cierre",
        "",
        f"- **Aprobado por:** {approver}",
        f"- **Acción ejecutada:** {incident.proposed_action or '—'}",
        "- **Reporte generado automáticamente** tras aprobación humana.",
    ]
    return base + "\n".join(extra)


def _fallback_data_recibida(incident: Incident) -> str:
    a = incident.alert
    return (
        f"Regla Wazuh: {a.rule_id} — {a.rule_description}\n"
        f"IP origen: {a.src_ip} | Host: {a.dst_host} | Usuario: {a.user}"
    )

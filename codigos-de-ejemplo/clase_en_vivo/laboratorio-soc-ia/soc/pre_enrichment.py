"""
Helpers para aplicar enrichment previo a la IA y formatear el ticket.
"""
from __future__ import annotations

from .enrichment import enrich_ip, parse_enrichment_blob
from .models import Alert, Incident, IPReputation


def apply_pre_enrichment(incident: Incident, enrichment_raw: object) -> None:
    """Mete en el incidente el enrichment determinista (worker / fallback)."""
    blob = parse_enrichment_blob(enrichment_raw)
    if not blob:
        blob = enrich_ip(incident.alert.src_ip)

    rep_data = blob.get("ip_reputation") or blob
    if isinstance(rep_data, dict) and "score" in rep_data:
        incident.enrichment.ip_reputation = IPReputation(**rep_data)

    geo = blob.get("geolocation")
    if geo:
        incident.enrichment.notes.append(f"Geolocalización (pre-IA): {geo}")

    source = blob.get("source", "soc-worker")
    incident.log(f"Enrichment determinista aplicado (fuente: {source})")
    incident.pre_ia_context = format_pre_ia_context(incident)


def ensure_pre_enrichment(incident: Incident) -> None:
    """Si no vino del worker, enriquecemos nosotros (fallback Wazuh directo)."""
    if incident.enrichment.ip_reputation:
        if not incident.pre_ia_context:
            incident.pre_ia_context = format_pre_ia_context(incident)
        return
    apply_pre_enrichment(incident, enrich_ip(incident.alert.src_ip))
    incident.log("Enrichment aplicado en bridge (fallback sin worker)")


def format_pre_ia_context(incident: Incident) -> str:
    a = incident.alert
    lines = [
        f"Regla Wazuh: {a.rule_id} — {a.rule_description} (nivel {a.level})",
        f"IP origen: {a.src_ip}",
        f"Host objetivo: {a.dst_host}",
        f"Usuario objetivo: {a.user or '—'}",
        f"Hora alerta: {a.timestamp}",
    ]
    rep = incident.enrichment.ip_reputation
    if rep:
        lines += [
            "",
            "Reputación IP (lookup determinista — simula VirusTotal/AbuseIPDB):",
            f"  - Score: {rep.score}/100",
            f"  - Blacklisteada: {'SÍ' if rep.blacklisted else 'no'}",
            f"  - Fuentes: {', '.join(rep.sources) or '—'}",
            f"  - País: {rep.country or '—'}",
        ]
    for note in incident.enrichment.notes:
        lines.append(f"  - {note}")
    return "\n".join(lines)


def parse_enriched_payload(payload: dict) -> tuple[Alert, dict | None]:
    """Interpreta el body que manda el worker SOC ({wazuh_alert, enrichment})."""
    if "wazuh_alert" in payload:
        alert = _alert_from_payload(payload["wazuh_alert"])
        return alert, payload.get("enrichment")

    if "alert" in payload and isinstance(payload["alert"], dict):
        inner = payload["alert"]
        if "src_ip" in inner and "rule_id" in inner:
            return Alert(**inner), payload.get("enrichment")
        return _alert_from_payload(inner), payload.get("enrichment")

    if "src_ip" in payload and "rule_id" in payload:
        return Alert(**payload), payload.get("enrichment")

    from .wazuh import alert_from_wazuh  # noqa: PLC0415

    return alert_from_wazuh(payload), payload.get("enrichment")


def _alert_from_payload(data: dict) -> Alert:
    from .wazuh import alert_from_wazuh  # noqa: PLC0415

    if "src_ip" in data and "rule_id" in data:
        return Alert(**data)
    return alert_from_wazuh(data)


def parse_shuffle_payload(payload: dict) -> tuple[Alert, dict | None]:
    """Alias legacy (Shuffle eliminado del lab)."""
    return parse_enriched_payload(payload)

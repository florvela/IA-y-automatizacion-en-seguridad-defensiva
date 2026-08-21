"""
Notificación por email al analista (después de la investigación con IA).

# El mail incluye DATA RECIBIDA + RESOLUCION + link al ticket en el dashboard.
# Sin SMTP: escribe .eml en disco para la demo.
"""
from __future__ import annotations

import smtplib
from email.message import EmailMessage
from pathlib import Path

from .config import settings
from .models import Incident, now_iso


def _mailbox_dir() -> Path:
    p = Path(settings.state_dir) / "mailbox"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _reports_dir() -> Path:
    p = Path(settings.state_dir) / "reports"
    p.mkdir(parents=True, exist_ok=True)
    return p


def _incident_url(incident_id: str) -> str:
    base = settings.dashboard_url.rstrip("/")
    return f"{base}/incidents/{incident_id}"


def build_alert_email(incident: Incident) -> EmailMessage:
    """Mail L1 post-investigación: contexto + resolución IA + link."""
    a = incident.alert
    url = _incident_url(incident.id)
    msg = EmailMessage()
    msg["Subject"] = (
        f"[SOC][{incident.risk.upper()}][{incident.risk_score}] "
        f"SSH brute force desde {a.src_ip} — revisar incidente"
    )
    msg["From"] = settings.email_from
    msg["To"] = settings.email_to

    action_line = (
        f"IA propone: {incident.proposed_action} — ESPERANDO TU APROBACIÓN."
        if incident.status == "awaiting_approval"
        else f"Estado: {incident.status} — sin acción bloqueante pendiente."
    )

    msg.set_content(
        f"Hola,\n\n"
        f"Se detectó actividad sospechosa (regla Wazuh {a.rule_id}).\n\n"
        f"Prioridad (scoring multi-señal): {incident.risk_score}/100 → {incident.risk.upper()}\n\n"
        f"=== DATA RECIBIDA EN EL TICKET ===\n"
        f"{incident.pre_ia_context or '(sin contexto pre-IA)'}\n\n"
        f"=== RESOLUCION (IA) ===\n"
        f"{incident.analysis or '(sin análisis)'}\n\n"
        f"{action_line}\n\n"
        f"Ver incidente completo y aprobar/rechazar:\n"
        f"  {url}\n\n"
        f"Incidente ID: {incident.id}\n"
    )
    return msg


def build_closure_email(incident: Incident) -> EmailMessage:
    a = incident.alert
    msg = EmailMessage()
    msg["Subject"] = f"[SOC][CERRADO] Incidente {incident.id[:12]} — IP {a.src_ip} bloqueada"
    msg["From"] = settings.email_from
    msg["To"] = settings.email_to
    msg.set_content(
        f"Incidente {incident.id} cerrado.\n\n"
        f"Acción ejecutada: {incident.proposed_action}\n"
        f"Estado final: {incident.status}\n\n"
        f"Reporte de cierre guardado en el SOAR.\n"
        f"Ver detalle: {_incident_url(incident.id)}\n"
    )
    return msg


def _deliver(msg: EmailMessage, prefix: str, incident_id: str) -> str:
    # Siempre guardamos .eml en disco (útil para la demo / auditoría).
    stamp = now_iso().replace(":", "").replace(".", "")
    path = _mailbox_dir() / f"{stamp}_{prefix}_{incident_id}.eml"
    path.write_text(msg.as_string())

    if not settings.smtp_host:
        return f"email guardado en {path} (sin SMTP)"

    with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=30) as s:
        s.ehlo()
        if settings.smtp_starttls:
            s.starttls()
            s.ehlo()
        if settings.smtp_user:
            s.login(settings.smtp_user, settings.smtp_password)
        s.send_message(msg)
    return f"email enviado a {settings.email_to} via {settings.smtp_host}; copia en {path}"


def send(incident: Incident) -> str:
    """Envía el mail de alerta con link (post-investigación)."""
    return _deliver(build_alert_email(incident), "alert", incident.id)


def send_closure(incident: Incident) -> str:
    """Mail de cierre tras aprobación humana."""
    return _deliver(build_closure_email(incident), "closed", incident.id)


def save_closure_report(incident: Incident, markdown: str) -> str:
    path = _reports_dir() / f"{incident.id}_closure.md"
    path.write_text(markdown, encoding="utf-8")
    return str(path)

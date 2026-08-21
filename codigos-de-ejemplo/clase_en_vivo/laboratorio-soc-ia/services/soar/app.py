"""
SOAR-bridge: recibe alertas enriquecidas del worker (o directo de Wazuh), orquesta la respuesta.

Flujo: enrichment determinista (worker) → IA → email con link → HITL → cierre.

El webhook responde YA (202) y el playbook corre en background — así el worker
no hace timeout mientras Ollama piensa / SMTP envía.
"""
from __future__ import annotations

import html
import logging

from fastapi import BackgroundTasks, FastAPI, Form, Request
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse

from soc import approval, notify, reporting, store
from soc.agent import investigate
from soc.enrichment import enrich_ip
from soc.models import Alert, Incident
from soc.pre_enrichment import apply_pre_enrichment, parse_enriched_payload
from soc.wazuh import alert_from_wazuh

logging.basicConfig(level=logging.INFO, format="%(asctime)s [soar-bridge] %(message)s")
log = logging.getLogger("soar-bridge")

app = FastAPI(title="SOC SOAR-bridge")


async def run_playbook(alert: Alert, enrichment_raw: object | None = None) -> None:
    """
    Playbook (background):
      1. Aplicar enrichment determinista (worker o fallback)
      2. Investigar con IA
      3. Notificar por email con link al ticket
      4. Persistir y esperar aprobación humana si aplica
    """
    incident = store.load(alert.id) or Incident(id=alert.id, alert=alert)
    incident.status = "investigating"
    try:
        # Si ya vino enriquecido en el enqueue, no re-aplicar (evita notes duplicadas).
        if enrichment_raw is not None and not incident.enrichment.ip_reputation:
            apply_pre_enrichment(incident, enrichment_raw)
            incident.log("Enrichment recibido desde worker (determinista)")

        store.save(incident)
        log.info("Playbook start %s (IP %s)", incident.id[:12], alert.src_ip)

        incident = await investigate(alert, incident)

        try:
            mail_result = notify.send(incident)
        except Exception as exc:  # noqa: BLE001
            mail_result = f"notificación falló: {exc}"
            log.exception("SMTP/notify falló para %s", incident.id[:12])
        incident.log(mail_result)

        store.save(incident)
        log.info(
            "Playbook OK %s status=%s risk=%s",
            incident.id[:12],
            incident.status,
            incident.risk,
        )
    except Exception as exc:  # noqa: BLE001
        log.exception("ERROR en playbook %s", alert.id[:12])
        incident.log(f"ERROR en playbook: {exc}")
        incident.status = "error"
        store.save(incident)


def _enqueue_playbook(
    background_tasks: BackgroundTasks,
    alert: Alert,
    enrichment_raw: object | None = None,
) -> dict:
    """Guarda el incidente ya y dispara el playbook sin bloquear el HTTP."""
    # Dedup: un solo ticket abierto por IP (evita siem-lite + 5551 + 5712 + 5763).
    existing = store.find_active_by_ip(alert.src_ip)
    if existing is not None:
        existing.log(
            f"Alerta duplicada ignorada (regla {alert.rule_id}, id {alert.id}) — "
            f"ya hay incidente activo {existing.id}"
        )
        store.save(existing)
        log.info(
            "Dedup IP %s → incidente existente %s (ignoré %s)",
            alert.src_ip,
            existing.id[:12],
            alert.id[:12],
        )
        return {
            "accepted": False,
            "deduplicated": True,
            "incident_id": existing.id,
            "status": existing.status,
            "message": f"Ya existe incidente activo para {alert.src_ip}",
        }

    incident = Incident(id=alert.id, alert=alert, status="queued")
    if enrichment_raw is not None:
        apply_pre_enrichment(incident, enrichment_raw)
        incident.log("Enrichment recibido desde worker (determinista)")
    else:
        incident.log("Alerta encolada (enrichment en playbook)")
    store.save(incident)
    background_tasks.add_task(run_playbook, alert, enrichment_raw)
    return {
        "accepted": True,
        "incident_id": incident.id,
        "status": incident.status,
        "message": "Playbook encolado; mirá el dashboard en unos segundos",
    }


@app.get("/enrich/ip/{ip}")
async def enrich_ip_endpoint(ip: str):
    """Lookup determinista de reputación IP (simula VirusTotal)."""
    return enrich_ip(ip)


@app.post("/webhook/wazuh")
async def webhook_wazuh(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    alert = alert_from_wazuh(payload)
    return JSONResponse(_enqueue_playbook(background_tasks, alert), status_code=202)


@app.post("/webhook/enriched")
async def webhook_enriched(request: Request, background_tasks: BackgroundTasks):
    payload = await request.json()
    alert, enrichment = parse_enriched_payload(payload)
    return JSONResponse(
        _enqueue_playbook(background_tasks, alert, enrichment_raw=enrichment),
        status_code=202,
    )


@app.post("/webhook/shuffle")
async def webhook_shuffle_compat(request: Request, background_tasks: BackgroundTasks):
    """Alias legacy (Shuffle eliminado del lab)."""
    return await webhook_enriched(request, background_tasks)


@app.post("/incidents/{incident_id}/approve")
async def approve_incident(incident_id: str, approver: str = Form("analyst")):
    result = await approval.approve(incident_id, approver=approver)
    return RedirectResponse(url="/", status_code=303) if result.get("ok") else JSONResponse(result, status_code=400)


@app.post("/incidents/{incident_id}/reject")
async def reject_incident(incident_id: str, reason: str = Form(""), approver: str = Form("analyst")):
    result = await approval.reject(incident_id, reason=reason, approver=approver)
    return RedirectResponse(url="/", status_code=303) if result.get("ok") else JSONResponse(result, status_code=400)


@app.get("/incidents/{incident_id}", response_class=HTMLResponse)
async def incident_detail(incident_id: str):
    incident = store.load(incident_id)
    if incident is None:
        return HTMLResponse("<h1>404 — incidente no encontrado</h1>", status_code=404)
    report_md = reporting.build_report(incident)
    return HTMLResponse(_page(f"<a href='/'>&larr; volver</a><pre>{html.escape(report_md)}</pre>"))


@app.get("/healthz")
async def healthz():
    return {"status": "ok"}


@app.get("/", response_class=HTMLResponse)
async def dashboard():
    incidents = store.list_all()
    rows = []
    for inc in incidents:
        badge = {
            "high": "#e5484d", "medium": "#f5a623", "low": "#30a46c", "unknown": "#888",
        }.get(inc.risk, "#888")
        actions = ""
        if inc.status == "awaiting_approval":
            actions = (
                f"<form method='post' action='/incidents/{inc.id}/approve' style='display:inline'>"
                f"<button class='ok'>Aprobar bloqueo</button></form> "
                f"<form method='post' action='/incidents/{inc.id}/reject' style='display:inline'>"
                f"<input type='hidden' name='reason' value='descartado por analista'>"
                f"<button class='no'>Rechazar</button></form>"
            )
        rows.append(
            f"<tr>"
            f"<td><a href='/incidents/{inc.id}'>{inc.id[:12]}</a></td>"
            f"<td>{html.escape(inc.alert.src_ip)}</td>"
            f"<td>{html.escape(str(inc.alert.user))}</td>"
            f"<td><span class='badge' style='background:{badge}'>{inc.risk}</span>"
            f" {inc.risk_score}/100</td>"
            f"<td>{inc.status}</td>"
            f"<td>{inc.proposed_action or '—'}</td>"
            f"<td>{actions}</td>"
            f"</tr>"
        )

    table = (
        "<table><tr><th>Incidente</th><th>IP origen</th><th>Usuario</th>"
        "<th>Riesgo / score</th><th>Estado</th><th>Acción propuesta</th><th></th></tr>"
        + ("".join(rows) or "<tr><td colspan=7>Sin incidentes todavía. Dispará el ataque SSH.</td></tr>")
        + "</table>"
    )
    return HTMLResponse(_page(f"<h1>SOC — Incidentes</h1>{table}"))


def _page(body: str) -> str:
    return f"""<!doctype html><html lang="es"><head><meta charset="utf-8">
<meta http-equiv="refresh" content="5"><title>SOC SOAR</title>
<style>
 body{{font-family:system-ui,sans-serif;margin:2rem;background:#0f1115;color:#e6e6e6}}
 table{{border-collapse:collapse;width:100%}} th,td{{padding:.5rem .7rem;border-bottom:1px solid #2a2d34;text-align:left}}
 a{{color:#7cc4ff}} .badge{{padding:.15rem .5rem;border-radius:6px;color:#fff;font-size:.8rem}}
 button{{padding:.35rem .7rem;border:0;border-radius:6px;cursor:pointer;color:#fff}}
 button.ok{{background:#30a46c}} button.no{{background:#e5484d}}
 pre{{background:#181b21;padding:1rem;border-radius:8px;white-space:pre-wrap}}
</style></head><body>{body}
<p style="color:#666;margin-top:2rem">Se refresca solo cada 5s.</p></body></html>"""

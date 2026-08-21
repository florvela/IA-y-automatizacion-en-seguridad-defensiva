"""
Human-in-the-loop + reporte automático de cierre.
"""
from __future__ import annotations

from . import notify, reporting, store
from .mcp_client import mcp_session, result_text


async def approve(incident_id: str, approver: str = "analyst") -> dict:
    incident = store.load(incident_id)
    if incident is None:
        return {"ok": False, "error": "incidente no encontrado"}
    if incident.status != "awaiting_approval" or not incident.proposed_action:
        return {"ok": False, "error": f"el incidente no está esperando aprobación (estado: {incident.status})"}

    action, _, target = incident.proposed_action.partition(":")

    if action == "block_ip":
        async with mcp_session() as session:
            call_result = await session.call_tool("block_ip", {"ip": target, "approved": True})
            text = result_text(call_result)
        incident.status = "actioned"
        incident.log(f"[{approver}] APROBÓ la acción. Ejecutado block_ip({target}) -> {text}")

        closure_md = reporting.build_closure_report(incident, approver=approver)
        report_path = notify.save_closure_report(incident, closure_md)
        incident.log(f"Reporte de cierre guardado en {report_path}")
        try:
            mail_result = notify.send_closure(incident)
            incident.log(mail_result)
        except Exception as exc:  # noqa: BLE001
            incident.log(f"mail de cierre falló: {exc}")

        store.save(incident)
        return {"ok": True, "action": action, "target": target, "result": text, "report": report_path}

    return {"ok": False, "error": f"acción desconocida: {action}"}


async def reject(incident_id: str, reason: str = "", approver: str = "analyst") -> dict:
    incident = store.load(incident_id)
    if incident is None:
        return {"ok": False, "error": "incidente no encontrado"}
    incident.status = "rejected"
    incident.log(f"[{approver}] RECHAZÓ la acción. Motivo: {reason or 'sin especificar'}")
    store.save(incident)
    return {"ok": True, "status": "rejected"}

"""
SOC worker: recibe alertas de Wazuh, enriquece IP (determinista) y reenvía al SOAR-bridge.

Reemplaza Shuffle en el lab — mismo flujo, sin UI ni contenedores extra.
"""
from __future__ import annotations

import logging
import os

import httpx
from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from soc.enrichment import enrich_ip
from soc.wazuh import alert_from_wazuh

logging.basicConfig(level=logging.INFO, format="%(asctime)s [soc-worker] %(message)s")
log = logging.getLogger("soc-worker")

SOAR_URL = os.environ.get("SOC_SOAR_URL", "http://soar-bridge:9000").rstrip("/")

app = FastAPI(title="SOC Worker")


@app.get("/healthz")
async def healthz():
    return {"status": "ok", "soar_url": SOAR_URL}


@app.post("/webhook/wazuh")
async def webhook_wazuh(request: Request):
    payload = await request.json()
    try:
        alert = alert_from_wazuh(payload)
    except Exception as exc:  # noqa: BLE001
        log.exception("No se pudo parsear alerta Wazuh")
        return JSONResponse({"error": str(exc)}, status_code=400)

    log.info("Alerta %s — IP %s — enriqueciendo...", alert.id[:12], alert.src_ip)
    enrichment = enrich_ip(alert.src_ip)
    body = {"wazuh_alert": payload, "enrichment": enrichment}

    try:
        # El bridge responde 202 al toque; el playbook (IA + mail) corre atrás.
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(f"{SOAR_URL}/webhook/enriched", json=body)
            resp.raise_for_status()
            result = resp.json()
    except Exception as exc:  # noqa: BLE001
        log.exception("Fallo al reenviar al SOAR-bridge")
        return JSONResponse({"error": str(exc)}, status_code=502)

    log.info(
        "Enviado al bridge — incidente %s (status=%s)",
        result.get("incident_id", "?"),
        result.get("status", "?"),
    )
    return result

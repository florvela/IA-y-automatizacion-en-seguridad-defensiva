"""
Enriquecimiento determinista de IPs (simula VirusTotal / AbuseIPDB).

# Usado por soc-worker y por el MCP (check_ip_reputation).
# La IA NO debería recalcular esto si ya vino del SOAR.
"""
from __future__ import annotations

import json
import os
from pathlib import Path

SEED_DIR = Path(os.getenv("SOC_SEED_DIR", "/app/data"))


def _load_blacklist() -> set[str]:
    f = SEED_DIR / "blacklist.txt"
    if not f.exists():
        return set()
    return {
        line.strip()
        for line in f.read_text().splitlines()
        if line.strip() and not line.startswith("#")
    }


def lookup_ip_reputation(ip: str) -> dict:
    """Score 0-100 y fuentes. Misma lógica que la tool MCP check_ip_reputation."""
    blacklist = _load_blacklist()
    blacklisted = ip in blacklist

    if blacklisted:
        score = 95
        sources = ["blacklist-interna", "AbuseIPDB(sim)"]
    else:
        private = ip.startswith(
            ("10.", "192.168.", "172.16.", "172.17.", "172.18.", "172.19.", "172.20.")
        )
        score = 5 if private else 20
        sources = ["blacklist-interna"]

    return {
        "ip": ip,
        "blacklisted": blacklisted,
        "score": score,
        "sources": sources,
        "country": "AR" if ip.startswith("200.") else ("RU" if blacklisted else "—"),
    }


def geolocate_ip_offline(ip: str) -> dict:
    if ip.startswith(("10.", "192.168.", "172.")):
        return {"ip": ip, "country": "—", "city": "red interna", "private": True}
    if ip.startswith("200."):
        return {"ip": ip, "country": "AR", "city": "Buenos Aires", "private": False}
    return {"ip": ip, "country": "??", "city": "desconocida", "private": False}


def enrich_ip(ip: str) -> dict:
    return {
        "ip_reputation": lookup_ip_reputation(ip),
        "geolocation": geolocate_ip_offline(ip),
        "source": "soc-worker-enrichment",
        "note": "En producción esto sería VirusTotal / AbuseIPDB.",
    }


def parse_enrichment_blob(raw: object) -> dict | None:
    """Normaliza respuestas de enrichment (dict, str JSON, envuelto en body/result)."""
    if raw is None:
        return None
    if isinstance(raw, str):
        try:
            raw = json.loads(raw)
        except json.JSONDecodeError:
            return None
    if not isinstance(raw, dict):
        return None

    # Respuesta HTTP cruda: a veces viene en "body" o "result".
    for key in ("body", "result", "data"):
        if key in raw and isinstance(raw[key], str):
            try:
                inner = json.loads(raw[key])
                if isinstance(inner, dict):
                    raw = inner
                    break
            except json.JSONDecodeError:
                pass

    if "ip_reputation" in raw:
        return raw
    if "blacklisted" in raw and "score" in raw:
        return {"ip_reputation": raw, "source": "enrichment-passthrough"}
    return raw if raw else None

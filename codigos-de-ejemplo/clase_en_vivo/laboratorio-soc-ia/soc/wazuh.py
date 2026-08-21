"""
Traducción de una alerta cruda de Wazuh a nuestro modelo Alert.

# Wazuh manda un JSON con muchísimos campos anidados e ilegibles.
# Acá lo normalizamos a algo limpio que el resto del pipeline entiende.
# Este es el "adaptador": aísla el formato de Wazuh del resto del código.
"""
from __future__ import annotations

import re
import uuid

from .models import Alert, now_iso

# Regex para pescar una IPv4 del texto crudo si Wazuh no la trae estructurada.
_IP_RE = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")


def _first_ip(text: str) -> str | None:
    m = _IP_RE.search(text or "")
    return m.group(0) if m else None


def alert_from_wazuh(payload: dict) -> Alert:
    """Recibe el JSON del integrator de Wazuh y devuelve una Alert limpia."""
    rule = payload.get("rule", {}) or {}
    data = payload.get("data", {}) or {}
    agent = payload.get("agent", {}) or {}

    # La IP de origen puede venir en distintos campos según la regla.
    src_ip = (
        data.get("srcip")
        or data.get("src_ip")
        or _first_ip(payload.get("full_log", ""))
        or "0.0.0.0"
    )
    # El usuario objetivo del ataque (o el que se autenticó).
    user = data.get("dstuser") or data.get("srcuser") or data.get("user")

    return Alert(
        id=str(payload.get("id") or payload.get("timestamp") or uuid.uuid4()),
        rule_id=str(rule.get("id", "?")),
        rule_description=rule.get("description", "(sin descripción)"),
        level=int(rule.get("level", 0) or 0),
        src_ip=src_ip,
        dst_host=agent.get("name", "unknown"),
        user=user,
        timestamp=payload.get("timestamp") or now_iso(),
        raw=payload,
    )

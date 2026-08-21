"""
Persistencia simple de incidentes en disco (JSON por incidente).

# No usamos base de datos a propósito: en un lab, archivos JSON son
# transparentes y fáciles de inspeccionar. En producción esto sería una DB,
# pero la interfaz (save/load/list_all) no cambiaría. Eso es buen diseño.
"""
from __future__ import annotations

import threading
from pathlib import Path

from .config import settings
from .models import Incident

# Lock para evitar escrituras pisadas si dos servicios guardan a la vez.
_lock = threading.Lock()


def _incidents_dir() -> Path:
    p = Path(settings.state_dir) / "incidents"
    p.mkdir(parents=True, exist_ok=True)
    return p


def save(incident: Incident) -> None:
    with _lock:
        path = _incidents_dir() / f"{incident.id}.json"
        path.write_text(incident.model_dump_json(indent=2))


def load(incident_id: str) -> Incident | None:
    path = _incidents_dir() / f"{incident_id}.json"
    if not path.exists():
        return None
    return Incident.model_validate_json(path.read_text())


def list_all() -> list[Incident]:
    # Más nuevos primero.
    incidents = [
        Incident.model_validate_json(f.read_text())
        for f in _incidents_dir().glob("*.json")
    ]
    return sorted(incidents, key=lambda i: i.created_at, reverse=True)


_ACTIVE = {"queued", "investigating", "open", "awaiting_approval"}


def find_active_by_ip(src_ip: str) -> Incident | None:
    """Evita 4 tickets del mismo brute force (siem-lite + varias reglas Wazuh)."""
    for inc in list_all():
        if inc.alert.src_ip == src_ip and inc.status in _ACTIVE:
            return inc
    return None


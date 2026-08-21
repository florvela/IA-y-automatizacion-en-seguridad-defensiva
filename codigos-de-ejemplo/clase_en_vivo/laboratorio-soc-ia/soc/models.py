"""
Modelos de datos del dominio SOC.

# Usamos pydantic para tener serialización JSON gratis y validación de tipos.
# Cada modelo representa un concepto real del trabajo de un analista.
"""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Literal, Optional

from pydantic import BaseModel, Field


def now_iso() -> str:
    # Timestamp UTC en formato ISO. Siempre UTC para no pelear con zonas horarias.
    return datetime.now(timezone.utc).isoformat()


class Alert(BaseModel):
    """Alerta normalizada. Viene de Wazuh o se arma a mano en el notebook."""

    id: str
    rule_id: str
    rule_description: str
    level: int
    src_ip: str
    dst_host: str = "unknown"
    user: Optional[str] = None
    timestamp: str = Field(default_factory=now_iso)
    raw: dict = Field(default_factory=dict)  # payload crudo original (por si hace falta)


class IPReputation(BaseModel):
    """Resultado de consultar la reputación de una IP (lo devuelve una tool MCP)."""

    ip: str
    blacklisted: bool
    score: int                      # 0-100; mayor = más peligroso
    sources: list[str] = Field(default_factory=list)
    country: Optional[str] = None


class Enrichment(BaseModel):
    """Contexto recolectado durante la investigación automática."""

    ip_reputation: Optional[IPReputation] = None
    user_history: dict = Field(default_factory=dict)
    notes: list[str] = Field(default_factory=list)


class Incident(BaseModel):
    """
    Un incidente: agrupa la alerta, el contexto, el análisis del LLM,
    la acción propuesta y el estado del human-in-the-loop.
    """

    id: str
    alert: Alert
    enrichment: Enrichment = Field(default_factory=Enrichment)
    analysis: str = ""                                  # texto redactado por el LLM
    risk: Literal["low", "medium", "high", "unknown"] = "unknown"
    risk_score: int = 0                                 # 0-100 scoring multi-señal
    score_breakdown: dict = Field(default_factory=dict)  # puntos por categoría
    proposed_action: Optional[str] = None               # ej: "block_ip:203.0.113.10"
    status: Literal[
        "queued",
        "investigating",
        "open",
        "awaiting_approval",
        "actioned",
        "closed",
        "rejected",
        "error",
    ] = "open"
    ticket_id: Optional[str] = None
    pre_ia_context: str = ""  # DATA RECIBIDA: enrichment determinista (worker), sin LLM
    created_at: str = Field(default_factory=now_iso)
    updated_at: str = Field(default_factory=now_iso)
    timeline: list[dict] = Field(default_factory=list)

    def log(self, msg: str) -> None:
        # Cada paso importante queda registrado en la línea de tiempo del incidente.
        self.timeline.append({"ts": now_iso(), "msg": msg})
        self.updated_at = now_iso()

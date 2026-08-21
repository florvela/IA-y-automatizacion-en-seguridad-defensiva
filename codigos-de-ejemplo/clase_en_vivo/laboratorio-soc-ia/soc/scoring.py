"""
Scoring de riesgo multi-señal (priorización de la cola SOC).

# Combina: alerta + usuario + activo + contexto + threat intel.
# Ninguna señal sola decide: el total (0-100) ordena el trabajo y alimenta el playbook.
"""
from __future__ import annotations

import json
import os
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Incident

SEED_DIR = Path(os.getenv("SOC_SEED_DIR", "/app/data"))

# Reglas típicas de brute force / auth failures en este lab.
BRUTE_FORCE_RULES = {"5551", "5710", "5711", "5712", "5720", "5763"}
PRIVILEGED_USERS = {"root", "admin", "Administrator"}

# Umbrales que consume el playbook.
THRESHOLD_HIGH = 70
THRESHOLD_MEDIUM = 40


def _load_json(name: str) -> dict:
    path = SEED_DIR / name
    if not path.exists():
        return {}
    return json.loads(path.read_text(encoding="utf-8"))


def _parse_hour(timestamp: str) -> int | None:
    if not timestamp:
        return None
    try:
        # Wazuh: 2026-08-20T15:24:06.524+0000  |  ISO con Z
        ts = timestamp.replace("Z", "+00:00")
        if len(ts) >= 5 and (ts[-5] in "+-") and ts[-3] != ":":
            ts = ts[:-2] + ":" + ts[-2:]
        return datetime.fromisoformat(ts).hour
    except ValueError:
        return None


def _score_alert(incident: Incident) -> tuple[int, list[str]]:
    a = incident.alert
    pts = 0
    reasons: list[str] = []

    # Severidad Wazuh (0-15) → hasta 30 pts
    level_pts = min(30, max(0, a.level) * 3)
    pts += level_pts
    reasons.append(f"Severidad regla (nivel {a.level}): +{level_pts}")

    if a.rule_id in BRUTE_FORCE_RULES or "brute" in (a.rule_description or "").lower():
        pts += 15
        reasons.append(f"Tipo de evento brute force / auth failures (regla {a.rule_id}): +15")

    return pts, reasons


def _score_user(incident: Incident) -> tuple[int, list[str]]:
    users = _load_json("users.json")
    user = (incident.alert.user or "").strip()
    history = incident.enrichment.user_history or {}
    pts = 0
    reasons: list[str] = []

    profile = history if history.get("user") else users.get(user, {})

    if not user:
        reasons.append("Usuario desconocido en alerta: +0")
        return pts, reasons

    if user in PRIVILEGED_USERS or "privilegiada" in str(profile.get("note", "")).lower():
        pts += 20
        reasons.append(f"Usuario privilegiado ('{user}'): +20")

    if profile.get("known") is False:
        pts += 15
        reasons.append(f"Usuario inexistente / no inventariado ('{user}'): +15")

    if profile and profile.get("mfa_enabled") is False:
        pts += 10
        reasons.append(f"Sin MFA ('{user}'): +10")

    if not reasons:
        reasons.append(f"Usuario '{user}' sin señales agravantes: +0")
    return pts, reasons


def _score_asset(incident: Incident) -> tuple[int, list[str]]:
    assets = _load_json("assets.json")
    host = incident.alert.dst_host or "unknown"
    asset = assets.get(host) or assets.get("unknown") or {}
    crit = (asset.get("criticality") or "medium").lower()
    table = {"low": 5, "medium": 10, "high": 18, "critical": 25}
    pts = table.get(crit, 10)
    role = asset.get("role") or host
    return pts, [f"Activo '{host}' ({role}, criticidad {crit}): +{pts}"]


def _score_context(incident: Incident) -> tuple[int, list[str]]:
    pts = 0
    reasons: list[str] = []
    hour = _parse_hour(incident.alert.timestamp)
    if hour is not None and (hour < 6 or hour >= 22):
        pts += 10
        reasons.append(f"Horario atípico (hora UTC {hour:02d}): +10")

    users = _load_json("users.json")
    user = (incident.alert.user or "").strip()
    profile = incident.enrichment.user_history or users.get(user, {})
    usual = set(profile.get("usual_source_countries") or [])
    rep = incident.enrichment.ip_reputation
    country = (rep.country if rep else None) or ""
    if usual and country and country not in ("—", "??") and country not in usual:
        pts += 15
        reasons.append(
            f"País origen '{country}' fuera del patrón del usuario {list(usual)}: +15"
        )

    # Notas de geo del enrichment
    for note in incident.enrichment.notes:
        if "red interna" in note and rep and rep.blacklisted:
            pts += 5
            reasons.append("IP en red lab pero marcada maliciosa (simulación): +5")
            break

    if not reasons:
        reasons.append("Contexto sin señales agravantes: +0")
    return pts, reasons


def _score_threat_intel(incident: Incident) -> tuple[int, list[str]]:
    rep = incident.enrichment.ip_reputation
    if not rep:
        return 0, ["Threat intel: sin reputación de IP aún: +0"]

    if rep.blacklisted:
        return 30, [
            f"Threat intel: IP {rep.ip} en blacklist "
            f"(fuentes: {', '.join(rep.sources) or '—'}): +30"
        ]

    # Reputación 0-100 → hasta 20 pts si no está blacklisteada
    intel_pts = min(20, rep.score // 5)
    return intel_pts, [f"Threat intel: reputación IP score={rep.score}/100 → +{intel_pts}"]


def _score_anomalia_ml(incident: Incident) -> tuple[int, list[str]]:
    """One-Class SVM tabular (POC). Hasta +25 pts."""
    try:
        from .anomaly import score_anomaly  # noqa: PLC0415
    except Exception:  # noqa: BLE001
        return 0, ["Anomalía ML: módulo no disponible: +0"]

    result = score_anomaly(incident)
    if not result.get("enabled"):
        return 0, ["Anomalía ML: modelo no cargado (train previo o SOC_ANOMALY_ML): +0"]

    ml_score = int(result.get("score_0_100", 0))
    is_outlier = bool(result.get("is_outlier"))
    # Mapear 0-100 del modelo → hasta 25 pts del scoring SOC
    pts = min(25, ml_score // 4)
    if is_outlier:
        pts = max(pts, 18)
    tag = "OUTLIER" if is_outlier else "inlier"
    return pts, [
        f"Anomalía ML (OneClassSVM tabular): {tag}, "
        f"score_modelo={ml_score}/100 → +{pts}"
    ]


def compute_risk_score(incident: Incident) -> dict[str, Any]:
    """
    Calcula score 0-100 y breakdown por categoría.
    El playbook usa el total para priorizar y decidir acción.
    """
    categories = {
        "alerta": _score_alert(incident),
        "usuario": _score_user(incident),
        "activo": _score_asset(incident),
        "contexto": _score_context(incident),
        "threat_intel": _score_threat_intel(incident),
        "anomalia_ml": _score_anomalia_ml(incident),
    }

    breakdown: dict[str, Any] = {}
    total = 0
    all_reasons: list[str] = []
    for name, (pts, reasons) in categories.items():
        breakdown[name] = {"points": pts, "reasons": reasons}
        total += pts
        all_reasons.extend(reasons)

    total = min(100, total)

    if total >= THRESHOLD_HIGH:
        risk = "high"
    elif total >= THRESHOLD_MEDIUM:
        risk = "medium"
    else:
        risk = "low"

    return {
        "score": total,
        "risk": risk,
        "breakdown": breakdown,
        "reasons": all_reasons,
        "thresholds": {"high": THRESHOLD_HIGH, "medium": THRESHOLD_MEDIUM},
    }


def format_score_section(result: dict[str, Any]) -> str:
    lines = [
        "",
        "Scoring de riesgo (multi-señal, pre-decisión del playbook):",
        f"  - TOTAL: {result['score']}/100 → riesgo {result['risk'].upper()}",
        f"  - Umbrales: high≥{result['thresholds']['high']}, "
        f"medium≥{result['thresholds']['medium']}",
    ]
    for cat, data in result["breakdown"].items():
        lines.append(f"  - {cat}: +{data['points']}")
        for reason in data["reasons"]:
            lines.append(f"      · {reason}")
    return "\n".join(lines)


def apply_score_to_incident(incident: Incident) -> dict[str, Any]:
    """Escribe score/risk/acción propuesta en el incidente según el total."""
    result = compute_risk_score(incident)
    incident.risk_score = result["score"]
    incident.score_breakdown = result["breakdown"]
    incident.risk = result["risk"]  # type: ignore[assignment]

    incident.log(
        f"Scoring multi-señal: {result['score']}/100 "
        f"(alerta={result['breakdown']['alerta']['points']}, "
        f"usuario={result['breakdown']['usuario']['points']}, "
        f"activo={result['breakdown']['activo']['points']}, "
        f"contexto={result['breakdown']['contexto']['points']}, "
        f"threat_intel={result['breakdown']['threat_intel']['points']}, "
        f"anomalia_ml={result['breakdown']['anomalia_ml']['points']}) "
        f"→ {result['risk'].upper()}"
    )

    ip = incident.alert.src_ip
    if result["risk"] == "high":
        incident.proposed_action = f"block_ip:{ip}"
    elif result["risk"] == "medium":
        incident.proposed_action = f"block_ip:{ip}"
    else:
        incident.proposed_action = None

    return result

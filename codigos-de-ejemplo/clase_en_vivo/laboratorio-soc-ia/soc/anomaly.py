"""
Detección de anomalías (POC): One-Class SVM sobre features tabulares.

Train offline: scripts/train_anomaly_model.py
Runtime: carga el .joblib y puntúa la alerta actual.
Si faltan artefactos o falla el load, score=0 (el scoring determinista sigue).

Sin embeddings: user/host/ip/hora/país → vector numérico → OneClassSVM.
"""
from __future__ import annotations

import json
import logging
import zlib
from datetime import datetime
from pathlib import Path
from typing import Any

from .models import Incident

log = logging.getLogger("soc.anomaly")

FEATURE_VERSION = 3
VECTOR_DIM = 8  # user, host, ip×4, hour, country
MODEL_FILENAME = "one_class_svm.joblib"

_model = None
_meta: dict[str, Any] | None = None
_load_attempted = False


def ml_dir() -> Path:
    from .config import settings  # noqa: PLC0415

    custom = (settings.ml_dir or "").strip()
    if custom:
        return Path(custom)
    return Path(settings.seed_dir) / "ml"


def _model_path() -> Path:
    return ml_dir() / MODEL_FILENAME


def _parse_hour(timestamp: str) -> int | None:
    if not timestamp:
        return None
    try:
        ts = timestamp.replace("Z", "+00:00")
        if len(ts) >= 5 and (ts[-5] in "+-") and ts[-3] != ":":
            ts = ts[:-2] + ":" + ts[-2:]
        return datetime.fromisoformat(ts).hour
    except ValueError:
        return None


def _cat_hash(value: str, buckets: int = 32) -> float:
    """Hash estable de categoría → [0, 1]. Sin vocabulario entrenado."""
    h = zlib.crc32(str(value).encode("utf-8")) & 0xFFFFFFFF
    return (h % buckets) / max(buckets - 1, 1)


def _ip_octets(ip: str) -> list[float]:
    parts = (ip or "0.0.0.0").split(".")
    out: list[float] = []
    for i in range(4):
        try:
            out.append(int(parts[i]) / 255.0 if i < len(parts) else 0.0)
        except ValueError:
            out.append(0.0)
    return out


def features_from_incident(incident: Incident) -> dict[str, Any]:
    """
    Features de comportamiento (train = runtime).
    Sin rule/level (SIEM) ni blacklist/ip_score (threat intel).
    """
    a = incident.alert
    rep = incident.enrichment.ip_reputation
    hour = _parse_hour(a.timestamp)
    return {
        "user": a.user or "unknown",
        "host": a.dst_host or "unknown",
        "src_ip": a.src_ip or "0.0.0.0",
        "hour": hour if hour is not None else -1,
        "country": (rep.country if rep else None) or "—",
    }


def features_to_vector(feat: dict[str, Any]) -> list[float]:
    """Vector numérico compartido train/runtime (dim = VECTOR_DIM)."""
    hour = int(feat.get("hour", -1))
    hour_n = (hour / 23.0) if hour >= 0 else -1.0
    return [
        _cat_hash(str(feat.get("user", "unknown"))),
        _cat_hash(str(feat.get("host", "unknown"))),
        *_ip_octets(str(feat.get("src_ip", "0.0.0.0"))),
        hour_n,
        _cat_hash(str(feat.get("country", "—")), buckets=64),
    ]


def features_to_text(feat: dict[str, Any]) -> str:
    """Resumen legible (debug / timeline); no se usa para el modelo."""
    return (
        f"user={feat.get('user', 'unknown')} host={feat.get('host', 'unknown')} "
        f"src_ip={feat.get('src_ip', '0.0.0.0')} "
        f"hour={int(feat.get('hour', -1))} country={feat.get('country', '—')}"
    )


def alert_to_text(incident: Incident) -> str:
    return features_to_text(features_from_incident(incident))


def anomaly_enabled() -> bool:
    from .config import settings  # noqa: PLC0415

    flag = getattr(settings, "anomaly_ml", None)
    if flag is False:
        return False
    return _model_path().exists()


def _load_models() -> bool:
    global _model, _meta, _load_attempted
    if _load_attempted:
        return _model is not None
    _load_attempted = True

    path = _model_path()
    meta_path = ml_dir() / "meta.json"
    if not path.exists():
        log.info("Anomaly ML: sin %s — señal desactivada", path)
        return False

    try:
        import joblib  # noqa: PLC0415

        _model = joblib.load(path)
        if meta_path.exists():
            _meta = json.loads(meta_path.read_text(encoding="utf-8"))
        log.info(
            "Anomaly ML listo (OneClassSVM tabular v%s, %s)",
            (_meta or {}).get("feature_version", "?"),
            path.name,
        )
        return True
    except Exception as exc:  # noqa: BLE001
        log.warning("Anomaly ML no disponible (%s) — scoring sin esa señal", exc)
        _model = None
        return False


def score_anomaly(incident: Incident) -> dict[str, Any]:
    """
    Devuelve score 0-100 (mayor = más anómalo), is_outlier, y detalle.
    Si ML off o error → score 0, is_outlier False.
    """
    feat = features_from_incident(incident)
    summary = features_to_text(feat)
    empty = {
        "score_0_100": 0,
        "is_outlier": False,
        "raw_decision": 0,
        "raw_score": 0.0,
        "text": summary,
        "enabled": False,
    }
    if not anomaly_enabled():
        return empty
    if not _load_models():
        return empty

    try:
        import numpy as np  # noqa: PLC0415

        vec = features_to_vector(feat)
        X = np.asarray([vec], dtype=float)
        decision = int(_model.predict(X)[0])  # -1 outlier, 1 inlier
        # OneClassSVM: decision_function > 0 → inlier; < 0 → outlier
        raw = float(_model.decision_function(X)[0])
        score = int(max(0, min(100, round(50 - raw * 40))))
        if decision == -1:
            score = max(score, 70)
        else:
            score = min(score, 55)

        return {
            "score_0_100": score,
            "is_outlier": decision == -1,
            "raw_decision": decision,
            "raw_score": raw,
            "text": summary,
            "vector": vec,
            "enabled": True,
        }
    except Exception as exc:  # noqa: BLE001
        log.warning("Anomaly ML inferencia falló (%s)", exc)
        return {**empty, "error": str(exc)}

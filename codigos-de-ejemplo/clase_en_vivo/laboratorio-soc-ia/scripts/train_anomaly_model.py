#!/usr/bin/env python3
"""
Entrena One-Class SVM (NO supervisado) sobre features tabulares.

Uso (antes de la clase, una vez):
  pip install scikit-learn joblib numpy
  python scripts/train_anomaly_model.py

Importante (pedagogía):
  - OneClassSVM.fit(X) NO usa etiquetas: aprende el contorno de lo "habitual".
  - Features numéricas: user/host/country (hash), src_ip (4 octetos), hour.
    Sin rule/level (SIEM), sin blacklist, sin embeddings.
  - baseline → fit; attack probes → solo eval post-hoc.
  - StandardScaler + RBF (nu ≈ fracción esperada de rareza en el baseline).

Escribe:
  data/ml/one_class_svm.joblib
  data/ml/meta.json
"""
from __future__ import annotations

import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

ML_DIR = ROOT / "data" / "ml"


def _synth_baseline() -> list[dict]:
    """Tráfico habitual del lab (con esto se entrena el One-Class SVM)."""
    rows: list[dict] = []
    for i in range(300):
        hour = 9 + (i % 9)  # 09-17
        rows.append(
            {
                "user": "labuser",
                "host": "victim" if i % 2 == 0 else "unknown",
                "src_ip": f"10.0.{i % 50}.{1 + i % 200}",
                "hour": hour,
                "country": "AR",
            }
        )
    return rows


def _synth_attack_probes() -> list[dict]:
    """Patrones de ataque — NO entran al fit; solo evalúan outliers."""
    rows: list[dict] = []
    for i in range(40):
        rows.append(
            {
                "user": "root" if i % 3 else "admin",
                "host": "victim" if i % 2 == 0 else "wazuh.manager",
                "src_ip": "172.20.0.66" if i % 2 == 0 else f"203.0.113.{i % 50}",
                "hour": i % 5,  # madrugada
                "country": "RU",
            }
        )
    return rows


def main() -> None:
    ML_DIR.mkdir(parents=True, exist_ok=True)

    from joblib import dump
    from sklearn.pipeline import Pipeline
    from sklearn.preprocessing import StandardScaler
    from sklearn.svm import OneClassSVM
    import numpy as np

    from soc.anomaly import (  # noqa: PLC0415
        FEATURE_VERSION,
        MODEL_FILENAME,
        VECTOR_DIM,
        features_to_text,
        features_to_vector,
    )

    baseline = _synth_baseline()
    probes = _synth_attack_probes()
    X_fit = np.asarray([features_to_vector(r) for r in baseline], dtype=float)
    X_probe = np.asarray([features_to_vector(r) for r in probes], dtype=float)

    assert X_fit.shape[1] == VECTOR_DIM
    print(f"[train] feature_version={FEATURE_VERSION} dim={VECTOR_DIM}")
    print(f"[train] ej: {features_to_text(baseline[0])} → {features_to_vector(baseline[0])}")
    print(f"[train] baseline (fit)={len(baseline)} | attack probes (eval only)={len(probes)}")
    print(f"[train] X_fit={X_fit.shape} X_probe={X_probe.shape}")

    nu = 0.08
    model = Pipeline(
        [
            ("scaler", StandardScaler()),
            ("ocsvm", OneClassSVM(kernel="rbf", gamma="scale", nu=nu)),
        ]
    )
    model.fit(X_fit)

    flagged_baseline = (model.predict(X_fit) == -1).mean()
    flagged_probes = (model.predict(X_probe) == -1).mean()
    print(
        f"[train] % outlier en baseline={flagged_baseline:.2%} | "
        f"en attack probes={flagged_probes:.2%} (eval, no fit)"
    )

    model_path = ML_DIR / MODEL_FILENAME
    dump(model, model_path)
    # limpia artefacto viejo de Isolation Forest si quedó
    legacy = ML_DIR / "isolation_forest.joblib"
    if legacy.exists():
        legacy.unlink()
        print(f"[train] removed legacy {legacy.name}")

    meta = {
        "version": 4,
        "mode": "unsupervised_one_class_svm_tabular",
        "algorithm": "OneClassSVM",
        "feature_version": FEATURE_VERSION,
        "features": ["user_hash", "host_hash", "ip_o1", "ip_o2", "ip_o3", "ip_o4", "hour", "country_hash"],
        "excluded": ["rule", "level", "blacklisted", "ip_score", "embeddings"],
        "nu": nu,
        "kernel": "rbf",
        "pipeline": ["StandardScaler", "OneClassSVM"],
        "n_fit_baseline": int(len(baseline)),
        "n_eval_probes": int(len(probes)),
        "feature_dim": int(X_fit.shape[1]),
        "note": (
            "Tabular One-Class SVM only. Probes are evaluation-only; "
            "fit never saw them or any labels."
        ),
        "metrics": {
            "outlier_rate_baseline": round(float(flagged_baseline), 4),
            "outlier_rate_attack_probes": round(float(flagged_probes), 4),
        },
    }
    meta_path = ML_DIR / "meta.json"
    meta_path.write_text(json.dumps(meta, indent=2) + "\n", encoding="utf-8")
    print(f"[train] OK → {model_path}")
    print(f"[train] OK → {meta_path}")


if __name__ == "__main__":
    main()

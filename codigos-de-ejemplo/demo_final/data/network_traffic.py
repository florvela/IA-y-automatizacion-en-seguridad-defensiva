"""
Generación de datos sintéticos de tráfico de red.

Produce dos tipos de registros:
- Tráfico normal: navegación web, DNS, SSH
- Tráfico anómalo: exfiltración masiva de datos

También incluye funciones para guardar y cargar datos en distintos formatos:
- CSV    : simple, legible, intercambio de datos
- NDJSON : newline-delimited JSON, formato de logs en SIEMs / pipelines
- Parquet: columnar + comprimido, óptimo para ML y análisis
"""

import json
import os
import numpy as np
import pandas as pd

# Features usadas por el Isolation Forest
FEATURES = [
    'bytes_sent',
    'bytes_recv',
    'duration',
    'dst_port',
    'packets_sent',
    'packets_recv',
    'bytes_per_packet',
    'upload_ratio',
]


def generate_normal_traffic(n: int = 5000, seed: int = 42) -> pd.DataFrame:
    """
    Genera n registros de tráfico de red normal.
    Simula navegación web, DNS, SSH con patrones realistas:
    - Más descarga que carga
    - Conexiones cortas
    - Puertos comunes
    """
    np.random.seed(seed)

    df = pd.DataFrame({
        'bytes_sent':   np.random.lognormal(mean=7,  sigma=1.5, size=n),
        'bytes_recv':   np.random.lognormal(mean=10, sigma=1.5, size=n),
        'duration':     np.random.exponential(scale=20, size=n),
        'dst_port':     np.random.choice(
                            [80, 443, 53, 22, 8080],
                            size=n,
                            p=[0.3, 0.4, 0.2, 0.05, 0.05]
                        ),
        'packets_sent': np.random.randint(1, 100, size=n),
        'packets_recv': np.random.randint(1, 500, size=n),
    })

    df['bytes_per_packet'] = df['bytes_sent'] / (df['packets_sent'] + 1)
    df['upload_ratio']     = df['bytes_sent'] / (df['bytes_recv']  + 1)

    return df


# ── Persistencia en múltiples formatos ───────────────────────────────────────

DATA_DIR = "data"

def save_as_csv(df: pd.DataFrame, path: str) -> None:
    """Guarda el DataFrame como CSV (legible, portable)."""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    df.to_csv(path, index=False)


def save_as_ndjson(df: pd.DataFrame, path: str) -> None:
    """
    Guarda como NDJSON (Newline-Delimited JSON).
    Un objeto JSON por línea — formato estándar en logs de SIEMs y pipelines
    de seguridad (Splunk, Elastic, etc.).
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w") as f:
        for record in df.to_dict(orient="records"):
            f.write(json.dumps(record) + "\n")


def save_as_parquet(df: pd.DataFrame, path: str) -> None:
    """
    Guarda como Parquet (columnar + comprimido).
    Mucho más eficiente en tamaño y velocidad de lectura que CSV para ML.
    """
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    df.to_parquet(path, index=False)


def load_traffic(path: str) -> pd.DataFrame:
    """
    Carga un dataset de tráfico desde disco.
    Detecta el formato por extensión: .csv, .ndjson, .parquet
    """
    if path.endswith(".parquet"):
        return pd.read_parquet(path)
    elif path.endswith(".ndjson"):
        records = []
        with open(path) as f:
            for line in f:
                records.append(json.loads(line))
        return pd.DataFrame(records)
    elif path.endswith(".csv"):
        return pd.read_csv(path)
    else:
        raise ValueError(f"Formato no soportado: {path}")


def get_demo_event_features() -> pd.DataFrame:
    """
    Devuelve las features del evento de demo (exfiltración)
    en el formato que espera el Isolation Forest.
    """
    bytes_sent   = 284_739_200
    bytes_recv   = 1_024
    packets_sent = 189_340

    return pd.DataFrame([{
        'bytes_sent':       bytes_sent,
        'bytes_recv':       bytes_recv,
        'duration':         847,
        'dst_port':         9001,
        'packets_sent':     packets_sent,
        'packets_recv':     12,
        'bytes_per_packet': bytes_sent / (packets_sent + 1),
        'upload_ratio':     bytes_sent / (bytes_recv + 1),
    }])

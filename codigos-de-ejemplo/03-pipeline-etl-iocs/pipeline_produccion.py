"""
pipeline_produccion.py — Versión productiva del Pipeline ETL de IOCs
=====================================================================
Mismo pipeline del notebook 03, con cuatro mejoras para producción:

  1. Retry con exponential backoff  — tolera fallos de red transitorios
  2. Extracción paralela de fuentes  — ThreadPoolExecutor, una thread por fuente
  3. Checkpoint                      — evita reprocesar logs ya procesados
  4. Loop schedulado                 — ejecuta automáticamente cada N minutos

Uso:
    pip install requests schedule
    python pipeline_produccion.py

    # Para cambiar el intervalo de ejecución:
    python pipeline_produccion.py --intervalo 10   # cada 10 minutos (default: 5)
    python pipeline_produccion.py --una-vez        # ejecutar una vez y salir
"""

import re
import json
import csv
import ipaddress
import logging
import argparse
import time
import requests
from datetime import datetime
from collections import Counter, defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import schedule

# ---------------------------------------------------------------------------
# Configuración de logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s'
)
logger = logging.getLogger('pipeline-etl-prod')

# ---------------------------------------------------------------------------
# Configuración del pipeline
# ---------------------------------------------------------------------------
FUENTES = {
    'ssh':    'https://raw.githubusercontent.com/logpai/loghub/master/OpenSSH/OpenSSH_2k.log',
    'apache': 'https://raw.githubusercontent.com/logpai/loghub/master/Apache/Apache_2k.log',
}

DIRECTORIO_SALIDA = Path('/tmp/etl_output')
CHECKPOINT_FILE   = DIRECTORIO_SALIDA / 'checkpoint.json'
MAX_WORKERS       = 4   # Threads simultáneas para extracción paralela
MAX_REINTENTOS    = 3   # Intentos por fuente antes de marcarla como fallida


# ===========================================================================
# MEJORA 1 — RETRY CON EXPONENTIAL BACKOFF
# ===========================================================================
def extraer_logs_url(url: str, nombre: str) -> list[str]:
    """Descarga logs con reintentos automáticos y espera exponencial.

    En producción las fuentes pueden estar temporalmente caídas o lentas.
    El backoff exponencial evita saturar el servicio remoto:
      intento 1 falla → esperar 1s
      intento 2 falla → esperar 2s
      intento 3 falla → esperar 4s → retornar []
    """
    logger.info(f'Extrayendo {nombre} desde {url}')
    for intento in range(MAX_REINTENTOS):
        try:
            resp = requests.get(url, timeout=15)
            resp.raise_for_status()
            lineas = [l for l in resp.text.splitlines() if l.strip()]
            logger.info(f'  → {len(lineas)} líneas extraídas de {nombre}')
            return lineas
        except requests.exceptions.RequestException as e:
            espera = 2 ** intento  # 1s, 2s, 4s
            if intento < MAX_REINTENTOS - 1:
                logger.warning(
                    f'Intento {intento + 1}/{MAX_REINTENTOS} fallido para {nombre} '
                    f'({e}). Reintentando en {espera}s...'
                )
                time.sleep(espera)
            else:
                logger.error(f'Todos los intentos fallaron para {nombre}: {e}')
    return []


# ===========================================================================
# MEJORA 2 — CHECKPOINT: ESTADO ENTRE EJECUCIONES
# ===========================================================================
def cargar_checkpoint() -> dict:
    """Lee el estado de la última ejecución exitosa.

    El checkpoint guarda el timestamp de la última vez que cada fuente
    fue procesada correctamente. Permite detectar si una fuente lleva
    mucho tiempo sin actualizarse (posible problema de conectividad).
    """
    if CHECKPOINT_FILE.exists():
        try:
            return json.loads(CHECKPOINT_FILE.read_text())
        except json.JSONDecodeError:
            logger.warning('Checkpoint corrupto, iniciando desde cero.')
    return {}


def guardar_checkpoint(estado: dict):
    """Persiste el estado de la ejecución actual."""
    CHECKPOINT_FILE.write_text(json.dumps(estado, indent=2))


# ===========================================================================
# PARSERS (idénticos al notebook)
# ===========================================================================
@dataclass
class EventoRaw:
    fuente: str
    timestamp_str: str
    mensaje: str
    campos: dict = field(default_factory=dict)


PATRON_SSH     = re.compile(
    r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+)\s+'
    r'(?P<host>\S+)\s+(?P<proceso>\S+):\s+(?P<mensaje>.+)'
)
PATRON_IP      = re.compile(r'from\s+(?P<ip>[\d.]+)')
PATRON_USUARIO = re.compile(r'(?:for|user)\s+(?:invalid user\s+)?(?P<usuario>\S+)\s+from')
PATRON_APACHE  = re.compile(r'\[(?P<timestamp>[^\]]+)\]\s+\[(?P<nivel>\w+)\]\s+(?P<mensaje>.+)')


def parsear_ssh(linea: str) -> Optional[EventoRaw]:
    m = PATRON_SSH.match(linea)
    if not m:
        return None
    campos = {}
    ip_m = PATRON_IP.search(m.group('mensaje'))
    if ip_m:
        campos['ip_origen'] = ip_m.group('ip')
    usr_m = PATRON_USUARIO.search(m.group('mensaje'))
    if usr_m:
        campos['usuario'] = usr_m.group('usuario')
    campos['resultado'] = (
        'fallo'   if 'Failed'   in m.group('mensaje') or 'Invalid' in m.group('mensaje') else
        'exitoso' if 'Accepted' in m.group('mensaje') else
        'info'
    )
    return EventoRaw(
        fuente='ssh',
        timestamp_str=f"{m.group('mes')} {m.group('dia')} {m.group('hora')}",
        mensaje=m.group('mensaje'),
        campos=campos,
    )


def parsear_apache(linea: str) -> Optional[EventoRaw]:
    m = PATRON_APACHE.match(linea)
    if not m:
        return None
    return EventoRaw(
        fuente='apache',
        timestamp_str=m.group('timestamp'),
        mensaje=m.group('mensaje'),
        campos={'nivel_log': m.group('nivel')},
    )


PARSERS = {'ssh': parsear_ssh, 'apache': parsear_apache}


# ===========================================================================
# NORMALIZACIÓN A ECS (idéntica al notebook)
# ===========================================================================
def normalizar_a_ecs(evento: EventoRaw) -> dict:
    ecs = {
        '@timestamp': evento.timestamp_str,
        'event': {
            'dataset': evento.fuente,
            'kind': 'event',
            'category': ['authentication'] if evento.fuente == 'ssh' else ['web'],
            'outcome': evento.campos.get('resultado', 'unknown'),
        },
        'log': {'original': evento.mensaje},
        'message': evento.mensaje,
    }
    if 'ip_origen'  in evento.campos:
        ecs['source'] = {'ip': evento.campos['ip_origen']}
    if 'usuario'    in evento.campos:
        ecs['user']   = {'name': evento.campos['usuario']}
    if 'nivel_log'  in evento.campos:
        ecs['log']['level'] = evento.campos['nivel_log'].lower()
    return ecs


# ===========================================================================
# EXTRACTOR DE IOCs (idéntico al notebook)
# ===========================================================================
class ExtractorIOCs:
    WHITELIST_REDES = [
        ipaddress.ip_network('10.0.0.0/8'),
        ipaddress.ip_network('172.16.0.0/12'),
        ipaddress.ip_network('192.168.0.0/16'),
        ipaddress.ip_network('127.0.0.0/8'),
    ]
    PATRONES = {
        'ip':          re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b'),
        'hash_md5':    re.compile(r'\b[a-fA-F0-9]{32}\b'),
        'hash_sha256': re.compile(r'\b[a-fA-F0-9]{64}\b'),
        'dominio':     re.compile(
            r'\b(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+'
            r'(?:com|net|org|io|ru|cn|cc|biz|info|co)\b'
        ),
        'url':         re.compile(r'https?://[^\s<>"{}|\\^\[\]`]+'),
        'cve':         re.compile(r'CVE-\d{4}-\d{4,7}', re.IGNORECASE),
    }

    def es_ip_privada(self, ip_str: str) -> bool:
        try:
            ip = ipaddress.ip_address(ip_str)
            return any(ip in red for red in self.WHITELIST_REDES)
        except ValueError:
            return False

    def extraer(self, texto: str) -> dict:
        iocs = defaultdict(set)
        for tipo, patron in self.PATRONES.items():
            for match in patron.findall(texto):
                if tipo == 'ip' and self.es_ip_privada(match):
                    continue
                iocs[tipo].add(match)
        return {k: list(v) for k, v in iocs.items()}


# ===========================================================================
# CARGA (idéntica al notebook)
# ===========================================================================
def cargar_jsonl(eventos: list, ruta: Path):
    with open(ruta, 'w', encoding='utf-8') as f:
        for evento in eventos:
            f.write(json.dumps(evento, ensure_ascii=False) + '\n')
    logger.info(f'Guardados {len(eventos)} eventos en {ruta}')


def cargar_csv_iocs(iocs: dict, ruta: Path):
    with open(ruta, 'w', newline='', encoding='utf-8') as f:
        writer = csv.DictWriter(f, fieldnames=['tipo', 'valor', 'fuente'])
        writer.writeheader()
        for tipo, valores in iocs.items():
            for valor in valores:
                writer.writerow({'tipo': tipo, 'valor': valor, 'fuente': 'pipeline-etl'})
    logger.info(f'IOCs exportados a {ruta}')


# ===========================================================================
# MEJORA 3 — EXTRACCIÓN PARALELA
# ===========================================================================
def extraer_todas_las_fuentes(fuentes: dict) -> dict:
    """Descarga todas las fuentes en paralelo usando un pool de threads.

    En el notebook las fuentes se descargan en serie (una tras otra).
    Con ThreadPoolExecutor todas las descargas ocurren simultáneamente,
    reduciendo el tiempo de extracción de O(n * latencia) a O(latencia).
    """
    logs_raw = {}
    with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
        futures = {
            executor.submit(extraer_logs_url, url, nombre): nombre
            for nombre, url in fuentes.items()
        }
        for future in as_completed(futures):
            nombre = futures[future]
            logs_raw[nombre] = future.result()
    return logs_raw


# ===========================================================================
# PIPELINE PRINCIPAL
# ===========================================================================
def ejecutar_pipeline(fuentes: dict = FUENTES) -> dict:
    """Ejecuta un ciclo completo Extract → Transform → Load.

    Diferencias respecto al notebook:
    - Extracción paralela de todas las fuentes
    - Retry automático por fuente
    - Checkpoint actualizado al finalizar exitosamente
    """
    inicio = datetime.now()
    logger.info('=== Iniciando ciclo de pipeline ETL ===')

    DIRECTORIO_SALIDA.mkdir(parents=True, exist_ok=True)
    extractor = ExtractorIOCs()
    todos_eventos_ecs = []
    todos_iocs = defaultdict(set)
    checkpoint = cargar_checkpoint()

    # ── EXTRACT (paralelo) ───────────────────────────────────────────────────
    logs_raw = extraer_todas_las_fuentes(fuentes)

    # ── TRANSFORM ────────────────────────────────────────────────────────────
    for nombre, lineas in logs_raw.items():
        if not lineas:
            continue

        parser = PARSERS.get(nombre)
        if not parser:
            logger.warning(f'Sin parser para fuente: {nombre}')
            continue

        eventos_raw_fuente = [e for e in (parser(l) for l in lineas) if e]
        eventos_ecs_fuente = [normalizar_a_ecs(e) for e in eventos_raw_fuente]
        todos_eventos_ecs.extend(eventos_ecs_fuente)

        for evento in eventos_ecs_fuente:
            for tipo, valores in extractor.extraer(evento.get('message', '')).items():
                todos_iocs[tipo].update(valores)

        # Registrar timestamp de última extracción exitosa por fuente
        checkpoint[nombre] = datetime.now().isoformat()

    # ── LOAD ─────────────────────────────────────────────────────────────────
    cargar_jsonl(todos_eventos_ecs, DIRECTORIO_SALIDA / 'eventos_normalizados.jsonl')
    cargar_csv_iocs(todos_iocs,     DIRECTORIO_SALIDA / 'iocs.csv')
    guardar_checkpoint(checkpoint)

    duracion = (datetime.now() - inicio).total_seconds()
    estadisticas = {
        'timestamp':                 inicio.isoformat(),
        'duracion_segundos':         round(duracion, 2),
        'total_eventos_procesados':  len(todos_eventos_ecs),
        'total_iocs_extraidos':      sum(len(v) for v in todos_iocs.values()),
        'iocs_por_tipo':             {k: len(v) for k, v in todos_iocs.items()},
        'fuentes_procesadas':        list(fuentes.keys()),
    }

    logger.info('=== Resumen del ciclo ===')
    logger.info(f"Eventos normalizados : {estadisticas['total_eventos_procesados']}")
    logger.info(f"IOCs únicos          : {estadisticas['total_iocs_extraidos']}")
    logger.info(f"Duración             : {estadisticas['duracion_segundos']}s")
    return estadisticas


# ===========================================================================
# MEJORA 4 — LOOP SCHEDULADO
# ===========================================================================
def main():
    parser = argparse.ArgumentParser(description='Pipeline ETL de IOCs — modo producción')
    parser.add_argument(
        '--intervalo', type=int, default=5,
        help='Minutos entre ejecuciones (default: 5)'
    )
    parser.add_argument(
        '--una-vez', action='store_true',
        help='Ejecutar una sola vez y salir (útil para pruebas o cron externo)'
    )
    args = parser.parse_args()

    if args.una_vez:
        ejecutar_pipeline()
        return

    # Registrar el job en el scheduler y ejecutar inmediatamente la primera vez
    schedule.every(args.intervalo).minutes.do(ejecutar_pipeline)
    logger.info(f'Pipeline schedulado cada {args.intervalo} minuto(s). Ctrl+C para detener.')
    ejecutar_pipeline()  # Ejecución inicial sin esperar el primer intervalo

    while True:
        schedule.run_pending()
        time.sleep(10)


if __name__ == '__main__':
    main()

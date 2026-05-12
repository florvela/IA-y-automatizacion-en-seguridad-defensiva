"""
soc/parsers.py — Extracción de campos desde líneas de log SSH.

Responsabilidad única: saber cómo leer el formato de log y nada más.
Si el formato del log cambia, este es el único archivo que hay que tocar.
"""
import re

PATRONES = {
    'failed_password': re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+)\s+\S+\s+\S+:\s+'
        r'Failed password for (?:invalid user )?(?P<usuario>\S+) from (?P<ip>[\d.]+) port (?P<puerto>\d+)'
    ),
    'invalid_user': re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+)\s+\S+\s+\S+:\s+'
        r'Invalid user (?P<usuario>\S+) from (?P<ip>[\d.]+)'
    ),
    'accepted': re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+)\s+\S+\s+\S+:\s+'
        r'Accepted (?P<metodo>\S+) for (?P<usuario>\S+) from (?P<ip>[\d.]+) port (?P<puerto>\d+)'
    ),
    'break_in': re.compile(
        r'(?P<mes>\w+)\s+(?P<dia>\d+)\s+(?P<hora>[\d:]+).*'
        r'POSSIBLE BREAK-IN ATTEMPT.*\[(?P<ip>[\d.]+)\]'
    ),
}


def parsear_log_ssh(linea: str) -> dict | None:
    """
    Parsea una línea de log SSH y devuelve un dict con los campos extraídos.
    Retorna None si la línea no corresponde a ningún patrón conocido.
    """
    for tipo, patron in PATRONES.items():
        match = patron.search(linea)
        if match:
            datos = match.groupdict()
            datos['tipo'] = tipo
            datos['raw'] = linea
            return datos
    return None

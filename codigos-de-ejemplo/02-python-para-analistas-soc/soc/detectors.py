"""
soc/detectors.py — Lógica de detección de amenazas sobre eventos parseados.

Responsabilidad única: recibir eventos ya normalizados y decidir qué es sospechoso.
No sabe nada del formato del log original — solo trabaja con dicts.
"""
from collections import defaultdict


def detectar_fuerza_bruta(eventos: list, umbral: int = 5) -> list:
    """
    Detecta IPs con comportamiento de fuerza bruta.

    Args:
        eventos: lista de dicts producidos por parsear_log_ssh()
        umbral:  cantidad mínima de intentos fallidos para considerar fuerza bruta

    Returns:
        Lista de dicts con IP, intentos, usuarios probados y nivel de riesgo,
        ordenada de mayor a menor cantidad de intentos.
    """
    intentos_por_ip = defaultdict(lambda: {'count': 0, 'usuarios': set()})

    for e in eventos:
        if e['tipo'] in ('failed_password', 'invalid_user'):
            ip = e.get('ip', 'unknown')
            intentos_por_ip[ip]['count'] += 1
            intentos_por_ip[ip]['usuarios'].add(e.get('usuario', 'unknown'))

    resultado = []
    for ip, datos in intentos_por_ip.items():
        if datos['count'] >= umbral:
            resultado.append({
                'ip': ip,
                'intentos': datos['count'],
                'usuarios_probados': list(datos['usuarios']),
                # ALTO: supera el doble del umbral (ej. >10 con umbral=5)
                'riesgo': 'ALTO' if datos['count'] >= umbral * 2 else 'MEDIO'
            })

    return sorted(resultado, key=lambda x: x['intentos'], reverse=True)

"""
soc/reporters.py — Agregación y presentación de resultados del análisis.

Responsabilidad única: tomar eventos y detecciones y construir resúmenes
legibles para analistas o para pasar al siguiente sistema (SOAR, SIEM, Jira).
"""
from soc.detectors import detectar_fuerza_bruta


def generar_resumen(eventos: list) -> dict:
    """
    Genera un resumen ejecutivo del análisis de una sesión de logs.

    Returns:
        Dict con totales, tasas y detalle de IPs sospechosas.
    """
    fallidos    = sum(1 for e in eventos if e['tipo'] == 'failed_password')
    exitosos    = sum(1 for e in eventos if e['tipo'] == 'accepted')
    sospechosas = detectar_fuerza_bruta(eventos)

    return {
        'total_eventos':       len(eventos),
        'intentos_fallidos':   fallidos,
        'accesos_exitosos':    exitosos,
        'ips_fuerza_bruta':    len(sospechosas),
        'detalle_sospechosas': sospechosas,
    }


def analizar_sesion_soc(logs: list[str], parsear_fn, umbral: int = 3) -> dict:
    """
    Pipeline completo: logs crudos → reporte listo para handoff de turno.

    Args:
        logs:      líneas de log sin procesar
        parsear_fn: función de parseo (inyectada para desacoplar de parsers.py)
        umbral:    intentos mínimos para considerar fuerza bruta
    """
    eventos = [e for e in (parsear_fn(l) for l in logs) if e]
    resumen = generar_resumen(eventos)
    sospechosas = resumen['detalle_sospechosas']

    accesos_exitosos = [
        {'ip': e['ip'], 'usuario': e['usuario']}
        for e in eventos if e['tipo'] == 'accepted'
    ]
    ips_sospechosas = {s['ip'] for s in sospechosas}
    comprometidos   = [a for a in accesos_exitosos if a['ip'] in ips_sospechosas]

    if comprometidos:
        recomendacion = '🔴 CRITICO: IPs con fuerza bruta lograron acceso. Investigar inmediatamente.'
    elif sospechosas:
        recomendacion = f'🟡 ATENCIÓN: {len(sospechosas)} IP(s) con fuerza bruta activa. Considerar bloqueo en firewall.'
    else:
        recomendacion = '🟢 Sin anomalías detectadas en este período.'

    return {
        'periodo_analizado':   f'{logs[0][:14]} → {logs[-1][:14]}',
        'total_eventos':       resumen['total_eventos'],
        'intentos_fallidos':   resumen['intentos_fallidos'],
        'accesos_exitosos':    accesos_exitosos,
        'ips_fuerza_bruta':    [s['ip'] for s in sospechosas],
        'posibles_compromisos': comprometidos,
        'recomendacion':       recomendacion,
    }

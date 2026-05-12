"""
soc — paquete de utilidades para análisis de logs SSH en el SOC.

API pública: importá directamente desde `soc` sin conocer la estructura interna.

    from soc import parsear_log_ssh, detectar_fuerza_bruta, generar_resumen
"""
from soc.parsers   import parsear_log_ssh, PATRONES
from soc.detectors import detectar_fuerza_bruta
from soc.reporters import generar_resumen, analizar_sesion_soc

__all__ = [
    'parsear_log_ssh',
    'PATRONES',
    'detectar_fuerza_bruta',
    'generar_resumen',
    'analizar_sesion_soc',
]

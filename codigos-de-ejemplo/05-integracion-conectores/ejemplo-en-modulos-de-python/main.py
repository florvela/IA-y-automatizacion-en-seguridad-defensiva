import os
import logging
from core import ConnectorRegistry
from connectors import ConectorVirusTotal, ConectorCrowdStrike, ConectorJira

logging.basicConfig(level=logging.INFO, format='%(asctime)s [%(levelname)s] %(message)s')

# ─────────────────────────────────────────────
#  CONFIGURACIÓN — cambiar USE_MOCK a False
#  y completar las variables de entorno para uso real
# ─────────────────────────────────────────────
USE_MOCK = True

VT_API_KEY         = os.environ.get('VT_API_KEY', 'TU_VT_API_KEY_AQUI')
CROWDSTRIKE_ID     = os.environ.get('CS_CLIENT_ID', 'TU_CS_ID_AQUI')
CROWDSTRIKE_SECRET = os.environ.get('CS_CLIENT_SECRET', 'TU_CS_SECRET_AQUI')
JIRA_URL           = os.environ.get('JIRA_URL', 'https://tu-org.atlassian.net')
JIRA_USER          = os.environ.get('JIRA_USER', 'analista@empresa.com')
JIRA_TOKEN         = os.environ.get('JIRA_TOKEN', 'TU_JIRA_TOKEN_AQUI')


def inicializar_registry() -> ConnectorRegistry:
    """Crea el registry y registra todos los conectores."""
    registry = ConnectorRegistry()
    registry.registrar('virustotal',  ConectorVirusTotal(VT_API_KEY, use_mock=USE_MOCK))
    registry.registrar('crowdstrike', ConectorCrowdStrike(CROWDSTRIKE_ID, CROWDSTRIKE_SECRET, use_mock=USE_MOCK))
    registry.registrar('jira',        ConectorJira(JIRA_URL, JIRA_USER, JIRA_TOKEN, use_mock=USE_MOCK))
    return registry


def responder_a_malware(alerta: dict, registry: ConnectorRegistry) -> dict:
    """
    Pipeline completo de respuesta a detección de malware.
    Solo habla con el registry — no sabe nada de los conectores internamente.
    """
    vt   = registry.obtener('virustotal')
    cs   = registry.obtener('crowdstrike')
    jira = registry.obtener('jira')

    print(f'\n{"="*55}')
    print(f' RESPUESTA AUTOMÁTICA A MALWARE')
    print(f'{"="*55}')
    print(f' Hash:      {alerta["hash"]}')
    print(f' Endpoint:  {alerta["hostname"]}')
    print(f'{"="*55}')

    # 1. Enriquecimiento con VirusTotal
    print('\n[1/4] Consultando VirusTotal...')
    vt_resultado = vt.analizar_hash(alerta['hash'])
    es_malicioso = vt_resultado.get('veredicto') == 'MALICIOSO'
    print(f'      Veredicto: {vt_resultado["veredicto"]} | Detecciones: {vt_resultado.get("malicious", 0)}')

    if not es_malicioso:
        print('\n→ Hash no confirmado como malicioso. Cerrando sin acción.')
        return {'resultado': 'falso_positivo'}

    # 2. Localizar dispositivo
    print('\n[2/4] Localizando endpoint en CrowdStrike...')
    dispositivo = cs.buscar_dispositivo(alerta['hostname'])
    print(f'      Encontrado: {dispositivo["hostname"]} | IP: {dispositivo["ip_local"]}')

    # 3. Aislar dispositivo
    print('\n[3/4] Aislando endpoint...')
    aislado = cs.aislar_dispositivo(dispositivo['device_id'])
    print(f'      Aislamiento: {"✓ EXITOSO" if aislado else "✗ FALLÓ"}')

    # 4. Crear ticket de incidente
    print('\n[4/4] Creando ticket en Jira...')
    detecciones = vt_resultado.get('malicious', 0)
    ticket = jira.crear_ticket(
        titulo=f'[CRÍTICO] Malware en {alerta["hostname"]} — {detecciones} detecciones VT',
        descripcion=(
            f'Hash: {alerta["hash"]}\n'
            f'Endpoint: {alerta["hostname"]} ({dispositivo["ip_local"]})\n'
            f'VirusTotal: {detecciones}/73 motores\n'
            f'Estado: dispositivo aislado automáticamente'
        ),
        prioridad='Highest'
    )
    print(f'      Ticket: {ticket["id"]} → {ticket["url"]}')
    print(f'\n→ Respuesta completada. Endpoint aislado. Ticket abierto.')

    return {'resultado': 'contenido', 'ticket': ticket['id'], 'aislado': aislado}


if __name__ == '__main__':
    print(f'Modo: {"MOCK (demo sin credenciales)" if USE_MOCK else "REAL (usando APIs reales)"}\n')

    registry = inicializar_registry()

    print('--- Health Check ---')
    estado = registry.verificar_todos()
    for nombre, ok in estado.items():
        print(f'  {"✓" if ok else "✗"} {nombre}')

    alerta_malware = {
        'hash': '44d88612fea8a8f36de82e1278abb02f',
        'hostname': 'LAPTOP-FINANCE-01',
        'proceso': 'invoice_q4.exe',
        'ruta': r'C:\Users\jsmith\Downloads\invoice_q4.exe'
    }

    resultado = responder_a_malware(alerta_malware, registry)
    print(f'\nResumen: {resultado}')

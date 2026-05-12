# Ejemplo en módulos de Python — Integración y Conectores

Este directorio muestra cómo se vería la arquitectura de conectores del módulo 05 organizada en archivos separados, tal como viviría en un proyecto real.

El mismo código del notebook, pero estructurado como un paquete Python.

## Estructura

```
ejemplo-en-modulos-de-python/
├── core/
│   ├── __init__.py      # Exporta ConectorBase y ConnectorRegistry
│   ├── base.py          # Clase abstracta ConectorBase (contrato común)
│   └── registry.py      # ConnectorRegistry (registro centralizado)
├── connectors/
│   ├── __init__.py      # Exporta todos los conectores
│   ├── virustotal.py    # Conector VirusTotal
│   ├── crowdstrike.py   # Conector CrowdStrike EDR
│   └── jira.py          # Conector Jira
└── main.py              # Punto de entrada: inicializa registry y ejecuta el pipeline
```

**`core/`** contiene el framework (contrato + orquestador) — se toca rara vez.  
**`connectors/`** contiene las implementaciones — crece con cada nueva integración.  
Agregar un conector nuevo = crear un archivo en `connectors/` y registrarlo en `main.py`.

## Cómo correrlo

```bash
python main.py
```

Corre en modo mock por defecto — no requiere credenciales reales. Para usar APIs reales, cambiar `USE_MOCK = False` en `main.py` y setear las variables de entorno:

```bash
export VT_API_KEY="tu_api_key"
export CS_CLIENT_ID="tu_client_id"
export CS_CLIENT_SECRET="tu_client_secret"
export JIRA_URL="https://tu-org.atlassian.net"
export JIRA_USER="analista@empresa.com"
export JIRA_TOKEN="tu_token"
```

## Arquitectura

El patrón central es el **ConnectorRegistry**: se crea al arrancar, y cada conector se registra ahí. Los playbooks y pipelines nunca instancian conectores directamente — solo piden al registry lo que necesitan.

```
main.py
  └── inicializar_registry()
        ├── registrar('virustotal',  ConectorVirusTotal(...))
        ├── registrar('crowdstrike', ConectorCrowdStrike(...))
        └── registrar('jira',        ConectorJira(...))

responder_a_malware(alerta, registry)
  ├── registry.obtener('virustotal')  → analizar_hash()
  ├── registry.obtener('crowdstrike') → buscar_dispositivo() + aislar_dispositivo()
  └── registry.obtener('jira')        → crear_ticket()
```

Todos los conectores heredan de `core.base.ConectorBase`, que provee logging estructurado y reintentos con backoff exponencial. Cada conector solo implementa la lógica específica de su API.

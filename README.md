# IA y Automatización en Seguridad Defensiva

Material del módulo 4 del curso de seguridad defensiva dictado en Hackademy.  

---

## Estructura del módulo

El módulo está organizado en 9 clases. Cada directorio contiene los markdowns de estudio y, cuando corresponde, los códigos de ejemplo están en `codigos-de-ejemplo/`.

| Clase | Contenido |
|:------|:----------|
| `01-por-que-automatizar` | El problema del volumen de alertas, criterios para automatizar y cuándo no hacerlo |
| `02-fundamentos-python` | Python para analistas SOC, buenas prácticas |
| `03-pipelines-e-iocs` | Pipelines ETL en seguridad, extracción de IOCs desde texto |
| `04-fundamentos-soar` | Runbooks, playbooks, plataformas SOAR, integraciones, scoring de riesgo |
| `05-integracion-conectores` | Desarrollo de conectores con patrón ConectorBase |
| `06-introduccion-ia-ml` | Machine learning aplicado a seguridad, métricas, overfitting |
| `07-ml-seguridad-anomalias` | Detección de anomalías, UEBA |
| `08-nlp-y-llms` | NLP, cómo funcionan los LLMs, alucinaciones, casos de uso en el SOC |
| `09-mcp-en-seguridad` | Model Context Protocol, construir servidores MCP, demo final |

## Códigos de ejemplo

```
codigos-de-ejemplo/
├── 02-python-para-analistas-soc/
├── 03-pipeline-etl-iocs/
├── 04-fundamentos-soar/
├── 05-integracion-conectores/
└── demo_final/
```

## Requisitos

```bash
pip install anthropic requests ioc-finder scikit-learn pandas mcp
```
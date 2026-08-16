# Guía de la clase en vivo — dónde presentar cada código

Clase de ~2 horas. El guión (`todo-lo-que-digo.pdf`) tiene 177 diapositivas y ya
incluye momentos de **"Veamos un ejemplo"** que apuntan a Google Colab. Estos son
los notebooks cortos que van en esos momentos, más la demo final.

Todos los notebooks abren en Colab con el botón que tienen arriba, y usan
imágenes traídas del repo (carpeta `/images` de cada clase).

| # | Notebook | Presentar entre slides | Tema | Reemplaza / condensa |
|---|----------|------------------------|------|----------------------|
| 1 | `live_01_python.ipynb` | **P40 → P41** | Buenas prácticas: regex, credenciales, logging, reintentos | `02-python-para-analistas-soc/` |
| 2 | `live_02_etl_iocs.ipynb` | **P63 → P64** | Mini pipeline ETL + extracción de IOCs | `03-pipeline-etl-iocs/` |
| 3 | `live_03_soar.ipynb` | **P78 → P79** | Runbook vs Playbook (antes del demo de Shuffle) | `04-fundamentos-soar/` |
| 4 | `live_04_conectores.ipynb` | **P86 → P89** | ConectorBase + Registry (mock) | `05-integracion-conectores/` |
| 5 | `live_05_ml.ipynb` | **P120 → P121** | Isolation Forest para anomalías (UEBA) | *nuevo* (no había demo en ese tramo) |
| 6 | `live_06_llm.ipynb` | **P152** ("Python para LLMs") | Llamada mínima a un LLM + triage de alertas | *nuevo* (amplía el snippet del slide) |
| — | `../demo_final/` | **P168** (cierre) | Pipeline SOC completo: ML → NLP → LLM → MCP → human-in-the-loop | se corre **local** en la terminal |

## Detalle por notebook

### 1 · `live_01_python.ipynb` — entre P40 y P41
El guión en P40 dice "Aca tenemos dos links, uno a Google Colab...". Ahí abrís este notebook.
4 celdas cortas alineadas con los slides P30 (regex), P32 (credenciales), P36 (logging) y P39 (resiliencia).

### 2 · `live_02_etl_iocs.ipynb` — entre P63 y P64
P63 dice "vamos a construir el pipeline paso a paso en el notebook". Extract → Transform
(normalización + dedup) y después extracción de IOCs con las regex del slide P58.

### 3 · `live_03_soar.ipynb` — entre P78 y P79
P78 dice "[ABRIR COLAB]" y muestra el runbook y el playbook. Este notebook tiene los dos.
Después, en P79, volvés al slide y hacés la demo de **Shuffle** desde GitHub (eso queda igual).

### 4 · `live_04_conectores.ipynb` — entre P86 y P89
P86 dice "Demo de conectores en Google Colab / github". Versión chica del framework de
`05-integracion-conectores`: `ConectorBase`, dos conectores con `mock`, `registry` y el
pipeline `responder_a_malware`.

### 5 · `live_05_ml.ipynb` — entre P120 y P121
El tramo de ML/anomalías (P90–P126) no tenía código en vivo. Este notebook entrena un
`IsolationForest` sobre tráfico simulado y detecta anomalías → conecta con UEBA (P121–P125).
Requiere `scikit-learn` + `matplotlib` (ya vienen en Colab).

### 6 · `live_06_llm.ipynb` — en P152
P152 muestra el "código mínimo" para llamar a un LLM. Este notebook lo ejecuta de verdad
(pide la API key con `getpass`, nunca hardcodeada) y agrega el caso de uso de **triage** con
salida JSON, más el recordatorio de verificar (P148/P157). Usa el modelo `claude-opus-5`.

### Demo final · `../demo_final/` — en P168
La demo final es una app de terminal (Rich + Ollama local + MCP por subproceso). Se corre
en tu máquina, no en Colab:

```bash
cd codigos-de-ejemplo/demo_final
pip install -r requirements.txt      # scikit-learn, ollama, mcp, rich...
python train_models.py               # entrena Isolation Forest + clasificador NLP
python demo.py                       # corre el pipeline de 6 pasos
```

El `mcp_server.py` ya quedó **completo con las tres primitivas de MCP**:
- **Tools**: `check_ip_reputation`, `create_incident_ticket`, `propose_host_isolation`
- **Resources** (nuevo): `soc://config`, `soc://runbooks/{tipo}`, `soc://tickets`
- **Prompts** (nuevo): `triage_alerta`, `reporte_incidente`

Así, cuando en P165 explicás "Tools / Resources / Prompts", la demo muestra las tres.

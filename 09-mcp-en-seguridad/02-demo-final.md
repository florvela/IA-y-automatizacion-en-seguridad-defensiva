# Demo Final: Pipeline SOC Completo

Este demo integra todas las clases del módulo en un solo pipeline funcional. 

El código completo está en el repositorio del curso: https://github.com/florvela/IA-y-automatizacion-en-seguridad-defensiva

---

## Los tres scripts del demo

### `generate_data.py`
Genera un dataset sintético de eventos de tráfico de red en tres formatos: CSV, NDJSON y Parquet. Los eventos simulan tráfico normal mezclado con anomalías (exfiltración de datos, conexiones a IPs maliciosas, volúmenes inusuales de transferencia). Este script existe porque en un SOC real los datos vienen del ETL, acá simplemente lo simulamos para que el demo sea reproducible sin necesitar infraestructura real.

### `train_models.py`
Entrena dos modelos sobre el dataset generado:
1. **Isolation Forest** — para detectar eventos anómalos
2. **Clasificador NLP** (TF-IDF + Naive Bayes) — para identificar el tipo de amenaza a partir del texto del evento

Guarda los modelos entrenados en disco para que `demo.py` los pueda cargar sin reentrenar cada vez.

### `demo.py`
Corre el pipeline completo, paso a paso, con un evento de entrada.

---

## El pipeline, paso a paso

```
Evento entrante
      │
      ▼
┌─────────────────────────────────────────────────────┐
│  PASO 1: Evento de red sospechoso                   │
│  bytes_enviados=9500000, dst_port=443,              │
│  duración=0.3s, conexiones_distintas=1              │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  PASO 2: Isolation Forest detecta anomalía          │
│  → El modelo devuelve -1 (outlier)                  │
│  → El evento se desvía del comportamiento normal    │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  PASO 3: Clasificador NLP identifica la amenaza     │
│  → Lee el texto del evento                          │
│  → Clasifica como: DATA_EXFILTRATION                │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  PASOS 4 + 5: LLM + MCP (tool-calling loop)         │
│  → LLM recibe el evento enriquecido con el contexto │
│  → Decide llamar a la tool vt_check_ip              │
│  → MCP ejecuta la llamada a VirusTotal              │
│  → LLM recibe el resultado: IP maliciosa confirmada │
│  → Decide llamar a la tool create_ticket            │
│  → MCP crea el ticket en el sistema de casos        │
└──────────────────────┬──────────────────────────────┘
                       │
                       ▼
┌─────────────────────────────────────────────────────┐
│  PASO 6: Human-in-the-Loop                          │
│  → El sistema pausa y muestra el análisis completo  │
│  → El analista lee: evento, veredicto, evidencia    │
│  → Decisión: ¿aislar el host? [s/n]                 │
│  → Solo si el analista confirma → se ejecuta        │
│    la acción de aislamiento en el EDR               │
└─────────────────────────────────────────────────────┘
```

---

## Qué clase del módulo aparece en cada paso

| Paso                   | Qué hace                                              | Clase                     |
| ---------------------- | ----------------------------------------------------- | ------------------------- |
| Generación del dataset | ETL: generate_data produce CSV/NDJSON/Parquet         | Pipelines ETL             |
| Paso 1                 | Evento normalizado llega al pipeline                  | Pipelines ETL (Transform) |
| Paso 2                 | Isolation Forest detecta que el evento es outlier     | ML y Anomalías            |
| Paso 3                 | Clasificador NLP identifica DATA_EXFILTRATION         | NLP y LLMs                |
| Pasos 4+5              | LLM razona, MCP ejecuta tools (VirusTotal, ticketing) | LLMs y MCP                |
| Paso 6                 | El sistema pausa y espera aprobación del analista     | human-in-the-loop         |

El punto de la demo es mostrar que cada clase no es un tema aislado: son capas que se apilan. El ETL produce los datos limpios que necesita el modelo de ML. El modelo de ML produce un score que necesita el clasificador NLP. El NLP produce un contexto que necesita el LLM. El LLM produce recomendaciones que necesita el analista para decidir.

---

## Cómo correr la demo

```bash
# 1. Clonar el repositorio
git clone https://github.com/florvela/IA-y-automatizacion-en-seguridad-defensiva
cd IA-y-automatizacion-en-seguridad-defensiva

# 2. Instalar dependencias
pip install -r requirements.txt

# 3. Generar el dataset
python generate_data.py

# 4. Entrenar los modelos
python train_models.py

# 5. Correr el pipeline completo
python demo.py
```

# 🛡️ Laboratorio SOC — Automatización + IA para Blue Team

Lab para una clase en vivo. Un solo `docker compose up -d` levanta **todo**:

> **ataque SSH → Wazuh → worker Python (enrichment) → soar-bridge (IA + MCP) → email con link → human-in-the-loop → reporte de cierre**

Herramientas reales. Código Python (inglés) con comentarios en español.

---

## 🧠 La idea

Ver **[`diagrama.md`](diagrama.md)**. En corto: Wazuh detecta brute force SSH y avisa al
**soc-worker** (Python en background), que hace enrichment determinista (simula VirusTotal)
y reenvía al **SOAR-bridge**. La **IA** escribe la RESOLUCION; el mail trae link al ticket.
Bloquear la IP requiere **aprobación humana** (`block_ip` sin `approved=True` no ejecuta).
Si el worker falla, `custom-soar.py` hace fallback directo al bridge.

**Cero setup manual** — no hay UI de SOAR que importar ni workflows que configurar.

### Antes de la clase (opcional, una vez)

El scoring incluye una señal ML (`anomalia_ml`: One-Class SVM tabular sobre
user/host/IP/hora/país). Los pesos `data/ml/one_class_svm.joblib` ya vienen
en el repo. Si querés re-entrenar:

```bash
pip install scikit-learn joblib numpy
python scripts/train_anomaly_model.py
```

Sin artefactos, el lab sigue: esa categoría suma 0.

---

## ✅ Requisitos (importante)

- Docker Desktop con **al menos 8 GB de RAM** asignados (Settings → Resources).
  Son ~11 contenedores: Wazuh (indexer/manager/dashboard) + Ollama + los del lab.
- El indexer de Wazuh pide `vm.max_map_count=262144`. En Mac/Docker Desktop **no**
  se setea con `sysctl` del host; se hace dentro del VM de Docker (ver abajo).

---

## 🚀 Levantar TODO desde cero

```bash
# 1) (Mac/Docker Desktop) max_map_count del VM de Docker — una vez por reinicio:
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144

# 2) Limpiar cualquier cosa que tengas de Docker (libera puertos como el 9000):
docker stop $(docker ps -q)
docker rm $(docker ps -aq)

# 3) Levantar el lab completo:
docker compose down -v --remove-orphans
docker compose build --no-cache
docker compose up -d
docker compose ps
```

**La primera vez tarda** (baja imágenes de Wazuh y el modelo `llama3.2`
de Ollama, ~2 GB). Dale unos minutos y volvé a mirar `docker compose ps`.

### Tiempos de arranque

- **Ollama** descarga `llama3.2` en segundo plano (servicio `soc-ollama-init`).
  Mientras tanto, la IA **cae a mock automáticamente** para no fallar.
- **Wazuh** tarda 2-3 min en quedar operativo (el indexer arranca lento).

---

## 🖥️ URLs (Safari)

| Servicio | URL | Credenciales |
|---|---|---|
| **Dashboard SOAR** (incidentes + aprobar) | http://localhost:9000 | — |
| **Wazuh** (SIEM) | https://localhost:443 | admin / SecretPassword |
| **Jupyter** | http://localhost:8888/?token=lab | token: `lab` |

En Wazuh te va a avisar del certificado autofirmado → "Mostrar detalles" → "visitar de todas formas".

---

## ▶️ Correr la demo

**1.** Dejá abierto el dashboard (http://localhost:9000).

**2.** (Opcional) Seguí el worker en vivo:

```bash
docker compose logs -f soc-worker
```

**3.** Disparás el ataque (¡`exec`, no `run`, porque el atacante ya está corriendo!):

```bash
docker compose exec attacker python brute_force.py
```

**4.** A los ~5 intentos fallidos, Wazuh detecta el brute force y aparece
un incidente **HIGH / awaiting_approval** en el dashboard.

**5.** Mirá el mail (con runbook) y el ticket:

```bash
docker compose exec soar-bridge sh -c 'cat /data/state/mailbox/*.eml'
docker compose exec soar-bridge sh -c 'cat /data/state/tickets/*.json'
```

**6.** En el dashboard, **Aprobar bloqueo** → el incidente pasa a **actioned** y se
escribe la IP en `blocklist`. Ese es el human-in-the-loop.

En **Wazuh** (https://localhost:443) el mismo ataque aparece en *Security events*
como regla **5712 (SSH brute force)**.

---

## 🤖 El LLM

Por defecto usa **Ollama** (`llama3.2`, local, no manda datos a la nube). Si el
modelo todavía se está descargando, cae a `mock` solo. Para cambiar, editá `.env`:

```bash
SOC_LLM_BACKEND=ollama    # local (default)
SOC_LLM_BACKEND=openai    # API (poné SOC_OPENAI_API_KEY)
SOC_LLM_BACKEND=mock      # determinístico, para que la demo nunca falle
```
Después: `docker compose up -d soar-bridge jupyter`.

---

## 📁 Estructura

```
docker-compose.yml        TODO EN UNO (Wazuh vendorizado + servicios Python)
soc/                      Paquete compartido (el "cerebro"): agente, MCP, IA, aprobación
services/
  ├── worker/app.py       Worker SOC: Wazuh → enrichment → bridge
  ├── mcp/server.py       Servidor MCP (tools). block_ip requiere approved=True
  ├── soar/app.py         SOAR-bridge (FastAPI): webhook + dashboard + aprobación
  ├── siem/siem_lite.py   Detector liviano (respaldo de Wazuh)
  ├── victim/             sshd + rsyslog -> reenvía a Wazuh
  └── attacker/           Fuerza bruta SSH con paramiko
wazuh/vendor/             Wazuh oficial (single-node) + config
wazuh/custom-soar*.py     Integración Wazuh -> soc-worker
notebooks/                Notebook del flujo completo
data/                     blacklist.txt + users.json + ml/ (One-Class SVM + meta)
GUION-CLASE.md            Guion para la demo en vivo
scripts/train_anomaly_model.py   Train offline OneClassSVM tabular → data/ml/
```

---

## 📋 Seguimiento

- [ ] `docker compose ps` muestra todo `Up` (Wazuh puede tardar 2-3 min).
- [ ] http://localhost:9000 abre (dashboard vacío).
- [ ] https://localhost:443 abre Wazuh (admin/SecretPassword).
- [ ] Disparaste el ataque (`docker compose exec attacker python brute_force.py`).
- [ ] Apareció el incidente HIGH / awaiting_approval.
- [ ] Viste el mail y el ticket; aprobaste → actioned + blocklist.
- [ ] En Wazuh viste la regla 5712.

---

## 🔧 Troubleshooting

- **Un servicio en `Restarting`:** `docker compose logs <servicio>`.
- **Wazuh indexer no arranca:** casi siempre `vm.max_map_count`. Corré el `docker run --privileged ... sysctl` de arriba y reintentá.
- **Puerto ocupado (9000/443/8888):** matá lo que lo use (`sudo lsof -nP -iTCP:<puerto> -sTCP:LISTEN`) o pará el otro contenedor.
- **El ataque dice "Address already in use":** usaste `run` en vez de `exec`. Es `docker compose exec attacker ...`.
- **Reset total:** `docker compose down -v --remove-orphans` y volvés a `up`.

---

## 🔬 Qué es real y qué está simulado

- **Real:** el ataque SSH (paramiko), la detección (Wazuh + siem-lite sobre logs
  reales de sshd), el ciclo MCP (tool-calling real), el LLM (Ollama razonando).
- **Simulado:** la reputación de IP sale de una blacklist local
  (`data/blacklist.txt`), no de una consulta real a VirusTotal/AbuseIPDB. La IP del
  atacante (`172.20.0.66`) está en esa lista para que la demo sea determinística.

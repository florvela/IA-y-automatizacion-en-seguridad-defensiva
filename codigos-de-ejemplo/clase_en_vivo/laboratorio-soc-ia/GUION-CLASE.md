# 🎬 Guion de la clase en vivo — Demo SOC con IA

> Demo: **ataque SSH → Wazuh (SIEM) → worker Python (enrichment) → IA (LLM + MCP) → email con link → aprobación humana → reporte de cierre**.
> Duración: 20-30 min.

---

## ⏱️ ANTES de empezar (10-15 min antes)

```bash
cd /Users/prisci/Documents/gitrepos/hackademy/IA-y-automatizacion-en-seguridad-defensiva/codigos-de-ejemplo/clase_en_vivo/laboratorio-soc-ia
cp .env.example .env
docker run --rm --privileged alpine sysctl -w vm.max_map_count=262144
docker compose down -v --remove-orphans
docker compose build
docker compose up -d
docker compose ps
```

Esperá 2-3 min. Chequeá: `wazuh.manager`, `soc-soar`, `soc-worker`, `soc-ollama` en `Up`.

**LLM:** por defecto el `.env` usa `SOC_LLM_BACKEND=mock` (rápido, demo fiable).
Si querés Ollama real: `SOC_LLM_BACKEND=ollama` y `docker compose up -d soar-bridge`
(si Ollama tarda >45s, cae a mock solo).

**Pestañas abiertas:**

| Pestaña | URL |
|---|---|
| SOAR dashboard | http://localhost:9000 |
| Wazuh | https://localhost:443 (`admin` / `SecretPassword`) |

Terminal en la carpeta del lab (opcional: `docker compose logs -f soc-worker` para ver el enrichment en vivo).

---

## 🎤 EL GUION

### Paso 0 — Presentar (1 min)
> "Un SOC en miniatura: SIEM real, enrichment automático en Python, IA que interpreta, y un humano que aprueba lo irreversible."

---

### Paso 1 — Wazuh (SIEM) · 2 min
**Dónde:** https://localhost:443 → Security events

> "Acá caen los eventos. Ahora está tranquilo; en un minuto aparece el brute force SSH."

---

### Paso 2 — Worker SOC (automatización) · 2 min
**Dónde:** terminal — `docker compose logs -f soc-worker`

> "Un proceso Python corre en background: recibe la alerta de Wazuh, consulta reputación de IP (simula VirusTotal), y manda el ticket enriquecido al bridge. **Acá no hay IA ni UI que configurar.**"

Mostrá el log cuando llegue una alerta: `Alerta … — IP … — enriqueciendo…` → `Playbook OK`.

---

### Paso 3 — Dashboard SOAR · 1 min
**Dónde:** http://localhost:9000 — vacío

> "El bridge recibe el ticket ya enriquecido, la IA escribe la RESOLUCION, manda un mail con link, y yo apruebo si hace falta bloquear."

---

### Paso 4 — EL ATAQUE · 2 min
```bash
docker compose exec attacker python brute_force.py
```

> "Fuerza bruta SSH real. ¿Cuándo salta la alarma? Al 5º intento."

---

### Paso 5 — Aparece el incidente · 2 min
**Dónde:** http://localhost:9000

> "Wazuh → worker (enrichment) → bridge → IA. Un incidente HIGH, awaiting_approval."

Wazuh: regla **5551** (PAM) o **5712**/**5763** (sshd). Al SOAR llega la primera; el resto se deduplican por IP.

---

### Paso 6 — El email · 1 min
```bash
docker compose exec soar-bridge sh -c 'cat /data/state/mailbox/*alert*.eml | tail -40'
```

> "Mail al analista con **DATA RECIBIDA** (enrichment), **RESOLUCION** (IA), y **link** al ticket."

---

### Paso 7 — Abrir el incidente · 3 min
Clic en el incidente en `:9000`.

> "Arriba: **DATA RECIBIDA EN EL TICKET** — hechos + **scoring multi-señal** (alerta, usuario, activo, contexto, threat intel, **anomalia_ml**). La IA no inventó el número."
> "Además del score por reglas, hay **One-Class SVM** tabular (user/host/IP/hora/país); mirá la categoría `anomalia_ml` en el breakdown del ticket."
> "Abajo: **RESOLUCION** — interpretación de la IA."
> "Score alto → cola prioritaria → acción propuesta: block_ip — **esperando mi OK**."

El breakdown del score está en el ticket (y en `soc/scoring.py`).

---

### Paso 8 — Human-in-the-loop · 2 min
Botón **Aprobar bloqueo**.

```bash
docker compose exec soar-bridge sh -c 'ls /data/state/blocklist/ && cat /data/state/blocklist/*.json'

```

> "Recién ahora se bloquea — mirá: la IP quedó escrita en la blocklist. Y el **reporte de cierre** se genera solo."

---

### Paso 9 — Cierre · 2 min
> "Resumen: detectar (Wazuh) → enriquecer (Python) → interpretar (IA) → decidir (humano) → cerrar (automático)."
> "No automatizamos todo: automatizamos lo repetible y dejamos al humano lo irreversible."

**Opcional si preguntan por notebooks:** Jupyter (`:8888`) es para **hunting** / casos sin playbook — no para el brute force que ya está automatizado.

---

## 🧯 Si algo falla

| Problema | Solución |
|---|---|
| No aparece incidente | `docker compose logs wazuh.manager --tail=30 \| grep integratord` — si dice "write permissions", reiniciá manager tras `docker compose up -d` |
| Worker caído | `docker compose restart soc-worker` — fallback en `custom-soar.py` manda al bridge igual |
| Repetir ataque | Mismo comando `exec` |
| Reset | `docker compose down -v && docker compose up -d` |

## 🔐 Credenciales

| Servicio | URL | Usuario | Contraseña |
|---|---|---|---|
| SOAR | http://localhost:9000 | — | — |
| Wazuh | https://localhost:443 | admin | SecretPassword |
| Jupyter (opcional) | http://localhost:8888/?token=lab | — | token `lab` |

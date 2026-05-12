# Cómo ejecutar la demo — Módulo 04

---

## Paso 1 — Levantar Shuffle

```bash
cd codigos-de-ejemplo/04-fundamentos-soar/shuffle/
docker compose up -d
```

Esperar ~2 minutos y verificar que todo esté corriendo:

```bash
docker compose ps
```

Todos los contenedores tienen que estar en estado `running`. Shuffle ya está en http://localhost:3001

Si el frontend muestra "Waiting for the Shuffle database to become available":

```bash
docker compose up -d --force-recreate backend
# esperar ~15 segundos y volver a abrir http://localhost:3001
```

---

## Paso 2 — Instalar dependencias

```bash
pip install requests
```

---

## Paso 3 — Crear el workflow con el script

```bash
cd codigos-de-ejemplo/04-fundamentos-soar/demo/
python setup_workflow.py
```

El script hace login, crea los 6 nodos con todas las conexiones, y al final imprime la URL del workflow:

```
✓ Login OK — usuario: admin
✓ Shuffle Tools app_id: a524a018-...
✓ Workflow creado — ID: xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx

 Abrir en Shuffle:
  http://localhost:3001/workflows/xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

Abrir esa URL — vas a ver los 6 nodos conectados con flechas.

---

## Paso 4 — Agregar el webhook trigger

El webhook no se puede crear via API — este es el único paso manual:

1. Abrir el workflow en Shuffle
2. Panel izquierdo → **Triggers**
3. Arrastrá **Webhook** al canvas
4. Conectarlo al nodo **Paso 1 — Recolectar datos**: arrastrá desde la salida del webhook hasta la entrada del Paso 1
5. Click en el nodo webhook → toggle **ON**
6. Copiar la URL que aparece — se ve así:

```
http://localhost:3001/api/v1/hooks/webhook-xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
```

7. Click **Save**

---

## Paso 5 — Ver el payload antes de enviar (opcional)

```bash
python trigger_alert.py --dry-run
```

---

## Paso 6 — Disparar la alerta

```bash
python trigger_alert.py --url <URL-DEL-WEBHOOK>
```

---

## Paso 7 — Ver la ejecución en Shuffle

1. Click en **Runs** en el menú izquierdo
2. Click en la ejecución para ver los nodos en verde

---

## Paso 8 — Probar con otra IP

```bash
# Ataque crítico
python trigger_alert.py --url <URL-DEL-WEBHOOK> --intentos 150

# IP y usuario distintos
python trigger_alert.py --url <URL-DEL-WEBHOOK> --ip 45.33.32.156 --usuario postgres --intentos 90
```

---

## Recrear el workflow desde cero

Si el workflow se rompe o hay que empezar de nuevo:

```bash
# 1. Borrar el workflow roto en Shuffle UI (Workflows → tres puntos → Delete)
# 2. Volver a correr el script
python setup_workflow.py
# 3. Agregar el webhook trigger manualmente (Paso 4)
```

---

## Apagar Shuffle

```bash
cd codigos-de-ejemplo/04-fundamentos-soar/shuffle/
docker compose down
```

Para borrar todos los datos también (workflows, runs, configuración):

```bash
docker compose down -v
```

---

## Ver logs si algo falla

```bash
docker compose logs -f backend
docker compose logs -f orborus
```

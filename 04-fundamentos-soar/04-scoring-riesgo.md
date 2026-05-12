# Scoring de Riesgo Automatizado

En el SOC, el volumen de alertas es insostenible: un SIEM grande genera decenas de miles de alertas diarias. Los analistas no pueden investigar todas. El scoring de riesgo es la técnica de **asignar un score (puntaje) a cada alerta** que refleja cuán probable es que sea una amenaza real y cuán grave sería si fuera verdadera.

La idea es usar scorings para poder priorizar alertas y que los analistas pierdan tiempo revisando falsos positivos.

---

## 1. Qué es el scoring de riesgo en el SOC

El scoring combina múltiples señales en una puntuación única entre 0 y 100:

```
Riesgo = f(tipo_alerta, severidad, contexto_usuario, historial_dispositivo, threat_intel)

Ejemplo:
Alerta: "Acceso a recurso financiero sensible"
  Tipo de evento:      20 pts  (acceso a recurso, no el peor tipo)
  Criticidad activo:   25 pts  (datos financieros)
  Rol de usuario:      10 pts  (usuario normal, sin historial sospechoso)
  IP de origen:        15 pts  (IP conocida de la oficina)
  Hora del evento:      0 pts  (horario laboral normal)
  ───────────────────────────
  Total: 70/100 → RIESGO ALTO
```

El objetivo es transformar "investigar todas las alertas" en "investigar las de mayor riesgo primero".

---

## 2. Variables y señales para calcular riesgo

**Variables de la alerta:**
- **Tipo de evento**: malware confirmado > anomalía de comportamiento > evento normal
- **Severidad declarada**: el SIEM ya puede asignar CRITICAL/HIGH/MEDIUM/LOW
- **IOCs presentes**: ¿hay IPs, dominios o hashes maliciosos confirmados?

**Variables del usuario:**
- **Rol y privilegios**: un acceso anómalo de un administrador es más grave que el de un usuario normal
- **Historial previo**: ¿tuvo alertas esta semana? Un patrón de actividad sospechosa acumulada sube el score
- **Comportamiento típico**: ¿el evento se sale de su patrón habitual?

**Variables del activo:**
- **Criticidad**: servidor de producción vs. máquina de prueba
- **Exposición**: interno, DMZ o expuesto a internet
- **Vulnerabilidades no parcheadas conocidas**

**Variables contextuales:**
- **Hora del evento**: fuera de horario laboral es más sospechoso
- **Ubicación geográfica**: ¿accede desde donde vive o desde otro país?
- **Datos accedidos**: ¿públicos o confidenciales/PII/financieros?

**Variables de threat intelligence:**
- ¿La IP está en listas negras conocidas (Spamhaus, etc.)?
- ¿Los IOCs coinciden con campañas conocidas?

---

## 3. Modelos de scoring: reglas vs. ML

### Scoring basado en reglas

Define cuántos puntos aporta cada variable y los suma. Es el punto de partida natural:

```
IF tipo = malware_confirmado  → +30 pts
IF usuario = administrador    → +20 pts
IF hora entre 22:00–06:00     → +10 pts
IF ip_en_blocklist = True     → +15 pts
IF datos_accedidos = PII      → +10 pts
...
```

**Ventajas:** fácil de entender, ajustar y auditar; podés explicar exactamente por qué una alerta tiene cierto score.

**Desventajas:** no captura interacciones entre variables. "Admin + fuera de horario + datos sensibles" es más grave que la suma de los tres, pero las reglas simples no lo ven así.

### Scoring basado en Machine Learning

En lugar de escribir los pesos manualmente, entrenás un modelo (Gradient Boosting, Random Forest) con el historial de alertas ya resueltas. El modelo aprende qué combinaciones de variables predicen amenazas reales.

**Ventajas:** captura interacciones complejas, se adapta a nuevos patrones.

**Desventajas:** menos interpretable, requiere datos de entrenamiento etiquetados, puede fallar ante tipos de ataque nuevos.

### Enfoque híbrido (el más común en producción)

Se combina ML para el score base con reglas de "hard stop" que nunca se pueden violar:

```
score = modelo_ml.predecir(evento)

# Reglas que fuerzan score mínimo independientemente del modelo
if evento.tipo == "malware_confirmado":
    score = max(score, 80)

if evento.datos_sensibles and evento.fuera_horario:
    score = max(score, 70)
```

Esto combina lo mejor de ambos mundos: el modelo aprende los matices, pero ciertos eventos críticos siempre se tratan con la seriedad que merecen.

---

## 4. Priorización de alertas con scoring

Con scores calculados, el SOC puede priorizar automáticamente:

```
Score 80–100 → CRITICAL
  Investigar en < 5 minutos
  Escalación automática al gerente de incidentes
  Ejecución automática de acciones (aislar si confirma)

Score 60–79  → HIGH
  Investigar en < 30 minutos
  Crear caso en SOAR
  Pausar para aprobación antes de acciones destructivas

Score 40–59  → MEDIUM
  Investigar en < 2 horas
  Enriquecer automáticamente con threat intel
  Agrupar con alertas similares del mismo origen

Score < 40   → LOW
  Auto-resolución posible
  O batch processing al final del turno
```

El scoring también habilita **correlación dinámica**: si cinco eventos de score MEDIUM provienen del mismo usuario en 10 minutos, el score combinado sube a HIGH. No es la gravedad de cada evento individual, es el patrón.

El scoring de riesgo es la capa que convierte el volumen inmanejable de alertas en una lista priorizada que un analista puede realmente trabajar. 
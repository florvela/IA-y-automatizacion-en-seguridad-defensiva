# Detección de Anomalías y UEBA

## 1. ¿Qué es una anomalía?

Imagina que te muestro una secuencia de números:

> **2, 2, 2, 2, 2, 2, 1, 2, 2, 2**

¿Puedes ver cuál es diferente? El **"1"** rompe el patrón. Eso es una anomalía: algo que **se desvía de lo normal**.

Ahora imagina lo mismo, pero en vez de diez números, tienes **miles de registros de logs** de usuarios, sistemas y redes. Encontrar la anomalía se vuelve como buscar una aguja en un pajar.

Para eso existe la tecnología que vamos a ver en esta clase.

---

## 2. ¿Qué es el Análisis de Comportamiento de Usuarios (UBA)?

**UBA** (*User Behavior Analytics*) es una tecnología que **analiza el comportamiento de los usuarios** para detectar actividades sospechosas o inusuales.

En lugar de revisar manualmente miles de registros, UBA:

1. **Establece una línea base**: aprende cómo se comporta normalmente cada usuario.
2. **Detecta desviaciones**: alerta cuando alguien se comporta de manera diferente a lo habitual.
3. **Prioriza riesgos**: en vez de mostrarte 10,000 alertas, te dice: *"Estos 5 usuarios son los más sospechosos hoy"*.

### Ejemplo práctico

Supongamos que tienes un empleado llamado **Juan**. Normalmente descarga 50 documentos al día y accede al sistema desde Chicago. De repente:

- Está descargando **50,000 documentos por día**
- Accede desde **Beijing**
- Su **puntaje de riesgo subió drásticamente**

Eso no es normal. UBA lo detecta automáticamente y lo destaca para que el equipo de seguridad lo investigue.

---

## 3. ¿Qué patrones analiza UBA?

UBA usa **técnicas de machine learning** para analizar múltiples tipos de comportamiento:
### 1. Volumen
¿Cuántos datos está moviendo el usuario?

- Normal: 50 registros/día
- Sospechoso: 50,000 registros/día de repente

### 2. Frecuencia
¿Con qué frecuencia realiza ciertas acciones?

- Normal: inicia sesión 2-3 veces al día
- Sospechoso: 50 inicios de sesión en un día

### 3. Ubicación
¿Desde dónde se conecta el usuario?

- Normal: oficina en Chicago
- Sospechoso: acceso desde Beijing sin previo aviso

### 4. Grupos de pares (Peer Groups)
Se compara al usuario con otros que tienen el mismo rol o función:

- **Perfil fijo**: el administrador define manualmente quiénes son los compañeros del usuario.
- **Perfil dinámico**: el sistema analiza los datos y agrupa automáticamente a usuarios con comportamientos similares.

Si todos en el grupo hacen X, pero este usuario de repente hace Y, eso es una señal de alerta.
### 5. Secuencias anómalas
No solo importa *qué* hace el usuario, sino *en qué orden* lo hace.

> **Ejemplo sospechoso:** Un administrador inicia sesión → crea una cuenta nueva → usa esa cuenta → borra la cuenta → repite el ciclo una y otra vez.
>
> Esto no tiene sentido lógico. ¿Por qué crear y borrar cuentas repetidamente? Podría ser una técnica para ocultar actividad maliciosa.

---

## 4. ¿Qué es UEBA?

**UEBA** (*User and Entity Behavior Analytics*) es la evolución de UBA. Agrega una letra: la **"E" de Entidades**.

| Concepto | ¿Qué analiza? |
|---|---|
| **UBA** | Solo usuarios humanos |
| **UEBA** | Usuarios **+** entidades (routers, servidores, bases de datos, etc.) |

### ¿Qué son las "entidades"?

Todo lo que no es una persona pero genera actividad en la red:
- Servidores
- Routers y switches
- Bases de datos
- Aplicaciones
- Dispositivos IoT

UEBA aplica el mismo principio: establece una línea base del comportamiento normal de cada entidad y detecta cuando algo se sale de ese patrón.

---

## 5. UEBA + SIEM

UEBA no trabaja sola. Se integra con el **SIEM** (*Security Information and Event Management*).

```
Fuentes de datos → SIEM → UEBA → Lista de usuarios/entidades más riesgosos → Investigación
```

Este flujo permite:

- **Reducir el ruido**: filtrar falsos positivos y enfocarse en amenazas reales.
- **Priorizar investigaciones**: saber exactamente dónde hay que mirar.
- **Escalar con el tamaño**: funciona igual de bien si tienes 100 usuarios o 100,000.

---

## 6. ¿Por qué es tan importante en el SOC?

Sin UEBA, un analista tendría que revisar **manualmente** la actividad de cientos de usuarios cada día.

Con UEBA, el analista recibe algo así:

> **"Top 10 usuarios más riesgosos hoy:"**
> 1. Juan - riesgo: **crítico**
> 2. ...

Ahora el analista sabe exactamente dónde enfocar su tiempo e investigación.

---

## 7. Isolation Forest: el algoritmo que usa UEBA

El concepto de UEBA suena bien, pero ¿cómo detecta el sistema que algo es anómalo? Uno de los algoritmos más usados para esto es **Isolation Forest**.

La idea es simple: **los puntos anómalos son más fáciles de aislar que los normales**. Si construís un árbol de decisión aleatorio sobre tus datos, los outliers terminan en ramas muy cortas (pocas particiones para separarlos del resto). Los puntos normales, en cambio, están tan mezclados con los demás que necesitan muchas particiones para quedar solos.

Isolation Forest construye muchos de estos árboles y mide cuántas particiones necesita cada punto para quedar aislado. Un punto que se aísla rápido → probablemente es una anomalía.

### Ejemplo: detección de anomalías en tráfico de red

Dado un dataset de tráfico de red con features como bytes enviados, duración de la conexión y cantidad de conexiones distintas, Isolation Forest detecta qué eventos se salen del patrón normal.

```python
import numpy as np
from sklearn.ensemble import IsolationForest

# Dataset de tráfico de red
# Columnas: [bytes_enviados, duracion_segundos, conexiones_distintas]
X_normal = np.array([
    [1500, 2.1, 3],
    [1200, 1.8, 2],
    [1800, 2.5, 4],
    [1100, 1.5, 2],
    [1600, 2.2, 3],
    [1400, 1.9, 3],
    [1700, 2.3, 4],
    [1300, 2.0, 3],
])

# Evento sospechoso: volumen de datos 6x mayor, duración muy corta
X_sospechoso = np.array([[9500000, 0.3, 1]])

X = np.vstack([X_normal, X_sospechoso])

# Entrenamos el modelo
modelo = IsolationForest(contamination=0.1, random_state=42)
modelo.fit(X_normal)  # entrenamos solo con datos normales

# Predecimos sobre todos los eventos
predicciones = modelo.predict(X)
scores = modelo.decision_function(X)

print("Resultados:")
for i, (pred, score) in enumerate(zip(predicciones, scores)):
    tipo = "ANOMALÍA" if pred == -1 else "normal"
    print(f"  Evento {i+1}: {tipo} (score: {score:.3f})")
```

**Salida esperada:**
```
Resultados:
  Evento 1: normal (score: 0.089)
  Evento 2: normal (score: 0.102)
  ...
  Evento 9: ANOMALÍA (score: -0.312)
```

El evento 9 (el sospechoso con 9.5 millones de bytes en 0.3 segundos) obtiene un score negativo y es clasificado como `-1` (outlier). Así es exactamente como funciona en el pipeline del demo: el modelo devuelve `-1` y el evento pasa a la etapa de clasificación NLP.

### Conexión con UEBA

Este es el tipo de modelo que tiene UEBA "por debajo". En lugar de que un analista defina manualmente reglas como *"alerta si bytes_enviados > 5000000"*, Isolation Forest aprende el comportamiento normal a partir de los datos y detecta automáticamente lo que se desvía, sin necesitar etiquetas de qué es bueno o malo.

Eso lo hace especialmente útil en seguridad: los atacantes pueden evadir reglas estáticas, pero es mucho más difícil evadir un modelo que aprendió la distribución completa del comportamiento normal.

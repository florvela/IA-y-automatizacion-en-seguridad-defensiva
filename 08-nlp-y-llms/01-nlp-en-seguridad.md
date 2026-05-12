# Una pequeña intro a NLP: De dónde vienen los LLMs

![](images/NLP-and-LLM-1-1024x576.png)

Antes de entrar a LLMs necesitamos entender de dónde vienen. Los LLMs no surgieron de la nada... son la evolución de un campo que existe hace décadas: **NLP**, procesamiento de lenguaje natural.

**NLP (Natural Language Processing)** es el campo de la IA que permite a las máquinas entender y procesar lenguaje humano. Texto, básicamente.

NLP no es lo mismo que LLMs. Los LLMs son una forma de hacer NLP, pero NLP es el campo más amplio. Con NLP podemos hacer clasificadores de texto, traductores automáticos y detectores de spam — y esa tecnología existió mucho antes de que existiera GPT.

---

## 1. Por qué importa en seguridad

En seguridad manejamos texto constantemente: logs, alertas, tickets, reportes de malware. NLP es el conjunto de técnicas para procesar ese texto automáticamente: clasificarlo, extraer información, detectar patrones.

Con NLP y machine learning podemos construir **modelos de clasificación** donde la entrada sea texto. Clasificar significa asignar una etiqueta a un texto. Funciona bien cuando las palabras que aparecen en el mensaje ya dicen a qué categoría pertenece el evento.

Casos de uso concretos en un SOC:

- **Clasificar alertas por tipo**: por el mensaje de la alerta, determinar si es fuerza bruta, exfiltración, reconocimiento, etc.
- **Categorizar reportes de threat intel**: ransomware, phishing, vulnerability, APT
- **Clasificar emails**: spam / phishing / legítimo

---

## 2. Tokenización

Antes de que una máquina pueda procesar texto, necesita dividirlo en partes. Generalmente esas partes son palabras. Eso es **tokenizar**.

```
"Failed login for admin from 203.0.113.45"
        ↓
['Failed', 'login', 'for', 'admin', 'from', '203.0.113.45']
```

A partir de ahí el modelo trabaja con esas unidades — no con el texto crudo. Es el primer paso de cualquier pipeline de NLP.


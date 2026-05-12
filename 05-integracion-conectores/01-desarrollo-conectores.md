# Desarrollo de Integraciones y Conectores

En este segmento vamos a ver cómo diseñar un sistema de conectores** que sea extensible, testeable y mantenible. La diferencia entre tener 10 scripts de integración y tener una plataforma de integración.

---

## 1. El problema del conector ad-hoc

Sin un patrón de diseño, las integraciones crecen así:

Imagina que ya escribiste integraciones con 5 herramientas. Cada una funciona, pero están dispersas. Después necesitás agregar 10 más. Cada nuevo conector que escribís repite la lógica de los anteriores: autenticación, manejo de timeouts, reintentos. Al mes, tenés 15 archivos Python con patrones incompatibles. Un día, descubrís un bug de timeout en uno; tenés que arreglar los 15. Eso es insostenible. 

```python
# virustotal.py — 80 líneas
# crowdstrike.py — 120 líneas
# jira.py — 90 líneas
# splunk.py — 110 líneas
# palo_alto.py — 100 líneas
```

Cada archivo tiene su propia forma de autenticar, su propio manejo de errores, sus propios timeouts, su propia forma de retornar resultados. Agregar un nuevo conector requiere reescribir la misma lógica de nuevo. Mantener la consistencia entre 15 conectores es imposible.

La solución: **una interfaz abstracta común** que todos los conectores implementan.

### El patrón en su forma mínima

Antes de ver la implementación completa, el patrón central es este:

```python
class ConectorBase:
    def ejecutar(self, accion):
        # Acá va lo que todos los conectores tienen en común:
        # logging, validación, reintentos, manejo de errores
        print(f"[LOG] Ejecutando acción: {accion}")
        return self._ejecutar(accion)

    def _ejecutar(self, accion):
        raise NotImplementedError

class ConectorEDR(ConectorBase):
    def _ejecutar(self, accion):
        return f"EDR: {accion}"
```

```python
# Uso
edr = ConectorEDR()
resultado = edr.ejecutar("aislar_host")
print(resultado)  # EDR: aislar_host
```

`ConectorBase` define el contrato: todos los conectores tienen un método público `ejecutar()`. Ese método llama a `_ejecutar()`, que cada subclase implementa con su propia lógica de API. La clase base es el lugar donde van las capacidades comunes: logging, reintentos, manejo de excepciones. Los conectores concretos solo escriben lo que los diferencia.

---

## 2. Interfaz base de conector

La idea es crear una clase abstracta `ConectorBase` que define cómo se debe comportar cualquier conector. Todos los conectores heredan de esta clase y solo implementan la lógica específica. 

```python
from abc import ABC, abstractmethod
from dataclasses import dataclass
from typing import Any, Optional
import logging
import requests
import time

@dataclass
class ResultadoConector:
    """Estructura de respuesta estándar para todos los conectores"""
    exitoso: bool
    datos: Any = None
    error: Optional[str] = None
    tiempo_ms: int = 0
    conector: str = ""

    def __bool__(self):
        return self.exitoso


class ConectorBase(ABC):
    """
    Interfaz base que todos los conectores deben implementar.
    Proporciona: logging estándar, manejo de errores, reintentos, timeouts.
    """

    def __init__(self, nombre: str, timeout: int = 30, max_reintentos: int = 3):
        self.nombre = nombre
        self.timeout = timeout
        self.max_reintentos = max_reintentos
        self.logger = logging.getLogger(f"conector.{nombre}")
        self._session = requests.Session()

    @abstractmethod
    def verificar_conectividad(self) -> bool:
        """Verifica que el conector puede autenticarse y alcanzar el servicio"""
        pass

    @abstractmethod
    def _ejecutar(self, accion: str, parametros: dict) -> Any:
        """Ejecuta una acción específica. Implementado por cada conector."""
        pass

    def ejecutar(self, accion: str, parametros: dict = None) -> ResultadoConector:
        """
        Método público con manejo automático de errores y reintentos.
        Los conectores son llamados siempre a través de este método.
        """
        parametros = parametros or {}
        inicio = time.time()

        for intento in range(1, self.max_reintentos + 1):
            try:
                self.logger.debug(f"Ejecutando '{accion}' | intento={intento}")
                datos = self._ejecutar(accion, parametros)
                tiempo_ms = int((time.time() - inicio) * 1000)
                self.logger.info(f"'{accion}' completado | {tiempo_ms}ms")
                return ResultadoConector(
                    exitoso=True, datos=datos,
                    tiempo_ms=tiempo_ms, conector=self.nombre
                )

            except requests.exceptions.Timeout:
                self.logger.warning(f"Timeout en '{accion}' | intento={intento}/{self.max_reintentos}")
                if intento < self.max_reintentos:
                    time.sleep(2 ** intento)  # backoff exponencial

            except requests.exceptions.ConnectionError as e:
                self.logger.error(f"Error de conexión en '{accion}': {e}")
                if intento < self.max_reintentos:
                    time.sleep(5)

            except Exception as e:
                tiempo_ms = int((time.time() - inicio) * 1000)
                self.logger.error(f"Error en '{accion}': {e}", exc_info=True)
                return ResultadoConector(
                    exitoso=False, error=str(e),
                    tiempo_ms=tiempo_ms, conector=self.nombre
                )

        return ResultadoConector(
            exitoso=False, error=f"Agotados {self.max_reintentos} reintentos",
            tiempo_ms=int((time.time() - inicio) * 1000), conector=self.nombre
        )
```

`ConectorBase` define el contrato:
* Todos los conectores deben tener un método `_ejecutar(accion, parametros)` que implementan específicamente. 
* El método público `ejecutar()` es el que llama a `_ejecutar()`, pero lo envuelve con lógica de reintentos exponenciales (backoff: espera 2 segundos, luego 4, luego 8), logging automático, y manejo de excepciones estándar. 
* Entonces, un playbook nunca llama a `_ejecutar()` directamente — siempre llama a `ejecutar()`, que garantiza que si falla por timeout, reintentar automáticamente. 
* Los conectores concretos heredan todo esto y solo escriben la lógica específica de su API.

---

## 3. Implementar un conector concreto

Con la interfaz base, implementar un conector nuevo es declarativo:

Ahora vamos a ver cómo dos conectores (`ConectorVirusTotal` y `ConectorCrowdStrike`) heredan de la base y solo implementan sus métodos específicos. Fijate que cada uno solo programa lo que hace diferente (las llamadas a su API, cómo procesar respuestas) pero autenticación, reintentos, logging, todo eso viene de la clase base.

Conector de VirusTotal: `ConectorVirusTotal` solo implementa cómo hablar con VirusTotal API (autenticación con x-apikey, endpoints específicos, parsing de respuestas). 
```python
class ConectorVirusTotal(ConectorBase):

    def __init__(self, api_key: str):
        super().__init__(nombre="virustotal", timeout=30, max_reintentos=3)
        self._api_key = api_key
        self._session.headers.update({"x-apikey": api_key})
        self._base_url = "https://www.virustotal.com/api/v3"

    def verificar_conectividad(self) -> bool:
        resp = self._session.get(f"{self._base_url}/feeds/files", timeout=5)
        return resp.status_code in (200, 429)  # 429 = rate limit, pero conectado

    def _ejecutar(self, accion: str, parametros: dict) -> Any:
        if accion == "check_hash":
            return self._check_hash(parametros["hash"])
        elif accion == "check_ip":
            return self._check_ip(parametros["ip"])
        elif accion == "check_domain":
            return self._check_domain(parametros["domain"])
        else:
            raise ValueError(f"Acción no soportada: {accion}")

    def _check_hash(self, hash_valor: str) -> dict:
        resp = self._session.get(
            f"{self._base_url}/files/{hash_valor}",
            timeout=self.timeout
        )
        if resp.status_code == 404:
            return {"veredicto": "NO_ENCONTRADO", "hash": hash_valor}
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        return {
            "hash": hash_valor,
            "malicious": stats["malicious"],
            "veredicto": "MALICIOSO" if stats["malicious"] > 0 else "LIMPIO",
            "nombre": data.get("meaningful_name", ""),
        }

    def _check_ip(self, ip: str) -> dict:
        resp = self._session.get(f"{self._base_url}/ip_addresses/{ip}", timeout=self.timeout)
        resp.raise_for_status()
        data = resp.json()["data"]["attributes"]
        stats = data["last_analysis_stats"]
        return {
            "ip": ip,
            "malicious": stats["malicious"],
            "pais": data.get("country", "desconocido"),
            "veredicto": "MALICIOSA" if stats["malicious"] > 5 else "LIMPIA",
        }

    def _check_domain(self, domain: str) -> dict:
        resp = self._session.get(f"{self._base_url}/domains/{domain}", timeout=self.timeout)
        resp.raise_for_status()
        stats = resp.json()["data"]["attributes"]["last_analysis_stats"]
        return {
            "domain": domain,
            "malicious": stats["malicious"],
            "veredicto": "MALICIOSO" if stats["malicious"] > 3 else "LIMPIO",
        }
```


Conector de Crowd Strike: `ConectorCrowdStrike` solo implementa CrowdStrike (OAuth, endpoints de contain/lift_containment). 
```python
class ConectorCrowdStrike(ConectorBase):

    def __init__(self, client_id: str, client_secret: str):
        super().__init__(nombre="crowdstrike", timeout=30)
        self._client_id = client_id
        self._client_secret = client_secret
        self._base_url = "https://api.crowdstrike.com"
        self._token = None

    def _autenticar(self):
        resp = self._session.post(
            f"{self._base_url}/oauth2/token",
            data={"client_id": self._client_id, "client_secret": self._client_secret}
        )
        resp.raise_for_status()
        self._token = resp.json()["access_token"]
        self._session.headers.update({"Authorization": f"Bearer {self._token}"})

    def verificar_conectividad(self) -> bool:
        try:
            self._autenticar()
            return bool(self._token)
        except Exception:
            return False

    def _ejecutar(self, accion: str, parametros: dict) -> Any:
        if not self._token:
            self._autenticar()

        if accion == "get_device":
            return self._get_device(parametros["device_id"])
        elif accion == "isolate_device":
            return self._isolate_device(parametros["device_id"])
        elif accion == "unisolate_device":
            return self._unisolate_device(parametros["device_id"])
        else:
            raise ValueError(f"Acción no soportada: {accion}")

    def _isolate_device(self, device_id: str) -> dict:
        resp = self._session.post(
            f"{self._base_url}/devices/entities/devices/actions/contain/v1",
            params={"action_name": "contain"},
            json={"ids": [device_id]},
            timeout=self.timeout
        )
        resp.raise_for_status()
        return {"device_id": device_id, "accion": "aislado", "exitoso": True}

    def _unisolate_device(self, device_id: str) -> dict:
        resp = self._session.post(
            f"{self._base_url}/devices/entities/devices/actions/lift_containment/v1",
            params={"action_name": "lift_containment"},
            json={"ids": [device_id]},
            timeout=self.timeout
        )
        resp.raise_for_status()
        return {"device_id": device_id, "accion": "liberado", "exitoso": True}

    def _get_device(self, device_id: str) -> dict:
        resp = self._session.get(
            f"{self._base_url}/devices/entities/devices/v2",
            params={"ids": device_id},
            timeout=self.timeout
        )
        resp.raise_for_status()
        return resp.json().get("resources", [{}])[0]
```

La clase base se encarga de lo demás. Si necesitás agregar un tercer conector mañana, heredás de `ConectorBase`, implementas 3-4 métodos, y listo. Sin repetir código.

---

## 4. Registro de conectores (ConnectorRegistry)

Un registro centralizado permite buscar conectores por nombre y gestionar su ciclo de vida:

Hasta ahora tenés conectores (clases que heredan de ConectorBase). Pero ¿cómo sabe un playbook dónde encontrar el conector de VirusTotal? ¿Cómo se inicializa? ¿Cómo verificás que todos estén funcionando al arrancar? Para eso existe el Registry: `RegistroConectores`, un diccionario centralizado donde se registran todos los conectores. Es como un service locator: los playbooks dicen "dame el conector de VirusTotal", y el registro te lo devuelve.

```python
from typing import Dict, Type

class RegistroConectores:
    """
    Registro centralizado de todos los conectores disponibles.
    Permite obtener, verificar y usar conectores por nombre.
    """

    _conectores: Dict[str, ConectorBase] = {}

    @classmethod
    def registrar(cls, conector: ConectorBase):
        cls._conectores[conector.nombre] = conector
        logging.getLogger("registro").info(f"Conector registrado: {conector.nombre}")

    @classmethod
    def obtener(cls, nombre: str) -> Optional[ConectorBase]:
        return cls._conectores.get(nombre)

    @classmethod
    def verificar_todos(cls) -> Dict[str, bool]:
        """Verifica conectividad de todos los conectores registrados"""
        resultados = {}
        for nombre, conector in cls._conectores.items():
            try:
                resultados[nombre] = conector.verificar_conectividad()
            except Exception as e:
                resultados[nombre] = False
                logging.error(f"Fallo en verificación de {nombre}: {e}")
        return resultados

    @classmethod
    def listar(cls):
        return list(cls._conectores.keys())


# Inicialización al arrancar el sistema
def inicializar_conectores(config: dict):
    """Registra todos los conectores con su configuración"""
    RegistroConectores.registrar(
        ConectorVirusTotal(api_key=config["vt_api_key"])
    )
    RegistroConectores.registrar(
        ConectorCrowdStrike(
            client_id=config["cs_client_id"],
            client_secret=config["cs_client_secret"]
        )
    )
    # Verificar que todo está operativo al arrancar
    estado = RegistroConectores.verificar_todos()
    for nombre, ok in estado.items():
        nivel = logging.INFO if ok else logging.ERROR
        logging.log(nivel, f"Conector '{nombre}': {'OK' if ok else 'FALLO'}")


# Uso desde un playbook
def playbook_verificar_ioc(hash_valor: str) -> dict:
    vt = RegistroConectores.obtener("virustotal")
    if not vt:
        raise RuntimeError("Conector VirusTotal no disponible")

    resultado = vt.ejecutar("check_hash", {"hash": hash_valor})
    if not resultado:
        return {"error": resultado.error}

    return resultado.datos
```

Fijate cómo funciona: al arrancar la aplicación, se llama a `inicializar_conectores(config)` que registra todos los conectores. Después, `verificar_todos()` prueba que cada uno realmente pueda conectarse: si alguno falla, se registra el error. 

Desde ahí en adelante, un playbook simplemente hace `RegistroConectores.obtener("virustotal").ejecutar("check_hash", ...)`. El registro se encarga de encontrarlo. Si agregas un nuevo conector, solo agregás una nueva llamada a `RegistroConectores.registrar()` en `inicializar_conectores()` y el resto del código no cambia.
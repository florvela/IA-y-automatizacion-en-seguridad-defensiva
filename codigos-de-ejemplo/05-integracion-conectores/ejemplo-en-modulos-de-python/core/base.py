import time
import logging
import requests
from abc import ABC, abstractmethod


class ConectorBase(ABC):
    """Clase base para todos los conectores del SOAR."""

    def __init__(self, nombre: str, use_mock: bool = True):
        self.nombre = nombre
        self.use_mock = use_mock
        self._logger = logging.getLogger(f'conector.{nombre}')

    @abstractmethod
    def verificar_salud(self) -> bool:
        """Verifica que el conector puede comunicarse con el servicio."""
        pass

    def _log(self, msg: str, nivel: str = 'info'):
        getattr(self._logger, nivel)(f'[{self.nombre}] {msg}')

    def _reintentar(self, fn, max_intentos: int = 3, backoff: float = 1.0):
        """Ejecuta una función con reintentos y backoff exponencial."""
        for intento in range(1, max_intentos + 1):
            try:
                return fn()
            except Exception as e:
                if intento == max_intentos:
                    self._log(f'Falló tras {max_intentos} intentos: {e}', 'error')
                    raise
                espera = backoff * (2 ** (intento - 1))
                self._log(f'Intento {intento} fallido. Reintentando en {espera}s...', 'warning')
                time.sleep(espera)

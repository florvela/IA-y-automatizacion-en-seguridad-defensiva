import logging
from .base import ConectorBase

logger = logging.getLogger('registry')


class ConnectorRegistry:
    """Registro centralizado de todos los conectores del SOAR."""

    def __init__(self):
        self._conectores: dict[str, ConectorBase] = {}

    def registrar(self, nombre: str, conector: ConectorBase):
        self._conectores[nombre] = conector
        logger.info(f'Conector registrado: {nombre}')

    def obtener(self, nombre: str) -> ConectorBase:
        if nombre not in self._conectores:
            raise KeyError(f'Conector no registrado: {nombre}')
        return self._conectores[nombre]

    def verificar_todos(self) -> dict[str, bool]:
        """Health check de todos los conectores registrados."""
        return {nombre: c.verificar_salud() for nombre, c in self._conectores.items()}

    def listar(self) -> list[str]:
        return list(self._conectores.keys())

"""
soc — Núcleo modular del laboratorio Blue Team.

# Este paquete se comparte entre TODOS los servicios (siem, soar, mcp, jupyter).
# Es el mismo código corriendo en distintos contenedores: eso es modularidad real.
#
# La idea pedagógica: la lógica vive acá, limpia y testeable. Los servicios son
# cáscaras finas que importan de acá. Un notebook de 5 líneas puede hacer lo mismo
# que el pipeline de producción porque ambos usan estas funciones.
"""

__version__ = "1.0.0"

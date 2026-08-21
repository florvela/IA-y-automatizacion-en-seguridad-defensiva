# Atacante: imagen mínima con paramiko para el brute force SSH.
FROM python:3.12-slim

# Comentario: instalamos solo lo necesario. Imagen chica = levanta rápido.
RUN pip install --no-cache-dir "paramiko>=3.4"

WORKDIR /app
COPY services/attacker/brute_force.py /app/brute_force.py

# Por defecto NO ataca solo: espera a que lo dispares (docker compose run attacker).
# Con AUTO_ATTACK=true ataca al arrancar (útil para pruebas automáticas).
CMD ["sh", "-c", "if [ \"$AUTO_ATTACK\" = \"true\" ]; then python /app/brute_force.py; else echo 'Atacante listo. Disparalo con: docker compose exec attacker python brute_force.py'; sleep infinity; fi"]

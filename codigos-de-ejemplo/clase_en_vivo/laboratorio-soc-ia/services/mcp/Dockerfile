# Servidor MCP con las tools de investigación y la acción bloqueante.
# Contexto de build = raíz del repo (para copiar el paquete soc compartido).
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Paquete compartido + código del servicio + datos semilla (blacklist, usuarios).
COPY soc /app/soc
COPY services/mcp/server.py /app/server.py
COPY data /app/data

EXPOSE 8080
CMD ["python", "server.py"]

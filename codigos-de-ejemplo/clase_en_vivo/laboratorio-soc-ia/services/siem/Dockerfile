# siem-lite: detector de brute force (stand-in de Wazuh para correr sin 8GB).
FROM python:3.12-slim

RUN pip install --no-cache-dir "requests>=2.31"

WORKDIR /app
COPY services/siem/siem_lite.py /app/siem_lite.py

CMD ["python", "-u", "siem_lite.py"]

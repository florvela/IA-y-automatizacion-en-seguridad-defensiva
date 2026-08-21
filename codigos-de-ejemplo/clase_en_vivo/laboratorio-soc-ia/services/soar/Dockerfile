# SOAR-bridge: API que orquesta la respuesta (webhook -> playbook -> aprobación).
FROM python:3.12-slim

WORKDIR /app
COPY requirements.txt /app/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

COPY soc /app/soc
COPY data /app/data
COPY services/soar/app.py /app/app.py

ENV SOC_SEED_DIR=/app/data

EXPOSE 9000
CMD ["uvicorn", "app:app", "--host", "0.0.0.0", "--port", "9000"]

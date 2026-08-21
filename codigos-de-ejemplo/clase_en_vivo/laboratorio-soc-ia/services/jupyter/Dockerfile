# Jupyter Lab con el paquete soc ya instalado, para explorar el flujo a mano.
FROM python:3.12-slim

WORKDIR /work
COPY requirements.txt /work/requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# El paquete compartido y los notebooks.
COPY soc /work/soc
COPY notebooks /work/notebooks

EXPOSE 8888
# Token fijo "lab" para entrar sin fricción: http://localhost:8888/?token=lab
CMD ["jupyter", "lab", "--ip=0.0.0.0", "--port=8888", "--no-browser", "--allow-root", \
     "--ServerApp.token=lab", "--ServerApp.password=", "--ServerApp.root_dir=/work"]

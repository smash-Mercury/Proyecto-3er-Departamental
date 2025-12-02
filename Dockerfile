# Usamos una imagen ligera de Python
FROM python:3.9-slim

# Directorio de trabajo dentro del contenedor
WORKDIR /app

# Copiamos SOLO el script del servidor (Ya no necesitamos los certs)
COPY Servidor.py .

# Instalamos la librería de criptografía (Esta SI la necesitamos para AES)
RUN pip install cryptography

# Exponemos el puerto del servidor
EXPOSE 12345

# Comando para iniciar el servidor
CMD ["python", "Servidor.py"]
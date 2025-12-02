Sistema de Almacenamiento Distribuido y Seguro (Python + K8s)

Este proyecto implementa un sistema cliente-servidor tolerante a fallos que permite subir archivos de forma segura. Utiliza Python para la lógica, Docker para la contenerización y Kubernetes (Minikube) para la orquestación y alta disponibilidad.

🛠️1. Requisitos Previos
Antes de empezar, asegúrate de tener instalado:

-Docker Desktop (y que esté corriendo).

-Minikube (para el clúster local).

-Python 3.9+ (para ejecutar el cliente localmente).

-Librería de criptografía:  pip install cryptography

##

⚙️2 Preparación del Entorno

Paso 1: Ubicación

Abre una terminal (PowerShell o CMD) y entra a la carpeta del proyecto:

cd ruta/a/tu/repositorio

Paso 2: Iniciar el Clúster

Arranca Minikube si no está activo:

minikube start

Paso 3: Conectar Docker (¡CRÍTICO!)

Esto permite que Minikube vea las imágenes que construyas en tu PC.

En PowerShell:

minikube -p minikube docker-env | Invoke-Expression

##

🏗️3. Despliegue de la Infraestructura

Paso 1: Construir la Imagen del Servidor

Empaquetamos el código del servidor en una imagen Docker llamada storage-server. Usamos --no-cache para asegurar que tome los últimos cambios.

docker build --no-cache -t storage-server:v1 .

Paso 2: Desplegar en Kubernetes

Esto crea el Servicio (Red) y el Deployment (3 Pods).

kubectl apply -f k8s-deployment.yaml

Paso 3: Verificar el Estado

Espera unos segundos hasta que veas 3 líneas con estado Running.

kubectl get pods

##

🔌4. Conexión del Cliente

   
Para que tu cliente local pueda hablar con el clúster aislado, necesitamos abrir un "puente".

Paso 1: Abrir el Puerto (Port-Forward)

⚠️ Abre una NUEVA terminal (no cierres la anterior) y ejecuta:

kubectl port-forward service/storage-service 30001:12345

Nota: Mantén esta ventana abierta y minimizada. Si la cierras, la conexión se corta.

##

💻 5. Uso del Cliente

Vuelve a tu terminal principal y ejecuta el cliente:

python Cliente.py 30001

****

Comandos Disponibles:

Registrarse: register [usuario] [password]

Iniciar Sesión: login [usuario] [password]

Subir Archivo: file [usuario] [ruta_del_archivo]

Ejemplo: file user1 mi_foto.png

Salir: exit

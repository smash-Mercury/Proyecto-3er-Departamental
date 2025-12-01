import socket
import ssl
import threading
import json
import hashlib
import os
import sys
import time
# [MODIFICADO] Importar Fernet para encriptación
from cryptography.fernet import Fernet

# --- 1. CONFIGURACIÓN DEL CLIENTE ---
# [MODIFICADO] Lista de servidores para conectar (NodePort de K8s o LoadBalancer)
SERVER_LIST = [
    ('127.0.0.1', 30001),  # Ejemplo: Puerto expuesto por Minikube
    ('localhost', 12345)   # Fallback local
]
BUFFER_SIZE = 4096

# [MODIFICADO] CLAVE COMPARTIDA (Debe ser idéntica en Cliente y Servidor)
# En producción, esto se manejaría con variables de entorno o intercambio de claves.
SHARED_KEY = b'uF8wT5Z9_G8oX4K7yQ3V2I1L0H6N4J2M7E4D9C6B4A2S='

# --- 2. VARIABLES GLOBALES DE ESTADO ---
is_running = True
logged_in_user = None
login_event = threading.Event()
recv_thread = None
session_username = None
session_password = None

# --- 3. HILO RECEPTOR (Sin cambios mayores) ---


def receive_handler(ssock):
    global is_running, logged_in_user
    client_buffer = b""

    while is_running:
        try:
            raw_data = ssock.recv(BUFFER_SIZE)
            if not raw_data:
                print("\n[Sistema] El servidor cerró la conexión.")
                break

            client_buffer += raw_data

            while b'\n' in client_buffer:
                response_data, client_buffer = client_buffer.split(b'\n', 1)

                if not response_data.strip():
                    continue

                response = json.loads(response_data.decode('utf-8'))

                if response['type'] == 'NEW_MESSAGE':
                    print(f"\n\n--- Nuevo Mensaje de [{response['from']}] ---")
                    print(f"> {response['content']}")
                    print("-------------------------------------------")

                elif response['type'] == 'RESPONSE':
                    print(f"\n[Servidor] {response['message']}")
                    if response['message'].startswith('Login exitoso'):
                        try:
                            username = response['message'].split(
                                ' ')[-1].replace('.', '')
                            logged_in_user = username
                            login_event.set()
                        except Exception as e:
                            print(
                                f"[Error] No se pudo parsear el nombre de login: {e}")

                elif response['type'] == 'ERROR':
                    print(f"\n[Error del Servidor] {response['message']}")
                    if "Usuario o contraseña" in response['message'] or "ya existe" in response['message']:
                        login_event.set()

                if logged_in_user:
                    print(f"\n[{logged_in_user}] (msg, file, exit): ", end="")
                else:
                    print(f"\n(login, register, exit): ", end="")
                sys.stdout.flush()

        except json.JSONDecodeError:
            print(
                f"\n[Error] JSON inválido: {response_data.decode('utf-8', errors='ignore')}")
        except (ssl.SSLError, ConnectionResetError, BrokenPipeError):
            if is_running:
                print("\n[Sistema] CONEXIÓN PERDIDA con el servidor.")
            break
        except Exception as e:
            if is_running:
                print(f"\n[Error] Error recibiendo datos: {e}")
            break

    is_running = False
    login_event.set()

# --- 4. FUNCIÓN DE CONEXIÓN ---


def connect_to_server(context):
    for host, port in SERVER_LIST:
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            # En K8s/Docker a veces el hostname no coincide con el certificado autogenerado, deshabilitamos check
            ssock = context.wrap_socket(sock, server_hostname=host)
            print(f"Intentando conectar a {host}:{port}...")
            ssock.connect((host, port))
            print(f"--- Conectado al servidor en {host}:{port} ---")
            return ssock
        except ConnectionRefusedError:
            print(f"Servidor {host}:{port} rechazó la conexión.")
            sock.close()
        except Exception as e:
            print(f"Error conectando a {host}:{port}: {e}")
            sock.close()
    return None

# --- 5. HILO PRINCIPAL ---


def main_loop():
    global is_running, logged_in_user, login_event, recv_thread
    global session_username, session_password

    context = ssl.create_default_context(ssl.Purpose.SERVER_AUTH)
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    while True:
        is_running = True
        logged_in_user = None
        login_event.clear()
        ssock = None
        recv_thread = None

        try:
            ssock = connect_to_server(context)
            if not ssock:
                print(
                    "[Sistema] No hay servidores disponibles. Reintentando en 5 segundos...")
                time.sleep(5)
                continue

            recv_thread = threading.Thread(
                target=receive_handler, args=(ssock,))
            recv_thread.start()

            if session_username and session_password:
                print(
                    f"[Sistema] Reconectado. Reanudando sesión como {session_username}...")
                command = {
                    "command": "LOGIN", "username": session_username, "password": session_password}
                login_event.clear()
                ssock.sendall(json.dumps(command).encode('utf-8') + b'\n')
                login_event.wait(timeout=5.0)
                if not logged_in_user:
                    session_username = None
                    session_password = None

            # BUCLE NO AUTENTICADO
            while is_running and logged_in_user is None:
                cmd_input = input(
                    "\nEscribe un comando (login, register, exit): ")
                if not is_running:
                    break
                parts = cmd_input.split()
                if not parts:
                    continue
                command_name = parts[0].lower()

                if command_name == 'exit':
                    is_running = False
                    break
                elif command_name == 'register':
                    if len(parts) != 3:
                        print("Uso: register <username> <password>")
                        continue
                    command = {"command": "REGISTER",
                               "username": parts[1], "password": parts[2]}
                    login_event.clear()
                    ssock.sendall(json.dumps(command).encode('utf-8') + b'\n')
                    login_event.wait(timeout=5.0)
                elif command_name == 'login':
                    if len(parts) != 3:
                        print("Uso: login <username> <password>")
                        continue
                    temp_user, temp_pass = parts[1], parts[2]
                    command = {"command": "LOGIN",
                               "username": temp_user, "password": temp_pass}
                    login_event.clear()
                    ssock.sendall(json.dumps(command).encode('utf-8') + b'\n')
                    login_event.wait(timeout=5.0)
                    if logged_in_user:
                        session_username = temp_user
                        session_password = temp_pass
                else:
                    print("Comando no reconocido.")

            # BUCLE AUTENTICADO
            while is_running and logged_in_user is not None:
                prompt = f"\n[{logged_in_user}] Escribe un comando (msg, file, exit): "
                cmd_input = input(prompt)
                if not is_running:
                    break
                parts = cmd_input.split()
                if not parts:
                    continue
                command_name = parts[0].lower()

                if command_name == 'exit':
                    is_running = False
                    session_username = None
                    session_password = None
                    break

                elif command_name == 'msg':
                    if len(parts) < 3:
                        print("Uso: msg <to_user> <mensaje...>")
                        continue
                    to_user = parts[1]
                    message_content = " ".join(parts[2:])
                    command = {"command": "SEND_MESSAGE",
                               "to": to_user, "content": message_content}
                    ssock.sendall(json.dumps(command).encode('utf-8') + b'\n')

                elif command_name == 'file':
                    # [MODIFICADO] Lógica de encriptación y envío seguro
                    if len(parts) != 3:
                        print("Uso: file <to_user> <ruta_del_archivo>")
                        continue

                    to_user = parts[1]
                    file_path = parts[2]

                    if not os.path.exists(file_path):
                        print(f"[Error] El archivo no existe: {file_path}")
                        continue

                    try:
                        # 1. Calcular Hash del archivo ORIGINAL (Integridad)
                        print("Calculando hash del archivo original...")
                        sha256_hash = hashlib.sha256()
                        file_data_original = b""
                        with open(file_path, "rb") as f:
                            while chunk := f.read(4096):
                                sha256_hash.update(chunk)
                                file_data_original += chunk

                        original_hash = sha256_hash.hexdigest()

                        # 2. Encriptar el archivo (Confidencialidad)
                        print("Encriptando archivo antes del envío...")
                        fernet = Fernet(SHARED_KEY)
                        encrypted_data = fernet.encrypt(file_data_original)
                        encrypted_size = len(encrypted_data)

                        # 3. Preparar comando con el tamaño del archivo ENCRIPTADO
                        command = {
                            "command": "SEND_FILE",
                            "to": to_user,
                            "filename": os.path.basename(file_path),
                            "size": encrypted_size,
                            "hash": original_hash  # Enviamos hash original para verificación
                        }

                        ssock.sendall(json.dumps(
                            command).encode('utf-8') + b'\n')

                        # 4. Enviar datos encriptados
                        print(f"Enviando {file_path} (encriptado)...")
                        ssock.sendall(encrypted_data)
                        print("Archivo enviado.")

                    except Exception as e:
                        print(f"[Error] No se pudo enviar el archivo: {e}")

                else:
                    print("Comando no reconocido.")

        except Exception as e:
            if is_running:
                print(f"[Error] Ocurrió un error inesperado en main: {e}")
        finally:
            is_running = False
            if ssock:
                ssock.close()
            if recv_thread and recv_thread.is_alive():
                recv_thread.join()
            if 'command_name' in locals() and command_name == 'exit':
                print("\nSaliendo.")
                break
            print("\n[Sistema] Desconectado. Reconectando...")
            time.sleep(3)


if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nSaliendo.")

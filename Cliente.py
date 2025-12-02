import socket
import threading
import json
import hashlib
import os
import sys
import time
from cryptography.fernet import Fernet

# --- 1. CONFIGURACIÓN DEL CLIENTE ---

# Lógica de Puerto Dinámico (Para que Kubernetes asigne el puerto)
try:
    TARGET_PORT = int(sys.argv[1])
    print(f"\n[Config] Usando puerto manual: {TARGET_PORT}")
except IndexError:
    TARGET_PORT = 30001
    print(f"\n[Config] Usando puerto por defecto: {TARGET_PORT}")
except ValueError:
    print("\n[Error] El puerto debe ser un número entero.")
    sys.exit(1)

SERVER_LIST = [
    ('127.0.0.1', TARGET_PORT),
    ('localhost', 12345)
]
BUFFER_SIZE = 4096

# CLAVE AES (Seguridad del proyecto)
SHARED_KEY = b'HegU0-k-ZWtT79TivN_O-XmIW0RrNUo6abZGPqwsnTs='

# --- 2. VARIABLES GLOBALES ---
is_running = True
logged_in_user = None
login_event = threading.Event()
recv_thread = None
session_username = None
session_password = None

# --- 3. HILO RECEPTOR (Tu lógica original) ---
def receive_handler(sock):
    global is_running, logged_in_user
    client_buffer = b""

    while is_running:
        try:
            raw_data = sock.recv(BUFFER_SIZE)
            if not raw_data:
                print("\n[Sistema] El servidor cerró la conexión.")
                break

            client_buffer += raw_data

            while b'\n' in client_buffer:
                response_data, client_buffer = client_buffer.split(b'\n', 1)
                if not response_data.strip(): continue

                try:
                    response = json.loads(response_data.decode('utf-8'))

                    if response['type'] == 'NEW_MESSAGE':
                        print(f"\n\n--- Nuevo Mensaje de [{response['from']}] ---")
                        print(f"> {response['content']}")
                        print("-------------------------------------------")

                    elif response['type'] == 'RESPONSE':
                        print(f"\n[Servidor] {response['message']}")
                        if 'Login exitoso' in response['message']:
                            # Extraer usuario
                            parts = response['message'].split(' ')
                            username = parts[-1].replace('.', '') if len(parts) > 2 else "Usuario"
                            logged_in_user = username
                            login_event.set()

                    elif response['type'] == 'ERROR':
                        print(f"\n[Error del Servidor] {response['message']}")
                        login_event.set()

                    # Restaurar prompt visual
                    if logged_in_user:
                        print(f"\n[{logged_in_user}] (msg, file, exit): ", end="")
                    else:
                        print(f"\n(login, register, exit): ", end="")
                    sys.stdout.flush()

                except json.JSONDecodeError:
                    pass

        except (ConnectionResetError, BrokenPipeError, OSError):
            if is_running:
                print("\n[Sistema] CONEXIÓN PERDIDA.")
            break
        except Exception as e:
            if is_running:
                print(f"\n[Error] Recepción: {e}")
            break

    is_running = False
    login_event.set()

# --- 4. CONEXIÓN (Modificado: Sin SSL) ---
def connect_to_server():
    for host, port in SERVER_LIST:
        try:
            # SOCKET PURO (TCP) - Esto elimina el error de SSL
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            print(f"Intentando conectar a {host}:{port}...")
            sock.connect((host, port))
            print(f"--- Conectado al servidor en {host}:{port} ---")
            return sock
        except ConnectionRefusedError:
            print(f"Servidor {host}:{port} no responde. Probando siguiente...")
            sock.close()
        except Exception as e:
            print(f"Error conectando a {host}:{port}: {e}")
            sock.close()
    return None

# --- 5. BUCLE PRINCIPAL (Tu estructura "Inmortal") ---
def main_loop():
    global is_running, logged_in_user, login_event, recv_thread
    global session_username, session_password

    # BUCLE INFINITO DE RECONEXIÓN
    while True:
        is_running = True
        logged_in_user = None
        login_event.clear()
        sock = None
        recv_thread = None

        try:
            sock = connect_to_server()

            if not sock:
                print("[Sistema] No hay servidores disponibles. Reintentando en 5 segundos...")
                time.sleep(5)
                continue

            # Iniciar hilo de escucha
            recv_thread = threading.Thread(target=receive_handler, args=(sock,))
            recv_thread.start()

            # --- RE-LOGIN AUTOMÁTICO ---
            if session_username and session_password:
                print(f"[Sistema] Reconectado. Reanudando sesión como {session_username}...")
                cmd = {"command": "LOGIN", "username": session_username, "password": session_password}
                login_event.clear()
                sock.sendall(json.dumps(cmd).encode('utf-8') + b'\n')
                login_event.wait(timeout=5.0)
                if not logged_in_user:
                    session_username = None
                    session_password = None

            # --- SUB-BUCLE 1: NO LOGUEADO ---
            while is_running and logged_in_user is None:
                try:
                    cmd_input = input("\nEscribe un comando (login, register, exit): ")
                except EOFError: break # Evita error si se cierra forzado
                
                if not is_running: break # Si se cayó el server mientras escribías
                
                parts = cmd_input.split()
                if not parts: continue
                command_name = parts[0].lower()

                if command_name == 'exit':
                    print("Saliendo...")
                    return # Salir del programa completo

                elif command_name == 'register' and len(parts) == 3:
                    cmd = {"command": "REGISTER", "username": parts[1], "password": parts[2]}
                    login_event.clear()
                    sock.sendall(json.dumps(cmd).encode('utf-8') + b'\n')
                    login_event.wait(5.0)

                elif command_name == 'login' and len(parts) == 3:
                    cmd = {"command": "LOGIN", "username": parts[1], "password": parts[2]}
                    login_event.clear()
                    sock.sendall(json.dumps(cmd).encode('utf-8') + b'\n')
                    login_event.wait(5.0)
                    if logged_in_user:
                        session_username = parts[1]
                        session_password = parts[2]
                else:
                    print("Comando incorrecto. Uso: login user pass | register user pass")

            # --- SUB-BUCLE 2: LOGUEADO ---
            while is_running and logged_in_user is not None:
                try:
                    prompt = f"\n[{logged_in_user}] (msg, file, exit): "
                    cmd_input = input(prompt)
                except EOFError: break

                if not is_running: break
                parts = cmd_input.split()
                if not parts: continue
                command_name = parts[0].lower()

                if command_name == 'exit':
                    print("Cerrando sesión...")
                    session_username = None
                    session_password = None
                    # Rompemos el bucle interno para volver al inicio, o salir del programa
                    is_running = False 
                    return 

                elif command_name == 'msg' and len(parts) >= 3:
                    content = " ".join(parts[2:])
                    cmd = {"command": "SEND_MESSAGE", "to": parts[1], "content": content}
                    sock.sendall(json.dumps(cmd).encode('utf-8') + b'\n')

                elif command_name == 'file' and len(parts) == 3:
                    # --- AQUÍ ESTÁ LA ENCRIPTACIÓN AES (REQUISITO PROYECTO) ---
                    path = parts[2]
                    if os.path.exists(path):
                        try:
                            # 1. Hash Original
                            sha = hashlib.sha256()
                            orig_data = b""
                            with open(path, "rb") as f:
                                while chunk := f.read(4096):
                                    sha.update(chunk)
                                    orig_data += chunk
                            
                            # 2. Encriptar
                            print("Encriptando archivo...")
                            fernet = Fernet(SHARED_KEY)
                            enc_data = fernet.encrypt(orig_data)
                            
                            # 3. Enviar Metadatos
                            cmd = {
                                "command": "SEND_FILE",
                                "to": parts[1],
                                "filename": os.path.basename(path),
                                "size": len(enc_data),
                                "hash": sha.hexdigest()
                            }
                            sock.sendall(json.dumps(cmd).encode('utf-8') + b'\n')
                            
                            # 4. Enviar Datos
                            print(f"Enviando {len(enc_data)} bytes encriptados...")
                            sock.sendall(enc_data)
                            print("Archivo enviado.")
                        except Exception as e:
                            print(f"[Error] Fallo al leer/enviar archivo: {e}")
                    else:
                        print("[Error] Archivo no encontrado.")

        except Exception as e:
            if is_running:
                print(f"[Error Global] {e}")

        finally:
            # SI LLEGAMOS AQUÍ, LA CONEXIÓN SE ROMPIÓ
            is_running = False
            if sock: sock.close()
            if recv_thread and recv_thread.is_alive():
                recv_thread.join()
            
            print("\n[Sistema] Desconectado. Reconectando en 3 segundos...")
            time.sleep(3)
            # El 'while True' externo volverá a empezar, reconectando automáticamente

if __name__ == "__main__":
    try:
        main_loop()
    except KeyboardInterrupt:
        print("\nSaliendo...")
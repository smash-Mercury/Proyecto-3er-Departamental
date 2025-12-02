import socket
import threading
import json
import logging
import os
import hashlib
import sqlite3
import time
from cryptography.fernet import Fernet

# --- CONFIGURACIÓN ---
HOST = '0.0.0.0'
PORT = 12345
REPLICA_HOST = os.getenv('K8S_SERVICE_HOST', 'storage-service')
REPLICA_PORT = int(os.getenv('K8S_SERVICE_PORT', 12345))

PRIMARY_DB = 'primary.db'
STORAGE_DIR = './storage'
# Clave AES para seguridad de datos (Cumple requisito de encriptación)
SHARED_KEY = b'HegU0-k-ZWtT79TivN_O-XmIW0RrNUo6abZGPqwsnTs='

online_clients = {}
online_clients_lock = threading.Lock()

logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# --- BASE DE DATOS ---


def init_db(db_name):
    try:
        db = sqlite3.connect(db_name, check_same_thread=False)
        c = db.cursor()
        c.execute(
            '''CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password_hash TEXT, salt BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS messages (id INTEGER PRIMARY KEY, sender TEXT, receiver TEXT, encrypted_message BLOB)''')
        c.execute('''CREATE TABLE IF NOT EXISTS files (id INTEGER PRIMARY KEY AUTOINCREMENT, filename TEXT, owner TEXT, stored_path TEXT, original_hash TEXT)''')
        db.commit()
        db.close()
    except Exception as e:
        logging.critical(f"Error DB: {e}")


def register_user(username, password):
    db = sqlite3.connect(PRIMARY_DB, check_same_thread=False)
    c = db.cursor()
    salt = os.urandom(16)
    ph = hashlib.pbkdf2_hmac('sha256', password.encode(), salt, 100000)
    try:
        c.execute("INSERT INTO users VALUES (?, ?, ?)",
                  (username, ph.hex(), salt.hex()))
        db.commit()
        return True
    except:
        return False
    finally:
        db.close()


def login_user(username, password):
    db = sqlite3.connect(PRIMARY_DB, check_same_thread=False)
    c = db.cursor()
    c.execute(
        "SELECT password_hash, salt FROM users WHERE username = ?", (username,))
    res = c.fetchone()
    db.close()
    if res:
        stored, salt = res
        ph = hashlib.pbkdf2_hmac(
            'sha256', password.encode(), bytes.fromhex(salt), 100000)
        return ph.hex() == stored
    return False

# --- REPLICACIÓN ---


def replicate_to_mirror(command_type, data):
    # Evitar bucle local
    if REPLICA_HOST in ['localhost', '127.0.0.1']:
        return

    logging.info(f"Replicando a {REPLICA_HOST}...")
    try:
        # Socket TCP puro (Sin SSL para evitar errores de red en Minikube)
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as rsock:
            rsock.settimeout(5.0)
            rsock.connect((REPLICA_HOST, REPLICA_PORT))

            if command_type == "NEW_FILE":
                # Header
                msg = f"REPLICATE_FILE|{data[0]}|{data[1]}|{data[2]}|{data[3]}\n"
                rsock.sendall(msg.encode('utf-8'))
                # Payload
                with open(data[2], 'rb') as f:
                    rsock.sendall(f.read())

            # Pausa técnica para asegurar transmisión completa
            time.sleep(1.0)
            logging.info(f"Replicación enviada.")
    except Exception as e:
        logging.error(f"Fallo replicación: {e}")

# --- GUARDADO ---


def save_file_locally(file_data_encrypted, filename, owner, original_hash, is_replica=False):
    try:
        stored_path = os.path.join(
            STORAGE_DIR, f"{original_hash}_{filename}.enc")
        with open(stored_path, "wb") as f:
            f.write(file_data_encrypted)

        # Registro en BD
        db = sqlite3.connect(PRIMARY_DB, check_same_thread=False)
        c = db.cursor()
        c.execute("SELECT id FROM files WHERE original_hash = ?",
                  (original_hash,))
        if not c.fetchone():
            c.execute("INSERT INTO files (filename, owner, stored_path, original_hash) VALUES (?, ?, ?, ?)",
                      (filename, owner, stored_path, original_hash))
            db.commit()
        db.close()

        # LÓGICA ANTI-BUCLE
        if not is_replica:
            threading.Thread(target=replicate_to_mirror, args=(
                "NEW_FILE", (filename, owner, stored_path, original_hash))).start()
            logging.info(f"Archivo guardado. Replicando...")
        else:
            logging.info(f"Réplica guardada (Fin de cadena).")
        return True
    except Exception as e:
        logging.error(f"Error guardando: {e}")
        return False

# --- MANEJADOR DE CLIENTES ---


def handle_client(conn, addr):
    logging.info(f"Conectado: {addr}")
    current_user = None
    client_buffer = b""

    try:
        while True:
            data = conn.recv(4096)
            if not data:
                break
            client_buffer += data

            while b'\n' in client_buffer:
                command_data, client_buffer = client_buffer.split(b'\n', 1)
                if not command_data.strip():
                    continue

                # CASO 1: RECIBIR RÉPLICA (FORMATO TEXTO)
                if command_data.startswith(b'REPLICATE_FILE'):
                    try:
                        parts = command_data.decode().strip().split('|')
                        filename, owner, original_hash = parts[1], parts[2], parts[4]

                        logging.info(f"Recibiendo réplica: {filename}")
                        replica_data = client_buffer
                        client_buffer = b""

                        conn.settimeout(5.0)
                        try:
                            while True:
                                chunk = conn.recv(4096)
                                if not chunk:
                                    break
                                replica_data += chunk
                        except:
                            pass

                        save_file_locally(
                            replica_data, filename, owner, original_hash, is_replica=True)
                        return  # Cerrar conexión tras recibir réplica
                    except Exception as e:
                        logging.error(f"Error réplica: {e}")
                        return

                # CASO 2: CLIENTE NORMAL (JSON)
                try:
                    cmd = json.loads(command_data.decode())

                    if cmd['command'] == 'REGISTER':
                        if register_user(cmd['username'], cmd['password']):
                            conn.sendall(json.dumps(
                                {"type": "RESPONSE", "message": "Registro exitoso"}).encode() + b'\n')
                        else:
                            conn.sendall(json.dumps(
                                {"type": "ERROR", "message": "Usuario existe"}).encode() + b'\n')

                    elif cmd['command'] == 'LOGIN':
                        if login_user(cmd['username'], cmd['password']):
                            current_user = cmd['username']
                            with online_clients_lock:
                                online_clients[current_user] = conn
                            conn.sendall(json.dumps(
                                {"type": "RESPONSE", "message": f"Login exitoso {current_user}"}).encode() + b'\n')
                        else:
                            conn.sendall(json.dumps(
                                {"type": "ERROR", "message": "Login fallido"}).encode() + b'\n')

                    elif cmd['command'] == 'SEND_MESSAGE':
                        if not current_user:
                            continue
                        tgt = cmd['to']
                        with online_clients_lock:
                            dest = online_clients.get(tgt)
                        if dest:
                            dest.sendall(json.dumps(
                                {"type": "NEW_MESSAGE", "from": current_user, "content": cmd['content']}).encode() + b'\n')
                            conn.sendall(json.dumps(
                                {"type": "RESPONSE", "message": "Enviado"}).encode() + b'\n')
                        else:
                            conn.sendall(json.dumps(
                                {"type": "RESPONSE", "message": "Usuario no conectado"}).encode() + b'\n')

                    elif cmd['command'] == 'SEND_FILE':
                        if not current_user:
                            continue
                        size = cmd["size"]
                        orig_hash = cmd["hash"]
                        fname = cmd["filename"]

                        # Leer payload encriptado
                        enc_data = b""
                        while len(enc_data) < size:
                            chunk = conn.recv(min(4096, size - len(enc_data)))
                            if not chunk:
                                break
                            enc_data += chunk

                        # SEGURIDAD: Desencriptar y verificar Hash
                        try:
                            f = Fernet(SHARED_KEY)
                            decrypted = f.decrypt(enc_data)
                            if hashlib.sha256(decrypted).hexdigest() == orig_hash:
                                save_file_locally(
                                    enc_data, fname, current_user, orig_hash)
                                conn.sendall(json.dumps(
                                    {"type": "RESPONSE", "message": "Archivo seguro guardado y replicado."}).encode() + b'\n')

                                # Notificar destinatario
                                with online_clients_lock:
                                    if dest := online_clients.get(cmd['to']):
                                        dest.sendall(json.dumps(
                                            {"type": "NEW_MESSAGE", "from": current_user, "content": f"Archivo recibido: {fname}"}).encode() + b'\n')
                            else:
                                conn.sendall(json.dumps(
                                    {"type": "ERROR", "message": "Integridad fallida"}).encode() + b'\n')
                        except:
                            conn.sendall(json.dumps(
                                {"type": "ERROR", "message": "Error desencriptación"}).encode() + b'\n')

                except json.JSONDecodeError:
                    pass
    except Exception as e:
        logging.error(f"Error: {e}")
    finally:
        if current_user:
            with online_clients_lock:
                if current_user in online_clients:
                    del online_clients[current_user]
        conn.close()


def main():
    init_db(PRIMARY_DB)
    os.makedirs(STORAGE_DIR, exist_ok=True)

    # Servidor TCP puro (Sin SSL)
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind((HOST, PORT))
        sock.listen(5)
        logging.info(f"Servidor TCP (Sin SSL) escuchando en {HOST}:{PORT}")
        while True:
            conn, addr = sock.accept()
            threading.Thread(target=handle_client, args=(conn, addr)).start()


if __name__ == "__main__":
    main()

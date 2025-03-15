import socket
import threading
import os
import json
import base64
import ssl

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'  # Replace with your server's public IP or domain
PORT = 12345

# ----------------- Key Management and Hybrid Encryption Functions -----------------
def load_or_generate_keys():
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        with open("private_key.pem", "wb") as f:
            f.write(private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.TraditionalOpenSSL,
                encryption_algorithm=serialization.NoEncryption()
            ))
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        return private_key, public_key

def encrypt_hybrid(plaintext, recipient_public_keys):
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_message = f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    encrypted_keys = {}
    for nick, pub_key_obj in recipient_public_keys.items():
        enc_sym_key = pub_key_obj.encrypt(
            symmetric_key,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        encrypted_keys[nick] = base64.b64encode(enc_sym_key).decode('utf-8')
    package = {
        'encrypted_message': encrypted_message,
        'encrypted_keys': encrypted_keys
    }
    return json.dumps(package)

def decrypt_hybrid(package_str, own_nickname, private_key):
    package = json.loads(package_str)
    encrypted_message = package['encrypted_message']
    encrypted_keys = package['encrypted_keys']
    if own_nickname not in encrypted_keys:
        raise Exception("No encrypted key available for this user.")
    enc_sym_key = base64.b64decode(encrypted_keys[own_nickname])
    symmetric_key = private_key.decrypt(
        enc_sym_key,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    f = Fernet(symmetric_key)
    decrypted_message = f.decrypt(encrypted_message.encode('utf-8')).decode('utf-8')
    return decrypted_message

# ----------------- Client Globals -----------------
private_key, public_key = load_or_generate_keys()
my_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

public_keys = {}   # {username: rsa_public_key_object}
my_nickname = None
current_room = None

# ----------------- TLS Setup for Client -----------------
# Create an SSL context for the client. For demonstration, we disable hostname checking.
ssl_context = ssl.create_default_context()
ssl_context.check_hostname = False
ssl_context.verify_mode = ssl.CERT_NONE

raw_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client = ssl_context.wrap_socket(raw_sock, server_hostname=HOST)
client.connect((HOST, PORT))

# ----------------- Communication -----------------
def send_command(command_line):
    client.send(f"CMD::{command_line}".encode('utf-8'))

def broadcast_our_key():
    if my_nickname:
        pubkey_msg = f"PUBKEY::{my_nickname}::{my_public_pem}"
        client.send(pubkey_msg.encode('utf-8'))

def handle_server_message(msg):
    if msg.startswith("PUBKEY::"):
        try:
            _, sender, pubkey_pem = msg.split("::", 2)
            if sender not in public_keys:
                pub_key_obj = serialization.load_pem_public_key(pubkey_pem.encode('utf-8'))
                public_keys[sender] = pub_key_obj
        except:
            pass
    elif msg.endswith(" joined the chat!") or msg.endswith(" left the chat."):
        print(msg)
    else:
        print(msg)

def receive_thread_func():
    global my_nickname
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            message = data.decode('utf-8', errors='ignore')
            try:
                _ = json.loads(message)
                if my_nickname:
                    try:
                        decrypted = decrypt_hybrid(message, my_nickname, private_key)
                        print(decrypted)
                    except Exception as e:
                        pass
                else:
                    pass
            except json.JSONDecodeError:
                handle_server_message(message)
        except Exception:
            client.close()
            break

def write_thread_func():
    global my_nickname, current_room
    print("Type '/login <user> <pass>' or '/register <user> <pass>' to get started.")
    print("Type '/create <room> <pass>' or '/join <room> <pass>' to manage rooms.")
    print("Type '/list' to list rooms.")
    print("Type 'exit' to disconnect.\n")
    while True:
        line = input()
        if not line:
            continue
        if line.lower() == "exit":
            client.close()
            break
        if line.startswith("/"):
            send_command(line)
            parts = line.split()
            if len(parts) >= 3 and parts[0].lower() == "/login":
                my_nickname = parts[1]
                broadcast_our_key()  # send our key after login
            if len(parts) >= 2 and parts[0].lower() == "/join":
                current_room = parts[1]
                broadcast_our_key()  # send our key after joining a room
        else:
            if not my_nickname:
                print("You must /login before sending chat messages.")
                continue
            if not current_room:
                print("You must /join a room before sending chat messages.")
                continue
            plaintext = f"{my_nickname}: {line}"
            # Include our own key in the recipients so that we (and others) can decrypt
            recipients = public_keys.copy()
            recipients[my_nickname] = public_key
            encrypted_body = encrypt_hybrid(plaintext, recipients)
            pkg = json.loads(encrypted_body)
            pkg['room'] = current_room
            client.send(json.dumps(pkg).encode('utf-8'))

recv_thread = threading.Thread(target=receive_thread_func)
recv_thread.start()
write_thread = threading.Thread(target=write_thread_func)
write_thread.start()

recv_thread.join()
write_thread.join()

import socket
import threading
import json
import os
import base64
import hashlib
import random
import string
from cryptography.fernet import Fernet

HOST = '127.0.0.1'
PORT = 12345

# --------------------- Encryption for the "database" ---------------------
DB_KEY_FILE = "db_key.bin"
DB_ENC_FILE = "database.enc"

def load_or_create_db_key():
    if os.path.exists(DB_KEY_FILE):
        with open(DB_KEY_FILE, 'rb') as f:
            return f.read()
    else:
        new_key = Fernet.generate_key()
        with open(DB_KEY_FILE, 'wb') as f:
            f.write(new_key)
        return new_key

db_key = load_or_create_db_key()
fernet = Fernet(db_key)

# --------------------- Database Structure ---------------------
def load_database():
    if not os.path.exists(DB_ENC_FILE):
        db = {"users": {}, "rooms": {}}
        print("No database found. Creating a new one...")
        god_pass = input("Set a password for the 'god' user: ").strip()
        create_user(db, "god", god_pass)
        save_database(db)
        return db
    else:
        with open(DB_ENC_FILE, 'rb') as f:
            enc_data = f.read()
        try:
            dec_data = fernet.decrypt(enc_data)
            return json.loads(dec_data.decode('utf-8'))
        except:
            print("ERROR: Could not decrypt database.enc with current db_key.")
            print("Delete database.enc and db_key.bin to reinitialize if needed.")
            raise

def save_database(db):
    data_bytes = json.dumps(db).encode('utf-8')
    enc_data = fernet.encrypt(data_bytes)
    with open(DB_ENC_FILE, 'wb') as f:
        f.write(enc_data)

# --------------------- Utility: Users ---------------------
def random_salt(length=16):
    chars = string.ascii_letters + string.digits
    return ''.join(random.choice(chars) for _ in range(length))

def hash_password(password, salt):
    return hashlib.sha256((salt + password).encode('utf-8')).hexdigest()

def create_user(db, username, password):
    if username in db["users"]:
        return False, "User already exists."
    salt = random_salt()
    pass_hash = hash_password(password, salt)
    db["users"][username] = {"salt": salt, "pass_hash": pass_hash}
    return True, "User created."

def check_user_credentials(db, username, password):
    if username not in db["users"]:
        return False
    user_data = db["users"][username]
    test_hash = hash_password(password, user_data["salt"])
    return (test_hash == user_data["pass_hash"])

# --------------------- Utility: Rooms ---------------------
def create_room(db, room_name, room_password):
    if room_name in db["rooms"]:
        return False, "Room already exists."
    db["rooms"][room_name] = {"password": room_password}
    return True, "Room created."

def check_room_password(db, room_name, room_password):
    if room_name not in db["rooms"]:
        return False
    return db["rooms"][room_name]["password"] == room_password

# --------------------- Server Global State ---------------------
client_sessions = {}  # {client_socket: {"username":..., "logged_in":bool, "room":...}}
public_keys = {}      # {username: <public key PEM string>}
db = load_database()

# --------------------- Socket Setup ---------------------
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()
print(f"Server is running on {HOST}:{PORT}")

# --------------------- Broadcasting ---------------------
def broadcast_to_room(room_name, message, exclude_client=None):
    for client, session in client_sessions.items():
        if session["room"] == room_name and client != exclude_client:
            try:
                client.send(message)
            except:
                remove_client(client)

def broadcast_to_all(message, exclude_client=None):
    for client in client_sessions:
        if client != exclude_client:
            try:
                client.send(message)
            except:
                remove_client(client)

def remove_client(client):
    if client not in client_sessions:
        return
    session = client_sessions[client]
    username = session["username"]
    room = session["room"]
    del client_sessions[client]
    if username is not None and username != "god" and room:
        broadcast_to_room(room, f"{username} left the chat.".encode('utf-8'))
        print(f"{username} disconnected from room {room}.")
    client.close()

# --------------------- Command Handling ---------------------
def handle_command(client, command_str):
    session = client_sessions[client]
    parts = command_str.strip().split()
    if not parts:
        return False

    cmd = parts[0].lower()

    if cmd == "/register":
        if len(parts) < 3:
            send_client(client, "Usage: /register <username> <password>")
            return True
        username, password = parts[1], parts[2]
        if username == "god":
            send_client(client, "Cannot create 'god' user. That is reserved.")
            return True
        success, msg = create_user(db, username, password)
        if success:
            save_database(db)
            send_client(client, f"Registration successful for {username}. You may now /login.")
        else:
            send_client(client, f"Registration failed: {msg}")
        return True

    elif cmd == "/login":
        if len(parts) < 3:
            send_client(client, "Usage: /login <username> <password>")
            return True
        username, password = parts[1], parts[2]
        if check_user_credentials(db, username, password):
            session["username"] = username
            session["logged_in"] = True
            session["room"] = None
            send_client(client, f"Login successful. Welcome, {username}!")
            print(f"User {username} logged in.")
        else:
            send_client(client, "Login failed. Invalid username or password.")
        return True

    elif cmd == "/create":
        if not session["logged_in"]:
            send_client(client, "You must /login first.")
            return True
        if len(parts) < 3:
            send_client(client, "Usage: /create <roomName> <roomPassword>")
            return True
        room_name, room_password = parts[1], parts[2]
        success, msg = create_room(db, room_name, room_password)
        if success:
            save_database(db)
            send_client(client, f"Room '{room_name}' created.")
        else:
            send_client(client, f"Create room failed: {msg}")
        return True

    elif cmd == "/join":
        if not session["logged_in"]:
            send_client(client, "You must /login first.")
            return True
        if len(parts) < 2:
            send_client(client, "Usage: /join <roomName> [<roomPassword>]")
            return True
        room_name = parts[1]
        if session["username"] == "god":
            room_password = None
        else:
            if len(parts) < 3:
                send_client(client, "Usage: /join <roomName> <roomPassword>")
                return True
            room_password = parts[2]
        if room_name not in db["rooms"]:
            send_client(client, f"Room '{room_name}' does not exist.")
            return True
        if session["username"] != "god":
            if not check_room_password(db, room_name, room_password):
                send_client(client, "Incorrect room password.")
                return True
        old_room = session["room"]
        session["room"] = room_name
        if session["username"] != "god":
            broadcast_to_room(room_name, f"{session['username']} joined the chat!".encode('utf-8'))
            print(f"{session['username']} joined room {room_name}.")
        else:
            print("god joined a room silently.")
        if old_room and old_room != room_name and session["username"] != "god":
            broadcast_to_room(old_room, f"{session['username']} left the chat.".encode('utf-8'))
        return True

    elif cmd == "/list":
        if not session["logged_in"]:
            send_client(client, "You must /login first.")
            return True
        rooms_list = list(db["rooms"].keys())
        if rooms_list:
            send_client(client, "Available rooms: " + ", ".join(rooms_list))
        else:
            send_client(client, "No rooms found.")
        return True

    return False

def send_client(client, text):
    try:
        client.send(text.encode('utf-8'))
    except:
        remove_client(client)

# --------------------- Main Client Loop ---------------------
def handle_client(client):
    client_sessions[client] = {"username": None, "logged_in": False, "room": None}
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            message = data.decode('utf-8', errors='ignore')
            if message.startswith("CMD::"):
                cmd_str = message[len("CMD::"):]
                recognized = handle_command(client, cmd_str)
                if not recognized:
                    send_client(client, "Unknown command.")
                continue
            if message.startswith("PUBKEY::"):
                # When a PUBKEY message is received, update our dictionary and forward it to everyone else.
                parts = message.split("::", 2)
                if len(parts) == 3:
                    _, user, pubkey_pem = parts
                    public_keys[user] = pubkey_pem
                    # Forward the public key message to all other clients.
                    for c in client_sessions:
                        if c != client:
                            try:
                                c.send(message.encode('utf-8'))
                            except:
                                remove_client(c)
                continue
            # Otherwise, assume it's an encrypted chat message in JSON format.
            session = client_sessions[client]
            if session["logged_in"] and session["room"]:
                try:
                    pkg = json.loads(message)
                    if "room" not in pkg:
                        send_client(client, "Invalid message format: missing room.")
                        continue
                    if pkg["room"] != session["room"]:
                        send_client(client, "Error: message room mismatch.")
                        continue
                    # --- Debug log added here ---
                    print(f"DEBUG: User '{session['username']}' in room '{session['room']}' sent package: {pkg}")
                    broadcast_to_room(session["room"], data, exclude_client=client)
                except Exception as e:
                    send_client(client, "Invalid message format.")
            else:
                send_client(client, "You must /join a room to chat.")
        except Exception as e:
            break
    remove_client(client)

def accept_connections():
    while True:
        client, address = server.accept()
        print(f"New connection from {address}")
        threading.Thread(target=handle_client, args=(client,)).start()

accept_connections()

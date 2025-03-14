import socket
import threading
import sqlite3
import os
import base64
import json
import time

from cryptography.fernet import Fernet
from passlib.hash import bcrypt

# ------------------ Server Configuration ------------------ #
HOST = '127.0.0.1'
PORT = 12345

# ------------------ Encryption Key for DB ----------------- #
# Used to encrypt messages at rest in the database
# In a real system, you might load this from a secure vault or environment variable
if not os.path.exists("server_db.key"):
    with open("server_db.key", "wb") as f:
        f.write(Fernet.generate_key())
with open("server_db.key", "rb") as f:
    DB_ENC_KEY = f.read()
DB_CIPHER = Fernet(DB_ENC_KEY)

# ------------------ Database Setup ------------------ #
db_path = "server_database.sqlite"

def init_db():
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    # Create tables if they do not exist
    c.execute("""CREATE TABLE IF NOT EXISTS users (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   username TEXT UNIQUE NOT NULL,
                   password_hash TEXT NOT NULL
                 );""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS chatrooms (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   roomname TEXT UNIQUE NOT NULL
                 );""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS memberships (
                   user_id INTEGER,
                   room_id INTEGER,
                   FOREIGN KEY(user_id) REFERENCES users(id),
                   FOREIGN KEY(room_id) REFERENCES chatrooms(id)
                 );""")
    
    c.execute("""CREATE TABLE IF NOT EXISTS messages (
                   id INTEGER PRIMARY KEY AUTOINCREMENT,
                   room_id INTEGER,
                   sender TEXT,
                   message_enc BLOB,   -- Encrypted with DB_CIPHER
                   timestamp REAL,
                   FOREIGN KEY(room_id) REFERENCES chatrooms(id)
                 );""")
    conn.commit()
    conn.close()

init_db()

def get_user_id(username):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def get_room_id(roomname):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT id FROM chatrooms WHERE roomname = ?", (roomname,))
    row = c.fetchone()
    conn.close()
    return row[0] if row else None

def create_room_if_not_exists(roomname):
    room_id = get_room_id(roomname)
    if room_id is None:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO chatrooms (roomname) VALUES (?)", (roomname,))
        conn.commit()
        conn.close()
        return get_room_id(roomname)
    return room_id

def user_in_room(username, roomname):
    """Check if user is a member of the given room."""
    user_id = get_user_id(username)
    room_id = get_room_id(roomname)
    if not user_id or not room_id:
        return False
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT 1 FROM memberships WHERE user_id = ? AND room_id = ?", (user_id, room_id))
    row = c.fetchone()
    conn.close()
    return bool(row)

def add_user_to_room(username, roomname):
    """Add user to room membership table."""
    user_id = get_user_id(username)
    room_id = create_room_if_not_exists(roomname)
    if user_id and room_id and not user_in_room(username, roomname):
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("INSERT INTO memberships (user_id, room_id) VALUES (?,?)", (user_id, room_id))
        conn.commit()
        conn.close()

def remove_user_from_room(username, roomname):
    user_id = get_user_id(username)
    room_id = get_room_id(roomname)
    if user_id and room_id:
        conn = sqlite3.connect(db_path)
        c = conn.cursor()
        c.execute("DELETE FROM memberships WHERE user_id = ? AND room_id = ?", (user_id, room_id))
        conn.commit()
        conn.close()

def store_message(roomname, sender, plaintext):
    """
    Encrypt the plaintext message with the DB_CIPHER and store it in the messages table.
    """
    room_id = create_room_if_not_exists(roomname)
    enc_msg = DB_CIPHER.encrypt(plaintext.encode('utf-8'))
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""INSERT INTO messages (room_id, sender, message_enc, timestamp)
                 VALUES (?,?,?,?)""",
                 (room_id, sender, enc_msg, time.time()))
    conn.commit()
    conn.close()

def get_room_history(roomname, limit=50):
    """
    Retrieve the last `limit` messages from the specified room, decrypt them,
    and return as a list of (sender, message, timestamp).
    """
    room_id = get_room_id(roomname)
    if not room_id:
        return []
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("""SELECT sender, message_enc, timestamp
                 FROM messages
                 WHERE room_id = ?
                 ORDER BY id DESC
                 LIMIT ?""", (room_id, limit))
    rows = c.fetchall()
    conn.close()
    # Reverse to get chronological order
    rows.reverse()
    # Decrypt
    history = []
    for sender, enc_msg, ts in rows:
        try:
            msg_plain = DB_CIPHER.decrypt(enc_msg).decode('utf-8')
        except:
            msg_plain = "<CORRUPTED MESSAGE>"
        history.append((sender, msg_plain, ts))
    return history

# ------------------ Registration & Login ------------------ #
def register_user(username, password):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    try:
        password_hash = bcrypt.hash(password)
        c.execute("INSERT INTO users (username, password_hash) VALUES (?,?)",
                  (username, password_hash))
        conn.commit()
        conn.close()
        return True
    except sqlite3.IntegrityError:
        conn.close()
        return False

def login_user(username, password):
    conn = sqlite3.connect(db_path)
    c = conn.cursor()
    c.execute("SELECT password_hash FROM users WHERE username = ?", (username,))
    row = c.fetchone()
    conn.close()
    if row:
        stored_hash = row[0]
        return bcrypt.verify(password, stored_hash)
    return False

# ------------------ Socket Handling ------------------ #
server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

# Global list of connected clients
clients = []  # list of (socket, username)
lock = threading.Lock()

def broadcast_to_room(roomname, message, sender_socket=None):
    """
    Broadcast an already-encrypted message to all users in the given room.
    We only send to clients that are logged in and belong to that room.
    """
    with lock:
        for (cl_socket, cl_username) in clients:
            if cl_socket != sender_socket and user_in_room(cl_username, roomname):
                try:
                    cl_socket.send(message)
                except:
                    pass

def find_socket_by_username(username):
    with lock:
        for (cl_socket, cl_username) in clients:
            if cl_username == username:
                return cl_socket
    return None

def remove_client(client_socket):
    """Remove a client from the global list."""
    with lock:
        for i, (cl_socket, cl_username) in enumerate(clients):
            if cl_socket == client_socket:
                clients.pop(i)
                print(f"{cl_username} disconnected.")
                break

def handle_client(client_socket):
    """
    Handle commands and messages from a single client.
    All messages from the client are expected to be in plaintext JSON
    containing the fields we need, or hybrid-encrypted packages
    that we just relay to the right place.
    """
    username = None
    active_room = None  # Track which room the user is currently chatting in

    try:
        while True:
            data = client_socket.recv(4096)
            if not data:
                break
            try:
                text = data.decode('utf-8')
            except:
                # Possibly an encrypted package. We just handle as a broadcast?
                continue

            # We'll parse commands in plaintext JSON
            # e.g. {"cmd":"register","username":"foo","password":"bar"}
            # or   {"cmd":"message","room":"general","content":"<encrypted JSON>"}
            # or   {"cmd":"pm","to":"bob","content":"<encrypted JSON>"}
            # etc.
            try:
                msg_obj = json.loads(text)
            except:
                # Not valid JSON => possibly an encrypted broadcast
                # If the user is in a room, store & broadcast
                if username and active_room:
                    store_message(active_room, username, text)
                    broadcast_to_room(active_room, data, client_socket)
                continue

            cmd = msg_obj.get("cmd")

            # ------------------ Registration ------------------ #
            if cmd == "register":
                reg_user = msg_obj.get("username")
                reg_pass = msg_obj.get("password")
                if register_user(reg_user, reg_pass):
                    client_socket.send(b'{"status":"ok","msg":"Registered successfully"}')
                else:
                    client_socket.send(b'{"status":"error","msg":"Username taken"}')

            # ------------------ Login ------------------ #
            elif cmd == "login":
                log_user = msg_obj.get("username")
                log_pass = msg_obj.get("password")
                if login_user(log_user, log_pass):
                    username = log_user
                    # Add to global list
                    with lock:
                        clients.append((client_socket, username))
                    client_socket.send(b'{"status":"ok","msg":"Login success"}')
                    print(f"{username} logged in.")
                else:
                    client_socket.send(b'{"status":"error","msg":"Invalid credentials"}')

            # ------------------ Join Room ------------------ #
            elif cmd == "join":
                room = msg_obj.get("room")
                if username:
                    add_user_to_room(username, room)
                    active_room = room  # Switch active room
                    client_socket.send(b'{"status":"ok","msg":"Joined room"}')
                else:
                    client_socket.send(b'{"status":"error","msg":"Login first"}')

            # ------------------ Leave Room ------------------ #
            elif cmd == "leave":
                room = msg_obj.get("room")
                if username:
                    remove_user_from_room(username, room)
                    # If user’s active_room is the one they left, set None
                    if active_room == room:
                        active_room = None
                    client_socket.send(b'{"status":"ok","msg":"Left room"}')
                else:
                    client_socket.send(b'{"status":"error","msg":"Login first"}')

            # ------------------ Switch Room ------------------ #
            elif cmd == "switch":
                room = msg_obj.get("room")
                if username:
                    if user_in_room(username, room):
                        active_room = room
                        client_socket.send(b'{"status":"ok","msg":"Switched room"}')
                    else:
                        client_socket.send(b'{"status":"error","msg":"Join the room first"}')
                else:
                    client_socket.send(b'{"status":"error","msg":"Login first"}')

            # ------------------ Send Message ------------------ #
            elif cmd == "message":
                # The content is already an encrypted JSON string
                room = msg_obj.get("room")
                content = msg_obj.get("content")
                if username and room and user_in_room(username, room):
                    # Store in DB
                    store_message(room, username, content)
                    # Broadcast
                    broadcast_to_room(room, content.encode('utf-8'), client_socket)
                else:
                    client_socket.send(b'{"status":"error","msg":"Cannot send message"}')

            # ------------------ Private Message ------------------ #
            elif cmd == "pm":
                to_user = msg_obj.get("to")
                content = msg_obj.get("content")
                if username and to_user and content:
                    # Send directly to recipient if they’re online
                    target_sock = find_socket_by_username(to_user)
                    if target_sock:
                        # We store it in DB as well if we want to keep PM history
                        # For demonstration, store in a special "pm-<two_users>" room
                        pm_room = f"pm-{min(username,to_user)}-{max(username,to_user)}"
                        store_message(pm_room, username, content)

                        target_sock.send(content.encode('utf-8'))
                    else:
                        client_socket.send(b'{"status":"error","msg":"User not online"}')
                else:
                    client_socket.send(b'{"status":"error","msg":"Invalid PM"}')

            # ------------------ Get History ------------------ #
            elif cmd == "history":
                room = msg_obj.get("room")
                if username and user_in_room(username, room):
                    logs = get_room_history(room, limit=50)
                    # Return as JSON
                    # logs is list of (sender, plaintext, timestamp)
                    # In a real system, messages are E2E encrypted, so the server never has plaintext.
                    # Here we are storing the E2E ciphertext in the DB. We can only give that back.
                    # For demonstration, we stored "plaintext" to show the concept of encryption at rest.
                    # In real E2E, you might store ciphertext in the DB, and let the client do the decrypt.
                    # So let's assume logs[] is storing the ciphertext or something. We'll just pass it back.
                    history_list = []
                    for sender, plaintext, ts in logs:
                        history_list.append({"sender": sender, "message": plaintext, "timestamp": ts})
                    resp = json.dumps({"status":"ok","history": history_list})
                    client_socket.send(resp.encode('utf-8'))
                else:
                    client_socket.send(b'{"status":"error","msg":"Cannot get history"}')

    except Exception as e:
        print(f"Client error: {e}")
    finally:
        remove_client(client_socket)
        client_socket.close()

def accept_clients():
    print(f"Server listening on {HOST}:{PORT}")
    while True:
        client_socket, addr = server.accept()
        print(f"Connection from {addr}")
        t = threading.Thread(target=handle_client, args=(client_socket,))
        t.start()

if __name__ == "__main__":
    accept_clients()

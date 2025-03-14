import socket
import threading
import json

import os
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

HOST = '127.0.0.1'
PORT = 12345

# ----------------- Key Management (Same as Before) ----------------- #

def load_or_generate_keys():
    """Load RSA key pair from files or generate new ones if not present."""
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
    """Encrypt plaintext with a random symmetric key, then RSA-encrypt that key for each recipient."""
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_message = f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    
    encrypted_keys = {}
    for nick, pub_key in recipient_public_keys.items():
        enc_sym_key = pub_key.encrypt(
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
    """Decrypt a hybrid-encrypted package for this user."""
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

# ------------------------------------------------------------------- #
private_key, public_key = load_or_generate_keys()
my_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Map from nickname -> public key
public_keys = {}

# Our session
client_socket = None
my_nickname = None
active_room = None

def send_json_command(cmd_obj):
    """Utility to send a JSON command to the server."""
    global client_socket
    msg_str = json.dumps(cmd_obj)
    client_socket.send(msg_str.encode('utf-8'))

def handle_server():
    """Background thread to handle server responses and E2E-encrypted messages."""
    while True:
        try:
            data = client_socket.recv(4096)
            if not data:
                print("Disconnected from server.")
                break
            text = data.decode('utf-8')
            
            # Try to parse as JSON
            try:
                resp = json.loads(text)
                # If it’s a JSON object with "status", we handle it as a command response
                if "status" in resp:
                    if resp["status"] == "ok":
                        if "msg" in resp:
                            print("[Server] OK:", resp["msg"])
                        if "history" in resp:
                            print("Chat History:")
                            for item in resp["history"]:
                                # item = {sender, message, timestamp}
                                print(f"{item['sender']}: {item['message']} (t={item['timestamp']})")
                    else:
                        print("[Server] ERROR:", resp["msg"])
                else:
                    # It's some other JSON we don't recognize
                    print("[Server] JSON:", resp)
            except:
                # Not valid JSON => treat as an encrypted chat message
                # Attempt to decrypt with our private key
                try:
                    plaintext = decrypt_hybrid(text, my_nickname, private_key)
                    print(plaintext)
                except:
                    # If it fails, just print raw
                    # (This might be a message not intended for us, or we have no key.)
                    pass

        except Exception as e:
            print("[Error receiving from server]", e)
            break

def connect_to_server():
    """Connect to the server and start the background thread."""
    global client_socket
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    client_socket = sock
    th = threading.Thread(target=handle_server, daemon=True)
    th.start()

def broadcast_our_public_key():
    """We can broadcast our public key to other clients by storing it on the client side,
       or we can rely on your previous approach of PUBKEY:: messages. 
       In this example, let's skip it or adapt as needed. 
       For a real multi-user environment, we'd want a key-exchange protocol."""
    pass

def main():
    global my_nickname, active_room
    connect_to_server()
    
    print("Commands:")
    print("  /register <username> <password>")
    print("  /login <username> <password>")
    print("  /join <roomname>")
    print("  /leave <roomname>")
    print("  /switch <roomname>")
    print("  /pm <recipient> <message>")
    print("  /history <roomname>")
    print("  /send <message> (sends to active room)")
    print("  /exit")
    
    while True:
        line = input("> ")
        if not line:
            continue
        
        parts = line.split(" ", 2)
        cmd = parts[0].lower()

        if cmd == "/exit":
            client_socket.close()
            print("Exiting.")
            break

        elif cmd == "/register" and len(parts) == 3:
            # /register <username> <password>
            username, password = parts[1], parts[2]
            send_json_command({"cmd":"register","username":username,"password":password})

        elif cmd == "/login" and len(parts) == 3:
            # /login <username> <password>
            username, password = parts[1], parts[2]
            send_json_command({"cmd":"login","username":username,"password":password})
            my_nickname = username

        elif cmd == "/join" and len(parts) == 2:
            # /join <roomname>
            roomname = parts[1]
            send_json_command({"cmd":"join","room":roomname})

        elif cmd == "/leave" and len(parts) == 2:
            # /leave <roomname>
            roomname = parts[1]
            send_json_command({"cmd":"leave","room":roomname})

        elif cmd == "/switch" and len(parts) == 2:
            # /switch <roomname>
            roomname = parts[1]
            active_room = roomname
            send_json_command({"cmd":"switch","room":roomname})

        elif cmd == "/pm" and len(parts) == 3:
            # /pm <recipient> <message>
            subparts = parts[1].split(" ", 1)
            # Actually we said: /pm <recipient> <message>
            # But we used parts[1], parts[2] => let's parse carefully
            recipient = parts[1]
            message_body = parts[2]

            # E2E-encrypt with your known public key for that recipient 
            # (in a real system, you'd store their public key in public_keys)
            # For demonstration, let's assume we have it or you skip encryption for PM. 
            # We'll just send the ciphertext as if it’s normal text:

            # If you want to do E2E with the same approach, you need:
            #   ciphertext = encrypt_hybrid(f"{my_nickname} (PM to {recipient}): {message_body}", {recipient: recipient_public_key})
            # But let's keep it simple for now:
            send_json_command({"cmd":"pm","to":recipient,"content":f"{my_nickname} (PM): {message_body}"})

        elif cmd == "/history" and len(parts) == 2:
            # /history <roomname>
            roomname = parts[1]
            send_json_command({"cmd":"history","room":roomname})

        elif cmd == "/send" and len(parts) == 2:
            # /send <message>
            if not active_room:
                print("No active room. Use /join or /switch first.")
            else:
                message_body = parts[1]
                # E2E encrypt with the known public keys of that room’s members (not tracked here).
                # For demonstration, we only do a single broadcast to the server.
                # In a real scenario, you'd maintain a dictionary of public keys for each user in the room.
                # We'll just treat it as if there's a single shared public key or skip it.
                
                # For the sake of the example, let's do "encrypt with my own key only" 
                # so that we see it on the client side:
                # (In a real system, you'd have each user’s key.)
                ciphertext = encrypt_hybrid(f"{my_nickname}: {message_body}", {my_nickname: public_key})
                send_json_command({"cmd":"message","room":active_room,"content":ciphertext})

        else:
            print("Unknown command or invalid syntax.")

if __name__ == "__main__":
    main()

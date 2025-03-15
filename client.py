import socket
import threading
import os
import json
import base64

from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

# ----------------- Key Management and Hybrid Encryption Functions -----------------

def load_or_generate_keys():
    """Load RSA key pair from files or generate new ones if not present."""
    if os.path.exists("private_key.pem") and os.path.exists("public_key.pem"):
        with open("private_key.pem", "rb") as f:
            private_key = serialization.load_pem_private_key(f.read(), password=None)
        with open("public_key.pem", "rb") as f:
            public_key = serialization.load_pem_public_key(f.read())
        return private_key, public_key
    else:
        # Generate new RSA key pair (simulating PGP key pair)
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()
        # Save keys to files
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
    """
    Encrypt the plaintext using a random symmetric key (Fernet),
    then encrypt that symmetric key with each recipient’s RSA public key.
    Returns a JSON string containing the encrypted message and
    the encrypted symmetric keys (one per recipient).
    """
    # Generate random symmetric key and encrypt the message
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_message = f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    
    # Encrypt the symmetric key for each recipient
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
    """
    Given a JSON package (as produced by encrypt_hybrid), use the client’s RSA
    private key to decrypt the symmetric key and then the message.
    """
    package = json.loads(package_str)
    encrypted_message = package['encrypted_message']
    encrypted_keys = package['encrypted_keys']
    
    if own_nickname not in encrypted_keys:
        # This message was not encrypted for the current user.
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

# ----------------- Global Variables -----------------

HOST = '127.0.0.1'
PORT = 12345

# Load or generate RSA keys for PGP-like encryption
private_key, public_key = load_or_generate_keys()
my_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

public_keys = {}  # {nickname: public_key_object}

# ----------------- Handshake Logic -----------------

def try_connect(nickname):
    """
    Connect to the server, handle the nickname handshake.
    Returns the socket if successful, or None if we need a new nickname.
    """
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.connect((HOST, PORT))
    
    # Wait for server to request a nickname
    msg = sock.recv(4096).decode('utf-8')
    if msg == "NICK":
        sock.send(nickname.encode('utf-8'))
        # Next message could be NICKACCEPT or NICKTAKEN
        msg2 = sock.recv(4096).decode('utf-8')
        if msg2 == "NICKACCEPT":
            # We store our own nickname in the dictionary too
            public_keys[nickname] = public_key
            return sock
        elif msg2 == "NICKTAKEN":
            sock.close()
            return None
    return None

# ----------------- Main Client Flow -----------------

while True:
    nickname = input("Choose your nickname: ")
    client = try_connect(nickname)
    if client is None:
        print("Nickname already taken. Please choose another one.")
    else:
        break

def broadcast_our_key():
    """Send our public key to everyone (via the server)."""
    pubkey_msg = f"PUBKEY::{nickname}::{my_public_pem}"
    client.send(pubkey_msg.encode('utf-8'))

def receive():
    """Receive messages, decrypt them if possible, and print plaintext with nickname."""
    while True:
        try:
            data = client.recv(4096)
            if not data:
                break
            message = data.decode('utf-8')

            if message.startswith("PUBKEY::"):
                # Format: PUBKEY::<sender_nickname>::<public_key_pem>
                try:
                    _, sender, pubkey_pem = message.split("::", 2)
                    if sender not in public_keys:
                        other_pub = serialization.load_pem_public_key(pubkey_pem.encode('utf-8'))
                        public_keys[sender] = other_pub
                except:
                    pass
            elif message.endswith(" joined the chat!"):
                # New user joined
                print(message)
                # Send our key so they can encrypt messages for us
                broadcast_our_key()
            else:
                # Likely an encrypted JSON
                try:
                    decrypted = decrypt_hybrid(message, nickname, private_key)
                    print(decrypted)
                except:
                    # If no key is available for us, ignore
                    pass

        except Exception:
            client.close()
            break

def write():
    print("Type 'exit' to leave the chat.")
    """Continuously read user input, encrypt it, and send to the server."""
    # Immediately broadcast our key so others can encrypt for us
    broadcast_our_key()
    
    while True:
        msg = input()
        if msg.lower() == "exit":
            client.close()
            break
        
        # Embed the nickname into the plaintext
        plaintext = f"{nickname}: {msg}"
        
        # Encrypt the plaintext for all known participants
        encrypted_package = encrypt_hybrid(plaintext, public_keys)
        client.send(encrypted_package.encode('utf-8'))

# Start the receive/write threads
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
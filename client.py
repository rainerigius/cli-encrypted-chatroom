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
                encryption_algorithm=serialization.NoEncryption()))
        with open("public_key.pem", "wb") as f:
            f.write(public_key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo))
        return private_key, public_key

def encrypt_hybrid(plaintext, recipient_public_keys):
    """
    Encrypt the plaintext using a random symmetric key (Fernet),
    then encrypt that symmetric key with each recipient’s RSA public key.
    Returns a JSON string containing the encrypted message and the
    encrypted symmetric keys (one per recipient).
    """
    # Generate random symmetric key and encrypt the message
    symmetric_key = Fernet.generate_key()
    f = Fernet(symmetric_key)
    encrypted_message = f.encrypt(plaintext.encode('utf-8')).decode('utf-8')
    
    # Encrypt symmetric key for each recipient
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

# ----------------- Global Variables and Socket Setup -----------------

# Ask user for a nickname
nickname = input("Choose your nickname: ")

# Load or generate RSA keys for PGP-like encryption
private_key, public_key = load_or_generate_keys()
# Serialize our public key to send to others (as a PEM string)
my_public_pem = public_key.public_bytes(
    encoding=serialization.Encoding.PEM,
    format=serialization.PublicFormat.SubjectPublicKeyInfo
).decode('utf-8')

# Dictionary to store known public keys of all participants (including self)
public_keys = {nickname: public_key}

# Server address configuration
HOST = '127.0.0.1'  # Server's IP address
PORT = 12345        # Server's listening port

client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

# ----------------- Communication Functions -----------------

def receive():
    """Receive messages from the server and process control and chat messages."""
    while True:
        try:
            message = client.recv(4096).decode('utf-8')
            if not message:
                break

            # Handle control messages:
            if message == "NICK":
                # Send nickname to server
                client.send(nickname.encode('utf-8'))
                # After nickname, immediately send our public key to everyone
                pubkey_msg = f"PUBKEY::{nickname}::{my_public_pem}"
                client.send(pubkey_msg.encode('utf-8'))
            elif message.startswith("PUBKEY::"):
                # Format: PUBKEY::<sender_nickname>::<public_key_pem>
                try:
                    _, sender, pubkey_pem = message.split("::", 2)
                    if sender not in public_keys:
                        other_pub = serialization.load_pem_public_key(pubkey_pem.encode('utf-8'))
                        public_keys[sender] = other_pub
                        print(f"[Key Exchange] Received public key from {sender}.")
                    # Optionally, if you already joined, you could re-send your own pubkey here.
                except Exception as e:
                    print("Error processing public key message:", e)
            else:
                # Assume this is a chat message package (JSON string produced by encrypt_hybrid)
                # Even though decryption happens in the background, we print only the encrypted package.
                # (In a real secure chat, decryption would yield the plaintext, but here we hide it.)
                try:
                    # Uncomment the following line to see the decrypted message (for debugging):
                    # decrypted = decrypt_hybrid(message, nickname, private_key)
                    # print(f"[Decrypted] {decrypted}")
                    # Instead, show the encrypted package:
                    print(f"[Encrypted Message] {message}")
                except Exception as e:
                    print("Error decrypting message:", e)
        except Exception as e:
            print("An error occurred! Disconnected from server.", e)
            client.close()
            break

def write():
    """Read user input, encrypt it for all known participants, and send it."""
    print("Write 'exit' to exit the chatroom.\n")
    while True:
        msg = input("Input your message ('exit' to exit): ")
        if msg.lower() == "exit":
            client.close()
            break
        
        # Encrypt the plaintext message using the hybrid method.
        # (It will be encrypted for every participant whose public key we know.)
        encrypted_package = encrypt_hybrid(msg, public_keys)
        client.send(encrypted_package.encode('utf-8'))

# ----------------- Start Threads -----------------

receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()

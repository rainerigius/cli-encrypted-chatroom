# Secure single-room CLI Chat Hybrid Encryption


## Overview

This project is a simple chat application built with Python that uses a server-client architecture and hybrid encryption to secure messages. Each client loads or generates an RSA key pair (simulating a PGP key pair) and exchanges public keys with other participants. Messages are encrypted using a combination of symmetric encryption (Fernet) for the message content and RSA encryption for the symmetric key.

## Features

- **Hybrid Encryption:**  
  Each message is encrypted with a random symmetric key using Fernet. The symmetric key is then encrypted separately for each recipient using their RSA public key.

- **Public Key Exchange:**  
  Clients broadcast their public keys to enable secure message encryption among all participants.

- **Nickname Handshake:**  
  A unique nickname is required for each client. The server performs a handshake to ensure no duplicate nicknames exist.

- **Multi-Client Chat:**  
  The server accepts multiple clients and broadcasts messages to all connected clients (excluding the sender).

## File Structure

- **server.py**  
  Manages client connections, handles nickname handshakes, and broadcasts messages between clients.

- **client.py**  
  Handles RSA key management, encrypts/decrypts messages using hybrid encryption, and manages sending/receiving messages from the server.

## Requirements

- Python 3.6 or higher
- [cryptography](https://pypi.org/project/cryptography/) library

Install the required dependency with:

    pip install cryptography

## How It Works

1. **Key Management:**  
   Each client checks for existing RSA keys (`private_key.pem` and `public_key.pem`). If not found, it generates a new 2048-bit RSA key pair and saves them.

2. **Message Encryption:**  
   - A random symmetric key is generated using Fernet.
   - The message is encrypted with this symmetric key.
   - The symmetric key is encrypted for each recipient using their RSA public key.
   - Both the encrypted message and the encrypted symmetric keys are packaged into a JSON string.

3. **Message Decryption:**  
   - On receiving a message, a client uses its RSA private key to decrypt the symmetric key.
   - The decrypted symmetric key is then used to decrypt the actual message content.

## Usage

1. **Start the Server:**  
   Open a terminal and run:
   
       python server.py

2. **Start the Client:**  
   Open a separate terminal for each client and run:
   
       python client.py

3. **Chatting:**  
   - When prompted, enter a unique nickname.
   - Start typing messages. Your messages will be encrypted and sent to all connected clients.
   - Type `exit` to leave the chat.

## Security Considerations

- **Encryption Strength:**  
  RSA keys are generated with a key size of 2048 bits, and message encryption uses the robust Fernet mechanism.
  
- **Key Exchange:**  
  Public keys are exchanged openly among clients, but only the intended recipients can decrypt the symmetric key and hence the message.

- **Disclaimer:**  
  This project is for educational purposes. For production use, consider additional security measures, error handling, and performance optimizations.

## License

This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE.

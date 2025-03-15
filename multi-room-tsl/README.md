# Secure multi-room CLI Chat with TLS & Hybrid Encryption

This repository contains a secure chat system built with Python. It includes a TLS-enabled server and a client that communicate using hybrid encryption (symmetric encryption for messages with RSA-encrypted keys). The system also features user authentication, chat room management, and an encrypted database for storing user credentials.

## Features

- **TLS Secure Communication:**  
  The server wraps its socket with TLS using certificates generated via OpenSSL.

- **Encrypted Database:**  
  User data and chat room details are stored in an encrypted JSON file. Passwords are salted and hashed for security.

- **Hybrid Encryption for Messaging:**  
  Chat messages are encrypted using a symmetric key (Fernet), with the symmetric key itself encrypted using RSA public keys for each recipient.

- **Chat Room Management:**  
  Users can register, log in, create rooms (with passwords), join existing rooms, and list available rooms.

## Files Overview

- **server.py:**  
  Handles client connections, authentication, room management, encrypted database operations, and message broadcasting.

- **client.py:**  
  Manages RSA key generation, sending and receiving encrypted messages, and handling public keys for hybrid encryption.

- **sslcertgen.bat & sslcertgen.sh:**  
  Scripts for generating a self-signed TLS certificate. The OpenSSL command used is:  
  `openssl req -x509 -newkey rsa:2048 -nodes -keyout server.key -out server.crt -days 365`  
  This command creates a new RSA key pair and a self-signed certificate valid for 365 days.

## Setup and Installation

1. **Clone the Repository:**  
   Use your terminal or command prompt:  
   - `git clone <repository-url>`  
   - `cd <repository-directory>`

2. **Generate TLS Certificate:**  
   - On **Windows**: Run the `sslcertgen.bat` script.  
   - On **Linux/macOS**: Make `sslcertgen.sh` executable with `chmod +x sslcertgen.sh` and run it.  
   This generates `server.crt` and `server.key`, required by the server.

3. **Install Dependencies:**  
   Ensure Python 3 is installed, then run:  
   - `pip install cryptography`

## Running the Application

1. **Start the Server:**  
   - Execute `python server.py`  
   The server listens on `0.0.0.0:12345` with TLS enabled (using the generated certificate files).

2. **Start the Client:**  
   - Execute `python client.py`  
   **Note:** Update the `HOST` variable in `client.py` with your server's public IP or domain name before running the client.

## Usage

- **User Authentication:**  
  - Register: `/register <username> <password>`  
  - Log in: `/login <username> <password>`

- **Chat Room Commands:**  
  - Create a room: `/create <room> <password>`  
  - Join a room: `/join <room> <password>`  
  - List rooms: `/list`

- **Chatting:**  
  After logging in and joining a room, type your message and press Enter to send an encrypted chat message.

## Notes

- The server initializes a reserved "god" user by prompting for a password if no database exists.
- Client public keys are broadcasted to facilitate hybrid encryption.
- Ensure the TLS certificate files (`server.crt` and `server.key`) remain in the server’s directory.

## License

This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE.

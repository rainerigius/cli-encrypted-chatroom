# Secure multi-room CLI Chat with Hybrid Encryption

## Overview
This project implements a secure chat application in Python. It consists of two main components:

- **server.py**: Manages user registration and login, room creation and joining, encrypted database storage, and broadcasting of chat messages. It uses multi-threading to handle multiple clients concurrently and reserves the special "god" user for administrative control and moderation.
- **client.py**: Provides a command-line interface for users to interact with the server. It implements hybrid encryption using RSA and Fernet to secure chat messages, manages key exchange between users, and handles sending and receiving encrypted messages.

## Features
- **User Authentication**: Register and log in using a username and password. Passwords are secured with salting and SHA-256 hashing.
- **Room Management**: Create new chat rooms or join existing ones. Each room (except for the "god" user) is protected by a password.
- **Encrypted Communication**:
  - The server encrypts its database (storing user and room information) using Fernet symmetric encryption.
  - The client employs a hybrid encryption scheme: messages are encrypted using a symmetric key (Fernet) and the symmetric key is then encrypted for each recipient using RSA.
- **Public Key Exchange**: Clients exchange public keys to facilitate secure message encryption.
- **Multi-threaded Server**: The server handles multiple client connections simultaneously using threading.

## Installation

### Prerequisites
- Python 3.x
- The [cryptography](https://pypi.org/project/cryptography/) package

Install the required package using pip:
`pip install cryptography`

### Setup
1. Clone the repository:
   `git clone https://github.com/yourusername/secure-chat-application.git`
2. Change into the project directory:
   `cd secure-chat-application`

## Usage

### Running the Server
Start the server by executing:
`python server.py`

- The server listens on `127.0.0.1` at port `12345`.
- On the first run, you will be prompted to set a password for the reserved "god" user, which is intended for administrative control.

### Running the Client
Start the client by executing:
`python client.py`

Once running, you can use the following commands:
- **`/register <username> <password>`**: Create a new user account.
- **`/login <username> <password>`**: Log in with an existing account.
- **`/create <room> <password>`**: Create a new chat room.
- **`/join <room> <password>`**: Join an existing chat room (the "god" user can join without a room password).
- **`/list`**: List all available chat rooms.
- To send a chat message, simply type your message once you are logged in and have joined a room. Messages are automatically encrypted before being sent.

## Security Notes
- **Encryption**: The project uses RSA for public key encryption and Fernet for symmetric encryption. Make sure the `cryptography` package is kept up-to-date.
- **Database Security**: User and room data are stored in an encrypted file (`database.enc`), with the encryption key stored in `db_key.bin`. These files must be kept secure.
- **Admin User ("god")**: The "god" user is reserved for administrative purposes. Regular users should not attempt to create or use this account.

## Contributing
Contributions are welcome! Please fork the repository and submit a pull request with your improvements or bug fixes.

## License
This project is licensed under the GNU AFFERO GENERAL PUBLIC LICENSE.

## Acknowledgements
- Python’s built-in libraries for networking, threading, and data handling.
- The [cryptography](https://pypi.org/project/cryptography/) package for providing robust encryption functionality.

# Secure Multi-Chatroom with End-to-End Encryption

A Python-based multi-chatroom application that supports user registration/login, private messaging, chat history, and end-to-end encryption – both over the network and at rest in the server database.

This project demonstrates a complete chat system with:

- **User Registration & Login:** Securely register new users and log in with hashed passwords.
- **Multiple Chatrooms:** Create, join, and switch between chatrooms.
- **Private Messaging:** Send direct, private messages between users.
- **Chat History:** Retrieve the history of messages from any chatroom.
- **End-to-End Encryption:** Hybrid (PGP-like) encryption on the client side ensures that messages are encrypted before transmission, while the server additionally encrypts stored messages in its database.
- **Encrypted Database:** Uses SQLite with an extra layer of encryption to protect stored messages.

## Features

- **Registration & Login:** 
  - Commands: `/register <username> <password>` and `/login <username> <password>`
  - Passwords are hashed using bcrypt (via Passlib).

- **Multi-Chatroom Support:** 
  - Commands: `/join <roomname>`, `/leave <roomname>`, `/switch <roomname>`
  - Users can join multiple rooms and switch their active chatroom.

- **Private Messaging:** 
  - Command: `/pm <recipient> <message>`
  - Direct messaging between online users.

- **Chat History Retrieval:** 
  - Command: `/history <roomname>`
  - Retrieves the last 50 messages for a chatroom from the encrypted database.

- **End-to-End Encryption:** 
  - Hybrid encryption is used on the client side, where each message is first symmetrically encrypted and then the session key is encrypted for each recipient using RSA.
  - The server stores only the ciphertext – an additional layer of encryption secures the database content.

## Architecture

The system is composed of two main components:

- **Server (server.py):**  
  Handles registration, login, chatroom management, message routing, private messaging, and stores an encrypted history of chat messages in a SQLite database.

- **Client (client.py):**  
  Provides a command-line interface for users. It handles key generation, public key exchange, end-to-end encryption/decryption of messages, and user commands to interact with the server.

### End-to-End Message Flow

1. **Client Side:**  
   - On startup, the client generates (or loads) an RSA key pair.
   - When sending a message, the client uses a hybrid encryption scheme:
     - A random symmetric key is generated.
     - The message is encrypted using this key (via Fernet).
     - The symmetric key is then encrypted with each recipient’s RSA public key.
   - The resulting JSON package is sent to the server.

2. **Server Side:**  
   - The server receives the encrypted JSON package and routes it to the appropriate chatroom members.
   - Before storing the message in the database, the server encrypts the content with a server-only key (using Fernet).

3. **Decryption:**  
   - Upon receipt, each client uses its RSA private key to decrypt the symmetric key and then uses that key to decrypt the message.
   - The process is entirely transparent to the user.

## Packet Diagram

Below is a quoted excerpt from the PacketDiagram.md file, which outlines the packet structure and flow for our protocol:

> **Packet Diagram from PacketDiagram.md:**
> 
>     [Client] ---(register/login)---> [Server]
>     [Client] <--(registration/login response)-- [Server]
>     
>     [Client] ---(join room command)---> [Server]
>     [Server] ---(confirmation and room update notification)---> [Client]
>     
>     [Client] ---(encrypted message packet)--->
>           [Hybrid Encryption]
>             • Generate random symmetric key
>             • Encrypt message with symmetric key
>             • Encrypt symmetric key for each recipient using RSA
>     [Server] receives JSON packet:
>       {
>         "encrypted_message": "<Fernet-encrypted message>",
>         "encrypted_keys": {
>             "user1": "<RSA encrypted symmetric key for user1>",
>             "user2": "<RSA encrypted symmetric key for user2>",
>             ...
>         }
>       }
>     [Server] ---(broadcast to room members)---> [Clients]
>     
>     [Client] receives packet and decrypts:
>       • Use RSA private key to decrypt symmetric key
>       • Use symmetric key to decrypt message
>     
>     Additional commands (e.g., /pm, /history) follow a similar structured packet format.

## Installation

### Prerequisites

- Python 3.6 or higher
- [pip](https://pip.pypa.io/en/stable/)

### Dependencies

Install the required Python packages using pip: `pip install cryptography passlib`

### Database Setup

The server uses SQLite for storing user data, memberships, and messages. The database is automatically initialized when you first run the server.

## Usage

### Running the Server

Start the server with: `python server.py`

The server will listen on `127.0.0.1:12345`.

### Running the Client

Start the client with: `python client.py`

The client will display available commands. Example commands include:

- **Register:** `/register alice secretpassword`
- **Login:** `/login alice secretpassword`
- **Join a Chatroom:** `/join general`
- **Switch Chatroom:** `/switch general`
- **Send a Message to the Active Room:** `/send Hello everyone!`
- **Private Message:** `/pm bob Hey Bob, how are you?`
- **Retrieve Chat History:** `/history general`
- **Exit:** `/exit`

## Contributing

Contributions, bug reports, and feature requests are welcome. Feel free to fork the repository and submit pull requests.

## License

This project is licensed under the MIT License. See the LICENSE file for details.

---

*This README includes quoted content from the PacketDiagram.md file to provide insight into the packet structures used within this secure messaging protocol.*

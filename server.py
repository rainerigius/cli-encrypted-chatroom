import socket
import threading

# Server configuration
HOST = '127.0.0.1'  # Localhost
PORT = 12345        # Arbitrary non-privileged port

clients = []
nicknames = []

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

def broadcast(message, sender_client):
    """Send message to all connected clients except the sender."""
    for client in clients:
        if client != sender_client:
            try:
                client.send(message)
            except:
                client.close()
                remove_client(client)

def remove_client(client):
    if client in clients:
        index = clients.index(client)
        nickname = nicknames[index]
        clients.remove(client)
        nicknames.remove(nickname)
        broadcast(f"{nickname} left the chat.".encode('utf-8'), client)
        print(f"{nickname} disconnected.")

def handle_client(client):
    """Handle communication with a client."""
    while True:
        try:
            # Increase buffer size to support larger (JSON) messages.
            message = client.recv(4096)
            if not message:
                break
            broadcast(message, client)
        except:
            remove_client(client)
            break

def receive():
    """Accept new client connections."""
    print(f"Server is running on {HOST}:{PORT}")
    while True:
        client, address = server.accept()
        print(f"Connected with {address}")

        # Request and store nickname
        client.send("NICK".encode('utf-8'))
        nickname = client.recv(4096).decode('utf-8')
        nicknames.append(nickname)
        clients.append(client)

        print(f"Nickname of the client is {nickname}")
        broadcast(f"{nickname} joined the chat!".encode('utf-8'), client)
        
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == '__main__':
    receive()

import socket
import threading

HOST = '127.0.0.1'
PORT = 12345

server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server.bind((HOST, PORT))
server.listen()

clients = []
nicknames = []

def broadcast(message, sender_client):
    """Send a message to all connected clients except the sender."""
    for client in clients:
        if client != sender_client:
            try:
                client.send(message)
            except:
                remove_client(client)

def remove_client(client):
    """Remove a client from the lists, notify others."""
    if client in clients:
        index = clients.index(client)
        nickname = nicknames[index]
        clients.remove(client)
        nicknames.remove(nickname)
        broadcast(f"{nickname} left the chat.".encode('utf-8'), client)
        print(f"{nickname} disconnected.")

def handle_client(client):
    """Handle communication with a single connected client."""
    while True:
        try:
            message = client.recv(4096)
            if not message:
                break
            broadcast(message, client)
        except:
            remove_client(client)
            break

def handshake(client):
    """
    Perform the nickname handshake with a newly connected client.
    Returns the nickname if successful, or None if the nickname is taken.
    """
    # Request nickname
    client.send("NICK".encode('utf-8'))
    nickname = client.recv(4096).decode('utf-8')
    
    # Check if nickname is already taken
    if nickname in nicknames:
        client.send("NICKTAKEN".encode('utf-8'))
        return None  # The caller will close the connection
    else:
        client.send("NICKACCEPT".encode('utf-8'))
        return nickname

def receive():
    """Accept new client connections and start a thread for each one."""
    print(f"Server is running on {HOST}:{PORT}")
    while True:
        client, address = server.accept()
        print(f"Connection from {address}")
        
        nickname = handshake(client)
        if not nickname:
            # Nickname was taken; close and wait for another client
            client.close()
            continue
        
        # Add new client to our lists
        nicknames.append(nickname)
        clients.append(client)
        
        print(f"Nickname of the client is {nickname}")
        broadcast(f"{nickname} joined the chat!".encode('utf-8'), client)
        
        # Start a thread to handle this client's messages
        thread = threading.Thread(target=handle_client, args=(client,))
        thread.start()

if __name__ == '__main__':
    receive()

import socket
import threading

# Ask user for a nickname
nickname = input("Choose your nickname: ")

# Server address configuration
HOST = '127.0.0.1'  # Server's IP address
PORT = 12345        # Server's listening port

# Create a TCP socket and connect to the server
client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
client.connect((HOST, PORT))

def receive():
    """Receive messages from the server."""
    while True:
        try:
            message = client.recv(1024).decode('utf-8')
            if message == "NICK":
                client.send(nickname.encode('utf-8'))
            else:
                print(message)
        except Exception as e:
            print("An error occurred! Disconnected from server.")
            client.close()
            break

def write():
    """Send messages to the server."""
    print("Write 'exit' to exit the chatroom.\n")
    while True:
        # Prompt the user for a message
        msg = input()
        if msg.lower() == "exit":
            client.close()
            break
        message = f"{nickname}: {msg}"
        client.send(message.encode('utf-8'))

# Start threads for receiving and sending messages
receive_thread = threading.Thread(target=receive)
receive_thread.start()

write_thread = threading.Thread(target=write)
write_thread.start()
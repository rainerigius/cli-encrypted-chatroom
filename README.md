# CLI Chatroom

CLI Chatroom is a collection of command-line based chatroom applications in Python that offer different modes of operation. It includes three implementations:

- **Single-Room Chatroom:** A simple, single chatroom implementation.
- **Multi-Room Chatroom (No TLS):** Supports multiple chatrooms without encryption.
- **Multi-Room Chatroom (TLS):** Supports multiple chatrooms with TLS encryption for secure communications.

Each version is self-contained within its own directory and includes its respective server and client scripts, a packet diagram (`PacketDiagram.md`) explaining the communication protocol, and an additional README for detailed usage instructions.

## Repository Structure

cli-chatroom/
├── LICENSE
├── README.md           # Main README file
├── single-room/
│   ├── client.py
│   ├── server.py
│   ├── PacketDiagram.md
│   └── README.md
├── multi-room-no-tsl/
│   ├── client.py
│   ├── server.py
│   ├── PacketDiagram.md
│   └── README.md
└── multi-room-tsl/
    ├── client.py
    ├── server.py
    ├── PacketDiagram.md
    ├── README.md
    ├── sslcertgen.sh    # Shell script for generating SSL certificates (Linux/Mac)
    └── sslcertgen.bat   # Batch script for generating SSL certificates (Windows)

## Getting Started

### Prerequisites

- **Python 3.x**: Ensure Python is installed on your system.
- **OpenSSL**: Required for generating certificates when using the TLS version.

### How to Run

#### Single-Room Chatroom

1. Open a terminal and navigate to the `single-room` directory.
2. Start the server:
   - Run: `python server.py`
3. In another terminal, start the client:
   - Run: `python client.py`
4. Follow the on-screen prompts to join the chat.

#### Multi-Room Chatroom (No TLS)

1. Open a terminal and navigate to the `multi-room-no-tsl` directory.
2. Start the server:
   - Run: `python server.py`
3. In separate terminals, start one or more clients:
   - Run: `python client.py`
4. This version supports multiple chatrooms; check the included README for details.

#### Multi-Room Chatroom (TLS)

1. Open a terminal and navigate to the `multi-room-tsl` directory.
2. **Generate SSL Certificates:**
   - For Unix/Linux/Mac: Run `bash sslcertgen.sh`
   - For Windows: Run `sslcertgen.bat`
3. Start the server:
   - Run: `python server.py`
4. In another terminal, start the client:
   - Run: `python client.py`
5. The connection will be secured using TLS. Refer to the included README for more in-depth instructions.

## Packet Diagram

Each implementation contains a `PacketDiagram.md` file, which describes the structure of the data packets used in the communication protocol.

## Contributing

Contributions, bug fixes, and feature enhancements are welcome. Feel free to fork the repository and submit a pull request with your improvements.

## License

This project is licensed under the terms specified in the [LICENSE](LICENSE) file.

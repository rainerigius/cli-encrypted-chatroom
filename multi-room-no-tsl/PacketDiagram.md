# Full Packet Diagram: Registration, Login, Room Creation, Room Joining & Message Sending

                 ┌─────────────────────────────────────┐
                 │           [CLIENT A]              │
                 │       (User: e.g., Alice)           │
                 └─────────────────────────────────────┘
                              │
       ┌──────────────────────┼─────────────────────────────┐
       │                      │                             │
       ▼                      ▼                             ▼
─────────────────────────────────────────────────────────────────────────────
**1. Registration Process**
─────────────────────────────────────────────────────────────────────────────
CLIENT A:
   • User inputs: `/register Alice secret123`
   • Sends: `CMD::/register Alice secret123`
                              │
                              ▼
SERVER:
   • Receives registration command
   • Checks if "Alice" exists in the encrypted DB
   • Creates user with salted & hashed password if new
   • Updates & encrypts the database (database.enc)
   • Sends response: "Registration successful for Alice." (or error)
                              │
                              ▼
CLIENT A:
   • Receives registration response
─────────────────────────────────────────────────────────────────────────────

       ▼
─────────────────────────────────────────────────────────────────────────────
**2. Login Process**
─────────────────────────────────────────────────────────────────────────────
CLIENT A:
   • User inputs: `/login Alice secret123`
   • Sends: `CMD::/login Alice secret123`
                              │
                              ▼
SERVER:
   • Validates credentials (checks hash with stored salt)
   • Updates session info: sets username "Alice", logged_in = True
   • Sends response: "Login successful. Welcome, Alice!"
                              │
                              ▼
CLIENT A:
   • Receives login confirmation
─────────────────────────────────────────────────────────────────────────────

       ▼
─────────────────────────────────────────────────────────────────────────────
**3. Room Creation Process**
─────────────────────────────────────────────────────────────────────────────
CLIENT A:
   • User inputs: `/create RoomX roomPass`
   • Sends: `CMD::/create RoomX roomPass`
                              │
                              ▼
SERVER:
   • Validates if RoomX already exists
   • Creates room with specified password and updates DB
   • Sends response: "Room 'RoomX' created." (or error)
                              │
                              ▼
CLIENT A:
   • Receives room creation response
─────────────────────────────────────────────────────────────────────────────

       ▼
─────────────────────────────────────────────────────────────────────────────
**4. Room Joining Process**
─────────────────────────────────────────────────────────────────────────────
CLIENT A:
   • User inputs: `/join RoomX roomPass`
   • Sends: `CMD::/join RoomX roomPass`
                              │
                              ▼
SERVER:
   • Checks if RoomX exists and validates room password
   • Updates client session to set current room to "RoomX"
   • Broadcasts (to RoomX clients) that "Alice joined the chat!" 
   • Sends confirmation to CLIENT A
                              │
                              ▼
CLIENT A:
   • Receives confirmation (and sees join notification if in other clients)
─────────────────────────────────────────────────────────────────────────────

       ▼
─────────────────────────────────────────────────────────────────────────────
**5. Message Sending Process (in a room)**
─────────────────────────────────────────────────────────────────────────────
CLIENT A:
   • User types a chat message, e.g.: "Alice: Hello RoomX!"
   • Encryption Steps:
       1. Generate a random symmetric (Fernet) key.
       2. Encrypt the plaintext message with this symmetric key 
          → produces "encrypted_message".
       3. For each recipient in RoomX (including self), encrypt the symmetric key 
          using the recipient's RSA public key 
          → produces an "encrypted_key" for each.
       4. Build a JSON packet including:
            {
              "room": "RoomX",
              "encrypted_message": "...",
              "encrypted_keys": {
                   "Bob": "...",
                   "Charlie": "..."
              }
            }
   • Sends the encrypted JSON packet to the SERVER.
                              │
                              ▼
SERVER:
   • Receives the JSON packet.
   • Verifies that the packet's "room" field matches the sender’s joined room.
   • Broadcasts the encrypted packet to all connected clients in RoomX (excluding sender, if desired).
                              │
                              ▼
CLIENTS in RoomX (e.g., Bob, Charlie):
   • Receive the encrypted JSON packet.
   • For each:
         - Extract "encrypted_keys" entry for their nickname.
         - Use RSA private key to decrypt the corresponding symmetric key.
         - Decrypt "encrypted_message" using the recovered symmetric key.
         - Display the plaintext message ("Alice: Hello RoomX!")
─────────────────────────────────────────────────────────────────────────────

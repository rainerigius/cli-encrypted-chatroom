# Packet Diagram

                           [CLIENT A (Sender)]
                           (NicknameA)
                                  │
       (User types: "NicknameA: Hello everyone!")
                                  │
                                  ▼
          ┌────────────────────────────────────┐
          │ Generate random symmetric key      │
          │ (Fernet key)                       │
          └────────────────────────────────────┘
                                  │
                                  ▼
          ┌────────────────────────────────────┐
          │ Encrypt plaintext with symmetric   │
          │ key → produces "encrypted_message" │
          └────────────────────────────────────┘
                                  │
                                  ▼
          ┌──────────────────────────────────────┐
          │ For each recipient:                  │
          │   Encrypt symmetric key using        │
          │   recipient's RSA public key         │
          │   → produces "encrypted_key" for each│
          └──────────────────────────────────────┘
                                  │
                                  ▼
          ┌────────────────────────────────────┐
          │ Build JSON Packet:                 │
          │ {                                  │
          │    "encrypted_message": "...",     │
          │    "encrypted_keys": {             │
          │         "UserB": "...",            │
          │         "UserC": "..."             │
          │    }                               │
          │ }  (All data encrypted)            │
          └────────────────────────────────────┘
                                  │
                                  │  (Encrypted JSON Packet sent over network)
                                  ▼
                           [SERVER]
         (Relays the encrypted packet unchanged)
                                  │
                                  │ (Encrypted JSON Packet forwarded)
                                  ▼
                           [CLIENT B (Receiver)]
                           (NicknameB)
                                  │
                ┌────────────────────────────────────┐
                │ Extract from JSON:                 │
                │   - "encrypted_message"            │
                │   - "encrypted_keys" (with key for │
                │      NicknameB)                    │
                └────────────────────────────────────┘
                                  │
                                  ▼
                ┌────────────────────────────────────┐
                │ Decrypt NicknameB's "encrypted_key"│
                │ using its RSA private key          │
                │ → recovers symmetric key           │
                └────────────────────────────────────┘
                                  │
                                  ▼
                ┌────────────────────────────────────┐
                │ Decrypt "encrypted_message" using  │
                │ the recovered symmetric key        │
                │ → yields plaintext:                │
                │ "NicknameA: Hello everyone!"       │
                └────────────────────────────────────┘
                                  │
                                  ▼
                         Display plaintext message:
                      "NicknameA: Hello everyone!"

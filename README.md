# Encrypted Files Transfer System

A client‑server system for securely transferring files with end-to-end encryption.  
The server and client communicate over a custom binary TCP protocol. The server stores only encrypted data; decryption happens at the client side.

---

## Table of Contents

- [Overview](#overview)  
- [Architecture & Flow](#architecture--flow)  
- [Protocol & Packet Structure](#protocol--packet-structure)  
- [Storage & DB](#storage--db)  
- [Supported Operations](#supported-operations)  
- [Setup & Running](#setup--running)  
- [Security Considerations](#security-considerations)  
- [Project Structure](#project-structure)  
- [Contact](#contact)

---

## Overview

This system enables:

- Encrypted upload, download, listing of files between clients  
- Server never has access to plaintext data  
- Integrity & authenticity checks using digital signatures  
- Reliable transfer even when recipient is offline (server queues encrypted files)  

---

## Architecture & Flow

1. **Client connects to server** over TCP socket.
2. **Key exchange / registration**:
   - Client sends public key or identification.
   - Server registers the client if new.
3. **File upload / transfer**:
   - Client encrypts file (or file chunks) with a symmetric cipher (e.g. AES).
   - Each chunk or packet is signed / hashed to ensure integrity.
   - Encrypted packets are sent to server, which stores them.
4. **File download / fetch**:
   - Recipient requests pending files.
   - Server sends encrypted packets.
   - Recipient verifies signatures, decrypts, reassembles file.

---

## Protocol & Packet Structure

Packets follow a binary format (Little Endian).  
Each packet typically includes:

- `sender_id`  
- `recipient_id`  
- `operation_code`  
- `file_id` / `chunk_index`  
- `payload_length`  
- `encrypted_payload`  
- `signature` (digital signature or HMAC over header + payload)

Operation codes differentiate commands like upload, download request, list files, etc.

---

## Storage & DB

The server uses persistent storage (e.g. SQLite or file system) for:

- Registered users + their public keys  
- Metadata about pending file transfers  
- Encrypted file chunks stored on disk or blob storage  

The server does **not** store or handle plaintext versions of files.

---

## Supported Operations

- **REGISTER / LOGIN** — client identifies or registers with public key  
- **SEND_FILE** — client uploads encrypted file data  
- **LIST_FILES** — client queries files awaiting delivery  
- **DOWNLOAD_FILE** — client fetches encrypted data  
- **ACK / COMPLETE** — client confirms successful download  
- **ERROR / REJECT** — error responses for invalid operations  

---

## Setup & Running

1. Clone the repo:
   ```bash
   git clone https://github.com/LiavSeg/Encrypted-files-transfer-System.git

2. Install dependencies (for Python parts):
   ```bash
    cd <Server or Client folder>
    pip install -r requirements.txt
3. Run server:
   ```bash
    python server.py

4. On client side, run client application:
   ```bash
    python client.py
5. Make sure firewall or network settings allow communication over the TCP port used.

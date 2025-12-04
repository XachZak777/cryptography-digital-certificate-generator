# Certificate Authority and Secure Client-Server System

A professional implementation of a Public Key Infrastructure (PKI) system with custom cryptographic primitives. This project demonstrates:

- **Certificate Authority (CA)**: Generates and signs digital certificates
- **Secure Server**: Provides certificates and establishes encrypted communication
- **Secure Client**: Authenticates server and communicates via encrypted channel

## Features

### Custom Cryptographic Implementations

All core cryptographic operations are implemented from scratch for educational purposes:

1. **AES (Advanced Encryption Standard)**
   - Full AES-128/192/256 implementation
   - SubBytes, ShiftRows, MixColumns, AddRoundKey transformations
   - Key expansion algorithm
   - CBC (Cipher Block Chaining) mode

2. **RSA Cryptosystem**
   - Key generation using Miller-Rabin primality test
   - RSA encryption/decryption
   - RSA-OAEP padding for secure encryption

3. **PKCS#7 Padding**
   - Block cipher padding implementation
   - Padding and unpadding operations

4. **Simplified X.509 Certificates**
   - Certificate creation and signing
   - Certificate verification
   - Serialization/deserialization

## Architecture

### Certificate Authority (`ca.py`)

The CA is responsible for:
- Generating its own RSA key pair (2048-bit)
- Creating a self-signed root certificate
- Generating and signing server certificates
- Maintaining the root of trust

### Secure Server (`server.py`)

The server implements:
- Certificate presentation to clients
- Session key decryption (RSA-OAEP)
- AES-CBC encrypted communication
- Secure message exchange

### Secure Client (`client.py`)

The client implements:
- Certificate verification using CA certificate
- Session key generation and encryption
- AES-CBC encrypted communication
- Secure message exchange

## Protocol Flow

1. **CA Setup**
   ```
   CA generates key pair → Creates self-signed certificate → Saves to files
   ```

2. **Server Certificate Generation**
   ```
   CA generates server key pair → Creates certificate → Signs with CA key → Saves to files
   ```

3. **Client-Server Handshake**
   ```
   Client connects → Server sends certificate → Client verifies certificate →
   Client generates session key → Client encrypts session key with server's public key →
   Server decrypts session key → Secure channel established
   ```

4. **Secure Communication**
   ```
   Messages encrypted with AES-CBC using session key →
   Each message includes random IV → PKCS#7 padding applied
   ```

## Installation

### Requirements

- Python 3.8 or higher
- Standard library only (no external dependencies for cryptographic operations)

### Setup

1. Clone or download this repository

2. No additional packages required! All cryptographic operations are implemented from scratch.

3. The `certificates/` directory will be created automatically when you generate certificates.

## Usage

### Method 1: CLI Menu (Recommended)

The easiest way to use the system through the command-line interface:

```bash
python main.py
```

Or:

```bash
python cli/main_menu.py
```

This launches an interactive CLI menu where you can:
- Generate Certificate Authority
- Generate server certificates
- Start the secure server
- Connect secure clients
- View system status
- Access help and documentation

### Method 2: Terminal Commands (Direct Usage)

This method uses separate terminal windows for the server and client, giving you full control over the connection process.

#### Step 1: Generate CA and Server Certificate

First, generate the Certificate Authority and server certificate:

```bash
python ca.py
```

This will:
- Generate CA private key (`certificates/ca_private_key.pem`)
- Generate CA certificate (`certificates/ca_certificate.pem`)
- Generate server private key (`certificates/localhost_key.pem`)
- Generate server certificate (`certificates/localhost_cert.pem`)

**Note**: Key generation may take 1-3 minutes as it involves generating large prime numbers.

#### Step 2: Start the Server (Terminal 1)

Open your first terminal and start the server:

```bash
python server.py
```

The server will:
- Load its certificate and private key
- Listen on `localhost:8443` (default)
- Display: "Server listening on localhost:8443"
- Wait for client connections
- Keep running until you press `Ctrl+C`

**Example output:**
```
Server certificates loaded successfully
Server listening on localhost:8443
Waiting for client connection...
```

#### Step 3: Connect with Client (Terminal 2)

Open a **second terminal** (keep the server running in Terminal 1) and connect the client:

```bash
python client.py
```

The client will:
- Load the CA certificate
- Connect to the server at `localhost:8443`
- Verify the server's certificate
- Generate and send an encrypted session key
- Establish secure communication
- Allow interactive messaging

**Example output:**
```
CA certificate loaded
Connected to server at localhost:8443
✓ Server certificate verified successfully!
Generated session key: 32 bytes
Encrypted session key sent to server
Server: Session key received. Secure communication established!

Secure communication established! Type messages (or 'exit' to quit):
You: 
```

#### Step 4: Exchange Messages

Once connected, you can:
- Type messages in the client terminal
- See encrypted responses from the server
- Type `exit` to disconnect

**Example session:**
```
You: Hello, secure world!
Server: Server received: Hello, secure world!
You: This is encrypted with AES-CBC
Server: Server received: This is encrypted with AES-CBC
You: exit
Disconnected from server
```

#### Stopping the Server

To stop the server, go back to Terminal 1 and press `Ctrl+C`.

### Example Session

```
$ python client.py
CA certificate loaded
Connected to server at localhost:8443
✓ Server certificate verified successfully!
Generated session key: 32 bytes
Encrypted session key sent to server
Server: Session key received. Secure communication established!

Secure communication established! Type messages (or 'exit' to quit):
You: Hello, secure world!
Server: Server received: Hello, secure world!
You: exit
Disconnected from server
```

## File Structure

```
.
├── main.py                # Main entry point (launches interactive menu)
├── ca.py                  # Certificate Authority implementation
├── server.py              # Secure server implementation
├── client.py              # Secure client implementation
├── certificates/          # Certificate and key files (auto-created)
│   ├── ca_private_key.pem
│   ├── ca_certificate.pem
│   ├── localhost_key.pem
│   └── localhost_cert.pem
├── crypto/                # Cryptographic implementations
│   ├── __init__.py
│   ├── aes.py             # AES block cipher implementation
│   ├── rsa_crypto.py      # RSA cryptosystem implementation
│   ├── pkcs7.py           # PKCS#7 padding implementation
│   ├── simple_certificate.py  # Simplified X.509 certificate
│   └── key_serialization.py   # RSA key serialization (PEM)
├── cli/                   # Command-line interface
│   └── main_menu.py       # Interactive CLI menu system
├── README.md              # This file
├── USAGE_GUIDE.md         # Detailed usage instructions
└── requirements.txt       # Dependencies (none needed!)
```

## Cryptographic Details

### AES Implementation

- **Block Size**: 128 bits (16 bytes)
- **Key Sizes**: 128, 192, or 256 bits
- **Mode**: CBC (Cipher Block Chaining)
- **Padding**: PKCS#7
- **IV**: Random 16-byte IV per message

### RSA Implementation

- **Key Size**: 2048 bits
- **Public Exponent**: 65537
- **Primality Test**: Miller-Rabin (40 iterations)
- **Padding**: OAEP (Optimal Asymmetric Encryption Padding)
- **Key Format**: PEM (Privacy-Enhanced Mail)

### Certificate Structure

- **Format**: Simplified X.509-like structure
- **Signature**: RSA signature over SHA-256 hash
- **Validity**: Configurable (CA: 10 years, Server: 1 year)
- **Serialization**: Base64-encoded JSON

## Security Considerations

This implementation is designed for **educational purposes**. For production use:

1. **Use established cryptographic libraries** (e.g., `cryptography` package)
2. **Implement proper error handling** and side-channel attack prevention
3. **Use secure random number generators** (os.urandom is acceptable)
4. **Implement certificate revocation** mechanisms
5. **Add proper authentication** beyond certificate verification
6. **Use authenticated encryption** (e.g., AES-GCM instead of AES-CBC)
7. **Implement proper key management** and storage

## Educational Value

This project demonstrates:

- **Symmetric Cryptography**: AES block cipher operations
- **Asymmetric Cryptography**: RSA key generation and encryption
- **Public Key Infrastructure**: Certificate creation and verification
- **Secure Communication Protocols**: Handshake and encrypted messaging
- **Cryptographic Primitives**: Padding, hashing, key derivation

## Testing

To test the system using the terminal:

**Terminal 1 - Start the server:**
```bash
# First, generate certificates if needed
python ca.py

# Then start the server
python server.py
```

**Terminal 2 - Connect the client:**
```bash
python client.py
```

You can then exchange messages and verify encryption. Type `exit` to quit the client.

## Troubleshooting

### Key Generation Takes Too Long

- This is normal for 2048-bit RSA keys
- Prime generation involves probabilistic testing
- Be patient (typically 1-3 minutes)

### Certificate Verification Fails

- Ensure CA certificate exists: `ca_certificate.pem`
- Check that server certificate was signed by CA
- Verify certificate validity period

### Connection Refused

- Ensure server is running before starting client
- Check that port 8443 is not in use
- Verify host/port configuration

## License

This project is provided for educational purposes.

## Author

Capstone Project - Certificate Authority and Secure Communication System

"""
Secure Client Implementation
Authenticates server, generates session key, and communicates via AES.

This client:
1. Connects to the server
2. Receives and verifies the server's certificate
3. Generates a session key and encrypts it with the server's public key
4. Communicates with the server using AES-CBC encryption
"""
import socket
import json
import base64
import os
from typing import Optional
from crypto import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    pkcs7_pad,
    pkcs7_unpad,
    rsa_oaep_encrypt,
    SimpleCertificate
)


class SecureClient:
    """
    Secure client that verifies server certificate and uses AES for communication.
    
    The client follows this protocol:
    1. Connect to server
    2. Receive and verify server's certificate
    3. Generate session key and encrypt it with server's public key
    4. Establish encrypted communication channel using AES-CBC
    """
    
    def __init__(
        self,
        host: str = 'localhost',
        port: int = 8443,
        ca_cert_path: str = 'certificates/ca_certificate.pem'
    ):
        """
        Initialize secure client.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            ca_cert_path: Path to CA certificate file
        """
        self.host = host
        self.port = port
        self.ca_cert_path = ca_cert_path
        self.ca_certificate: Optional[SimpleCertificate] = None
        self.server_certificate: Optional[SimpleCertificate] = None
        self.server_public_key: Optional[tuple] = None
        self.session_key: Optional[bytes] = None
        
    def load_ca_certificate(self) -> None:
        """
        Load CA certificate for verification.
        
        Raises:
            FileNotFoundError: If CA certificate file doesn't exist
        """
        if not os.path.exists(self.ca_cert_path):
            raise FileNotFoundError(
                "CA certificate not found. Please generate it first using ca.py"
            )
        
        with open(self.ca_cert_path, "rb") as f:
            cert_data = f.read()
            try:
                cert_str = cert_data.decode('utf-8').strip()
                if cert_str.startswith('-----'):
                    # PEM-like format, extract base64 part
                    lines = [l for l in cert_str.split('\n') if l and not l.startswith('-----')]
                    cert_str = ''.join(lines)
                self.ca_certificate = SimpleCertificate.deserialize(cert_str)
            except Exception as e:
                raise ValueError(f"Failed to load CA certificate: {e}")
        
        print("CA certificate loaded")
    
    def receive_and_verify_certificate(self, server_socket: socket.socket) -> bool:
        """
        Receive server certificate and verify it using CA certificate.
        
        Verification process:
        1. Deserialize certificate from server
        2. Verify signature using CA's public key
        3. Check certificate validity period
        4. Extract server's public key
        
        Args:
            server_socket: Connected server socket
        
        Returns:
            True if certificate is valid, False otherwise
        """
        try:
            data = self._receive_complete_message(server_socket)
            message = json.loads(data)
        except (json.JSONDecodeError, ConnectionError) as e:
            print(f"Error receiving certificate: {e}")
            return False
        
        if message['type'] != 'certificate':
            raise ValueError("Expected certificate message")
        
        # Deserialize certificate
        cert_data = message['certificate']
        self.server_certificate = SimpleCertificate.deserialize(cert_data)
        
        # Verify certificate
        try:
            if self.ca_certificate is None:
                raise ValueError("CA certificate not loaded")
            
            # Verify signature using CA's public key
            if not self.server_certificate.verify(self.ca_certificate.public_key):
                raise ValueError("Certificate signature verification failed")
            
            # Verify validity period
            if not self.server_certificate.is_valid():
                raise ValueError("Certificate is not valid (expired or not yet valid)")
            
            print("✓ Server certificate verified successfully!")
            
            # Extract server's public key
            self.server_public_key = self.server_certificate.public_key
            
            return True
        except Exception as e:
            print(f"✗ Certificate verification failed: {e}")
            return False
    
    def generate_and_send_session_key(self, server_socket: socket.socket) -> None:
        """
        Generate session key, encrypt it with server's public key, and send it.
        
        The session key is a 32-byte (256-bit) random value used for AES-256 encryption.
        It is encrypted using RSA-OAEP with the server's public key.
        
        Args:
            server_socket: Connected server socket
        
        Raises:
            ValueError: If server public key is not available
        """
        if self.server_public_key is None:
            raise ValueError("Server public key not available")
        
        # Generate 256-bit (32-byte) AES session key
        self.session_key = os.urandom(32)
        print(f"Generated session key: {len(self.session_key)} bytes")
        
        # Encrypt session key with server's public key using RSA-OAEP
        encrypted_key = rsa_oaep_encrypt(self.session_key, self.server_public_key)
        
        # Encode to base64
        encrypted_key_b64 = base64.b64encode(encrypted_key).decode('utf-8')
        
        # Send to server
        message = {
            'type': 'session_key',
            'encrypted_session_key': encrypted_key_b64
        }
        
        server_socket.send(json.dumps(message).encode('utf-8') + b'\n')
        print("Encrypted session key sent to server")
    
    def encrypt_message(self, message: str) -> str:
        """
        Encrypt message using AES-CBC with the session key.
        
        Process:
        1. Convert message to bytes
        2. Apply PKCS7 padding
        3. Generate random IV
        4. Encrypt using AES-CBC
        5. Return IV + ciphertext as base64
        
        Args:
            message: Plaintext message to encrypt
        
        Returns:
            Base64-encoded IV + ciphertext
        
        Raises:
            ValueError: If session key is not set
        """
        if self.session_key is None:
            raise ValueError("Session key not set")
        
        # Convert message to bytes
        message_bytes = message.encode('utf-8')
        
        # Apply PKCS7 padding
        padded_data = pkcs7_pad(message_bytes, block_size=16)
        
        # Generate random IV (16 bytes for AES)
        iv = os.urandom(16)
        
        # Encrypt using AES-CBC
        ciphertext = aes_cbc_encrypt(padded_data, self.session_key, iv)
        
        # Return IV + ciphertext as base64
        return base64.b64encode(iv + ciphertext).decode('utf-8')
    
    def decrypt_message(self, encrypted_message: str) -> str:
        """
        Decrypt message using AES-CBC with the session key.
        
        Process:
        1. Decode from base64
        2. Extract IV and ciphertext
        3. Decrypt using AES-CBC
        4. Remove PKCS7 padding
        5. Return plaintext
        
        Args:
            encrypted_message: Base64-encoded IV + ciphertext
        
        Returns:
            Decrypted plaintext message
        
        Raises:
            ValueError: If session key is not set or decryption fails
        """
        if self.session_key is None:
            raise ValueError("Session key not set")
        
        # Decode from base64
        data = base64.b64decode(encrypted_message)
        
        # Extract IV and ciphertext
        iv = data[:16]
        ciphertext = data[16:]
        
        # Decrypt using AES-CBC
        padded_plaintext = aes_cbc_decrypt(ciphertext, self.session_key, iv)
        
        # Remove PKCS7 padding
        plaintext = pkcs7_unpad(padded_plaintext, block_size=16)
        
        return plaintext.decode('utf-8')
    
    def send_message(self, server_socket: socket.socket, message: str) -> None:
        """
        Send encrypted message to server.
        
        Args:
            server_socket: Connected server socket
            message: Plaintext message to send
        
        Raises:
            ConnectionError: If connection is broken or closed
        """
        try:
            encrypted = self.encrypt_message(message)
            msg = {
                'type': 'encrypted_message',
                'message': encrypted
            }
            server_socket.send(json.dumps(msg).encode('utf-8') + b'\n')
        except BrokenPipeError:
            raise ConnectionError("Connection closed by server")
        except OSError as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def _receive_complete_message(self, server_socket: socket.socket) -> str:
        """
        Receive a complete JSON message from server (until newline).
        
        Args:
            server_socket: Connected server socket
        
        Returns:
            Complete message string (without trailing newline)
        
        Raises:
            ConnectionError: If connection is closed or empty data received
        """
        buffer = b''
        while True:
            chunk = server_socket.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by server")
            buffer += chunk
            if b'\n' in buffer:
                # Found complete message
                message, remaining = buffer.split(b'\n', 1)
                return message.decode('utf-8')
    
    def receive_message(self, server_socket: socket.socket) -> Optional[str]:
        """
        Receive and decrypt message from server.
        
        Args:
            server_socket: Connected server socket
        
        Returns:
            Decrypted message, or None if message type is invalid
        """
        try:
            data = self._receive_complete_message(server_socket)
            if not data or not data.strip():
                return None
            message = json.loads(data)
            
            if message['type'] == 'encrypted_message':
                decrypted = self.decrypt_message(message['message'])
                return decrypted
            return None
        except (json.JSONDecodeError, ConnectionError, ValueError) as e:
            print(f"Error receiving message: {e}")
            return None
    
    def connect(self) -> bool:
        """
        Connect to server and establish secure communication.
        
        The connection process:
        1. Load CA certificate
        2. Connect to server
        3. Receive and verify server certificate
        4. Generate and send encrypted session key
        5. Establish encrypted communication channel
        
        Returns:
            True if connection and handshake successful, False otherwise
        """
        self.load_ca_certificate()
        
        # Connect to server
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.connect((self.host, self.port))
        print(f"Connected to server at {self.host}:{self.port}")
        
        try:
            # Step 1: Receive and verify server certificate
            if not self.receive_and_verify_certificate(server_socket):
                print("Certificate verification failed. Aborting connection.")
                return False
            
            # Step 2: Generate and send encrypted session key
            self.generate_and_send_session_key(server_socket)
            
            # Step 3: Receive confirmation
            confirmation = self.receive_message(server_socket)
            print(f"Server: {confirmation}")
            
            # Step 4: Interactive communication
            print("\nSecure communication established! Type messages (or 'exit' to quit):")
            while True:
                user_input = input("You: ")
                if user_input.lower() == 'exit':
                    self.send_message(server_socket, 'exit')
                    break
                
                self.send_message(server_socket, user_input)
                response = self.receive_message(server_socket)
                if response:
                    print(f"Server: {response}")
            
            return True
            
        except Exception as e:
            print(f"Error: {e}")
            return False
        finally:
            server_socket.close()
            print("Disconnected from server")


if __name__ == "__main__":
    client = SecureClient()
    client.connect()


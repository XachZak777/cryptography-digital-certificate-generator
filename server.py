"""
Secure Server Implementation
Provides certificate to clients and establishes encrypted communication using AES.

This server:
1. Sends its certificate to connecting clients
2. Receives and decrypts session keys encrypted with its public key
3. Communicates with clients using AES-CBC encryption
"""
import socket
import os
import json
import base64
from typing import Optional
from crypto import (
    aes_cbc_encrypt,
    aes_cbc_decrypt,
    pkcs7_pad,
    pkcs7_unpad,
    rsa_oaep_decrypt,
    pem_to_rsa_private_key,
    SimpleCertificate
)


class SecureServer:
    """
    Secure server that provides certificate and uses AES for communication.
    
    The server follows this protocol:
    1. Client connects
    2. Server sends its certificate
    3. Client verifies certificate and sends encrypted session key
    4. Server decrypts session key
    5. Both parties communicate using AES-CBC encryption
    """
    
    def __init__(
        self,
        host: str = 'localhost',
        port: int = 8443,
        server_key_path: str = 'certificates/localhost_key.pem',
        server_cert_path: str = 'certificates/localhost_cert.pem'
    ):
        """
        Initialize secure server.
        
        Args:
            host: Server hostname or IP address
            port: Server port number
            server_key_path: Path to server's private key file
            server_cert_path: Path to server's certificate file
        """
        self.host = host
        self.port = port
        self.server_key_path = server_key_path
        self.server_cert_path = server_cert_path
        self.server_private_key: Optional[tuple] = None
        self.server_certificate: Optional[SimpleCertificate] = None
        self.session_key: Optional[bytes] = None
        
    def load_certificates(self) -> None:
        """
        Load server's private key and certificate from files.
        
        Raises:
            FileNotFoundError: If certificate or key files don't exist
        """
        if not os.path.exists(self.server_key_path) or not os.path.exists(self.server_cert_path):
            raise FileNotFoundError(
                "Server certificate or key not found. "
                "Please generate them first using ca.py"
            )
        
        # Load private key
        with open(self.server_key_path, "rb") as f:
            key_data = f.read()
            self.server_private_key = pem_to_rsa_private_key(key_data)
        
        # Load certificate
        with open(self.server_cert_path, "rb") as f:
            cert_data = f.read()
            # Try to decode as our simple certificate format
            try:
                cert_str = cert_data.decode('utf-8').strip()
                if cert_str.startswith('-----'):
                    # PEM-like format, extract base64 part
                    lines = [l for l in cert_str.split('\n') if l and not l.startswith('-----')]
                    cert_str = ''.join(lines)
                self.server_certificate = SimpleCertificate.deserialize(cert_str)
            except Exception as e:
                raise ValueError(f"Failed to load certificate: {e}")
        
        print("Server certificates loaded successfully")
    
    def decrypt_session_key(self, encrypted_session_key: str) -> bytes:
        """
        Decrypt the session key sent by the client using server's private key.
        
        The session key is encrypted using RSA-OAEP with the server's public key.
        
        Args:
            encrypted_session_key: Base64-encoded encrypted session key
        
        Returns:
            Decrypted session key (32 bytes for AES-256)
        
        Raises:
            ValueError: If decryption fails
        """
        if self.server_private_key is None:
            raise ValueError("Server private key not loaded")
        
        try:
            # Decode from base64
            encrypted_data = base64.b64decode(encrypted_session_key)
            
            # Decrypt using RSA-OAEP
            session_key = rsa_oaep_decrypt(encrypted_data, self.server_private_key)
            
            self.session_key = session_key
            print(f"Session key received and decrypted: {len(session_key)} bytes")
            return session_key
        except Exception as e:
            print(f"Error decrypting session key: {e}")
            raise ValueError(f"Failed to decrypt session key: {e}")
    
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
    
    def send_certificate(self, client_socket: socket.socket) -> None:
        """
        Send server certificate to client.
        
        Args:
            client_socket: Connected client socket
        """
        if self.server_certificate is None:
            raise ValueError("Server certificate not loaded")
        
        # Serialize certificate
        cert_data = self.server_certificate.serialize()
        
        message = {
            'type': 'certificate',
            'certificate': cert_data
        }
        
        client_socket.send(json.dumps(message).encode('utf-8') + b'\n')
        print("Certificate sent to client")
    
    def _receive_complete_message(self, client_socket: socket.socket) -> str:
        """
        Receive a complete JSON message from client (until newline).
        
        Args:
            client_socket: Connected client socket
        
        Returns:
            Complete message string (without trailing newline)
        
        Raises:
            ConnectionError: If connection is closed or empty data received
        """
        buffer = b''
        while True:
            chunk = client_socket.recv(4096)
            if not chunk:
                raise ConnectionError("Connection closed by client")
            buffer += chunk
            if b'\n' in buffer:
                # Found complete message
                message, remaining = buffer.split(b'\n', 1)
                return message.decode('utf-8')
    
    def receive_session_key(self, client_socket: socket.socket) -> bool:
        """
        Receive encrypted session key from client.
        
        Args:
            client_socket: Connected client socket
        
        Returns:
            True if session key received and decrypted successfully, False otherwise
        """
        try:
            data = self._receive_complete_message(client_socket)
            message = json.loads(data)
        except (json.JSONDecodeError, ConnectionError) as e:
            print(f"Error receiving session key: {e}")
            return False
        
        if message['type'] == 'session_key':
            encrypted_key = message['encrypted_session_key']
            self.decrypt_session_key(encrypted_key)
            return True
        return False
    
    def send_response(self, client_socket: socket.socket, message: str) -> None:
        """
        Send encrypted response to client.
        
        Args:
            client_socket: Connected client socket
            message: Plaintext message to send
        
        Raises:
            ConnectionError: If connection is broken or closed
        """
        try:
            encrypted = self.encrypt_message(message)
            response = {
                'type': 'encrypted_message',
                'message': encrypted
            }
            client_socket.send(json.dumps(response).encode('utf-8') + b'\n')
        except BrokenPipeError:
            raise ConnectionError("Connection closed by client")
        except OSError as e:
            raise ConnectionError(f"Connection error: {e}")
    
    def receive_message(self, client_socket: socket.socket) -> Optional[str]:
        """
        Receive and decrypt message from client.
        
        Args:
            client_socket: Connected client socket
        
        Returns:
            Decrypted message, or None if message type is invalid
        """
        try:
            data = self._receive_complete_message(client_socket)
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
    
    def start(self) -> None:
        """
        Start the secure server.
        
        The server listens for client connections and handles the secure
        communication protocol:
        1. Send certificate to client
        2. Receive and decrypt session key
        3. Establish encrypted communication channel
        """
        self.load_certificates()
        
        # Create socket
        server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        server_socket.bind((self.host, self.port))
        server_socket.listen(5)
        
        print(f"Server listening on {self.host}:{self.port}")
        print("Waiting for client connection...")
        
        while True:
            client_socket, address = server_socket.accept()
            print(f"Client connected from {address}")
            
            try:
                # Step 1: Send certificate to client
                self.send_certificate(client_socket)
                
                # Step 2: Receive encrypted session key
                if self.receive_session_key(client_socket):
                    print("Session key established!")
                    
                    # Step 3: Send confirmation
                    self.send_response(
                        client_socket,
                        "Session key received. Secure communication established!"
                    )
                    
                    # Step 4: Handle client messages
                    while True:
                        try:
                            message = self.receive_message(client_socket)
                            if message is None:
                                # Connection error or invalid message, break the loop
                                print("Connection closed or invalid message received")
                                break
                            
                            print(f"Received from client: {message}")
                            
                            # Echo back with modification
                            response = f"Server received: {message}"
                            self.send_response(client_socket, response)
                            
                            # Exit on specific command
                            if message.lower() == 'exit':
                                break
                        except (ConnectionError, OSError) as e:
                            print(f"Connection error: {e}")
                            break
                        except Exception as e:
                            print(f"Error in communication: {e}")
                            break
                else:
                    print("Failed to receive session key")
                    
            except Exception as e:
                print(f"Error handling client: {e}")
            finally:
                client_socket.close()
                self.session_key = None  # Reset session key for next client
                print("Client disconnected")


if __name__ == "__main__":
    server = SecureServer()
    server.start()


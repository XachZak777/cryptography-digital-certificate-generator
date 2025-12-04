"""
Certificate Authority (CA) Implementation
Generates digital certificates for servers using custom cryptographic implementations.

This CA:
1. Generates its own RSA key pair
2. Creates a self-signed CA certificate
3. Generates and signs server certificates
"""
import os
import random
from datetime import datetime, timedelta
from typing import Tuple, Optional
from crypto import (
    generate_rsa_keypair,
    rsa_private_key_to_pem,
    rsa_public_key_to_pem,
    pem_to_rsa_private_key,
    pem_to_rsa_public_key,
    SimpleCertificate
)


class CertificateAuthority:
    """
    Certificate Authority that generates and signs certificates.
    
    A CA is a trusted entity that issues digital certificates. It:
    - Maintains its own key pair (public/private)
    - Signs certificates for servers
    - Provides a root of trust for certificate verification
    """
    
    def __init__(
        self,
        ca_key_path: str = "certificates/ca_private_key.pem",
        ca_cert_path: str = "certificates/ca_certificate.pem"
    ):
        """
        Initialize Certificate Authority.
        
        Args:
            ca_key_path: Path to save CA's private key
            ca_cert_path: Path to save CA's certificate
        """
        self.ca_key_path = ca_key_path
        self.ca_cert_path = ca_cert_path
        self.ca_private_key: Optional[Tuple[int, int]] = None
        self.ca_public_key: Optional[Tuple[int, int]] = None
        self.ca_certificate: Optional[SimpleCertificate] = None
    
    def generate_ca(self) -> None:
        """
        Generate CA's own private key and self-signed certificate.
        
        The CA generates:
        1. RSA key pair (2048-bit)
        2. Self-signed certificate valid for 10 years
        3. Saves key and certificate to files
        """
        if os.path.exists(self.ca_key_path) and os.path.exists(self.ca_cert_path):
            print("CA key and certificate already exist. Loading...")
            self.load_ca()
            return
        
        print("Generating CA private key...")
        # Generate CA key pair
        self.ca_public_key, self.ca_private_key = generate_rsa_keypair(key_size=2048)
        
        # Create CA certificate (self-signed)
        now = datetime.utcnow()
        serial_number = random.randint(1, 2**64 - 1)
        
        self.ca_certificate = SimpleCertificate(
            subject="CA",
            issuer="CA",  # Self-signed
            public_key=self.ca_public_key,
            serial_number=serial_number,
            not_before=now,
            not_after=now + timedelta(days=3650),  # 10 years
            is_ca=True
        )
        
        # Sign the certificate with its own private key
        self.ca_certificate.sign(self.ca_private_key)
        
        # Save CA key and certificate
        self.save_ca()
        print("CA generated successfully!")
    
    def save_ca(self) -> None:
        """
        Save CA private key and certificate to files.
        
        The private key is saved in PEM format.
        The certificate is saved in our simplified format (base64-encoded JSON).
        """
        if self.ca_private_key is None or self.ca_certificate is None:
            raise ValueError("CA not initialized. Call generate_ca() first.")
        
        # Save private key
        key_pem = rsa_private_key_to_pem(self.ca_private_key)
        with open(self.ca_key_path, "wb") as f:
            f.write(key_pem)
        
        # Save certificate
        cert_data = self.ca_certificate.serialize()
        # Add PEM-like headers for consistency
        cert_pem = f"-----BEGIN CERTIFICATE-----\n"
        # Split into 64-character lines
        for i in range(0, len(cert_data), 64):
            cert_pem += cert_data[i:i+64] + "\n"
        cert_pem += "-----END CERTIFICATE-----\n"
        
        with open(self.ca_cert_path, "w") as f:
            f.write(cert_pem)
    
    def load_ca(self) -> None:
        """
        Load CA private key and certificate from files.
        
        Raises:
            FileNotFoundError: If key or certificate files don't exist
        """
        if not os.path.exists(self.ca_key_path) or not os.path.exists(self.ca_cert_path):
            raise FileNotFoundError("CA key or certificate file not found")
        
        # Load certificate first (contains public key)
        with open(self.ca_cert_path, "rb") as f:
            cert_data = f.read()
            cert_str = cert_data.decode('utf-8').strip()
            if cert_str.startswith('-----'):
                # PEM-like format, extract base64 part
                lines = [l for l in cert_str.split('\n') if l and not l.startswith('-----')]
                cert_str = ''.join(lines)
            self.ca_certificate = SimpleCertificate.deserialize(cert_str)
        
        # Extract public key from certificate
        self.ca_public_key = self.ca_certificate.public_key
        
        # Load private key
        with open(self.ca_key_path, "rb") as f:
            key_data = f.read()
            self.ca_private_key = pem_to_rsa_private_key(key_data)
    
    def generate_server_certificate(
        self,
        server_name: str,
        server_key_path: Optional[str] = None,
        server_cert_path: Optional[str] = None
    ) -> Tuple[str, str]:
        """
        Generate a certificate for a server signed by the CA.
        
        Process:
        1. Generate server's RSA key pair
        2. Create certificate with server's public key
        3. Sign certificate with CA's private key
        4. Save server's private key and certificate
        
        Args:
            server_name: Common name for the server (e.g., "localhost" or IP)
            server_key_path: Path to save server's private key
                           (default: {server_name}_key.pem)
            server_cert_path: Path to save server's certificate
                            (default: {server_name}_cert.pem)
        
        Returns:
            Tuple of (server_key_path, server_cert_path)
        
        Raises:
            ValueError: If CA is not initialized
        """
        if self.ca_private_key is None or self.ca_certificate is None:
            raise ValueError("CA not initialized. Call generate_ca() first.")
        
        if server_key_path is None:
            server_key_path = f"certificates/{server_name}_key.pem"
        if server_cert_path is None:
            server_cert_path = f"certificates/{server_name}_cert.pem"
        
        print(f"Generating certificate for server: {server_name}")
        
        # Generate server's key pair
        print("  Generating server key pair...")
        server_public_key, server_private_key = generate_rsa_keypair(key_size=2048)
        
        # Create server certificate
        now = datetime.utcnow()
        serial_number = random.randint(1, 2**64 - 1)
        
        server_cert = SimpleCertificate(
            subject=server_name,
            issuer=self.ca_certificate.subject,  # Issued by CA
            public_key=server_public_key,
            serial_number=serial_number,
            not_before=now,
            not_after=now + timedelta(days=365),  # 1 year validity
            is_ca=False
        )
        
        # Sign certificate with CA's private key
        server_cert.sign(self.ca_private_key)
        
        # Save server key and certificate
        key_pem = rsa_private_key_to_pem(server_private_key)
        with open(server_key_path, "wb") as f:
            f.write(key_pem)
        
        cert_data = server_cert.serialize()
        cert_pem = f"-----BEGIN CERTIFICATE-----\n"
        for i in range(0, len(cert_data), 64):
            cert_pem += cert_data[i:i+64] + "\n"
        cert_pem += "-----END CERTIFICATE-----\n"
        
        with open(server_cert_path, "w") as f:
            f.write(cert_pem)
        
        print(f"Server certificate generated: {server_cert_path}")
        return server_key_path, server_cert_path
    
    def _is_ip(self, address: str) -> bool:
        """
        Check if a string is an IP address.
        
        Args:
            address: String to check
        
        Returns:
            True if address is an IP, False otherwise
        """
        try:
            parts = address.split('.')
            if len(parts) != 4:
                return False
            for part in parts:
                num = int(part)
                if num < 0 or num > 255:
                    return False
            return True
        except:
            return False


if __name__ == "__main__":
    import pathlib
    # Ensure certificates directory exists
    cert_dir = pathlib.Path("certificates")
    cert_dir.mkdir(exist_ok=True)
    
    # Generate CA
    ca = CertificateAuthority()
    ca.generate_ca()
    
    # Generate server certificate
    ca.generate_server_certificate("localhost")

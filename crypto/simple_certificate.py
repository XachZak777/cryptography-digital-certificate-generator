"""
Simplified X.509 Certificate Implementation
A simplified certificate structure for educational purposes.

This implementation provides basic certificate functionality:
- Certificate creation with subject, issuer, public key
- Certificate signing and verification
- Certificate serialization/deserialization
"""

import json
import base64
from datetime import datetime
from typing import Dict, Tuple, Optional
import hashlib


class SimpleCertificate:
    """
    Simplified X.509 certificate structure.
    
    A certificate binds a public key to an identity and is signed by a CA.
    """
    
    def __init__(
        self,
        subject: str,
        issuer: str,
        public_key: Tuple[int, int],
        serial_number: int,
        not_before: datetime,
        not_after: datetime,
        signature: Optional[bytes] = None,
        is_ca: bool = False
    ):
        """
        Initialize a certificate.
        
        Args:
            subject: Subject name (e.g., "localhost")
            issuer: Issuer name (e.g., "CA")
            public_key: RSA public key (n, e)
            serial_number: Unique serial number
            not_before: Certificate validity start date
            not_after: Certificate validity end date
            signature: Certificate signature (None for unsigned)
            is_ca: Whether this is a CA certificate
        """
        self.subject = subject
        self.issuer = issuer
        self.public_key = public_key
        self.serial_number = serial_number
        self.not_before = not_before
        self.not_after = not_after
        self.signature = signature
        self.is_ca = is_ca
    
    def to_dict(self) -> Dict:
        """
        Convert certificate to dictionary (excluding signature).
        
        Returns:
            Dictionary representation
        """
        return {
            'subject': self.subject,
            'issuer': self.issuer,
            'public_key': {
                'n': str(self.public_key[0]),  # Convert to string for JSON
                'e': str(self.public_key[1])
            },
            'serial_number': str(self.serial_number),
            'not_before': self.not_before.isoformat(),
            'not_after': self.not_after.isoformat(),
            'is_ca': self.is_ca
        }
    
    def get_tbs_bytes(self) -> bytes:
        """
        Get "To Be Signed" bytes (certificate data without signature).
        
        Returns:
            Bytes to be signed
        """
        cert_dict = self.to_dict()
        cert_json = json.dumps(cert_dict, sort_keys=True)
        return cert_json.encode('utf-8')
    
    def sign(self, ca_private_key: Tuple[int, int]) -> None:
        """
        Sign certificate with CA's private key.
        
        Args:
            ca_private_key: CA's private key (n, d)
        """
        # Get data to sign
        tbs_bytes = self.get_tbs_bytes()
        
        # Hash the data (SHA-256)
        hash_value = hashlib.sha256(tbs_bytes).digest()
        
        # Convert hash to integer (for RSA signing)
        hash_int = int.from_bytes(hash_value, 'big')
        
        # Ensure hash is less than modulus
        n, _ = ca_private_key
        if hash_int >= n:
            # Truncate if necessary (simplified approach)
            hash_int = hash_int % n
        
        # Sign using RSA (in practice, use proper padding like PSS)
        # For educational purposes, we'll use a simple approach
        signature_int = pow(hash_int, ca_private_key[1], n)
        
        # Convert signature to bytes
        key_size_bytes = (n.bit_length() + 7) // 8
        self.signature = signature_int.to_bytes(key_size_bytes, 'big')
    
    def verify(self, ca_public_key: Tuple[int, int]) -> bool:
        """
        Verify certificate signature using CA's public key.
        
        Args:
            ca_public_key: CA's public key (n, e)
        
        Returns:
            True if signature is valid, False otherwise
        """
        if self.signature is None:
            return False
        
        # Get data that was signed
        tbs_bytes = self.get_tbs_bytes()
        
        # Hash the data
        hash_value = hashlib.sha256(tbs_bytes).digest()
        hash_int = int.from_bytes(hash_value, 'big')
        
        # Verify signature
        n, e = ca_public_key
        signature_int = int.from_bytes(self.signature, 'big')
        
        # Decrypt signature
        verified_hash_int = pow(signature_int, e, n)
        
        # Ensure hash is less than modulus
        if hash_int >= n:
            hash_int = hash_int % n
        
        # Compare (with padding consideration)
        # In simplified version, we compare the lower bits
        hash_bytes = hash_int.to_bytes(32, 'big')
        verified_hash_bytes = verified_hash_int.to_bytes((n.bit_length() + 7) // 8, 'big')
        
        # Compare last 32 bytes (SHA-256 hash length)
        return hash_bytes == verified_hash_bytes[-32:]
    
    def is_valid(self) -> bool:
        """
        Check if certificate is within validity period.
        
        Returns:
            True if certificate is valid, False if expired
        """
        now = datetime.utcnow()
        return self.not_before <= now <= self.not_after
    
    def serialize(self) -> str:
        """
        Serialize certificate to base64-encoded JSON string.
        
        Returns:
            Serialized certificate
        """
        cert_dict = self.to_dict()
        if self.signature:
            cert_dict['signature'] = base64.b64encode(self.signature).decode('utf-8')
        cert_json = json.dumps(cert_dict)
        return base64.b64encode(cert_json.encode('utf-8')).decode('utf-8')
    
    @classmethod
    def deserialize(cls, data: str) -> 'SimpleCertificate':
        """
        Deserialize certificate from base64-encoded JSON string.
        
        Args:
            data: Serialized certificate
        
        Returns:
            Deserialized certificate
        """
        cert_json = base64.b64decode(data).decode('utf-8')
        cert_dict = json.loads(cert_json)
        
        # Reconstruct certificate
        signature = None
        if 'signature' in cert_dict:
            signature = base64.b64decode(cert_dict['signature'])
        
        return cls(
            subject=cert_dict['subject'],
            issuer=cert_dict['issuer'],
            public_key=(int(cert_dict['public_key']['n']), int(cert_dict['public_key']['e'])),
            serial_number=int(cert_dict['serial_number']),
            not_before=datetime.fromisoformat(cert_dict['not_before']),
            not_after=datetime.fromisoformat(cert_dict['not_after']),
            signature=signature,
            is_ca=cert_dict.get('is_ca', False)
        )


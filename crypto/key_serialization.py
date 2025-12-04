"""
RSA Key Serialization
Handles serialization and deserialization of RSA keys to/from PEM format.
"""

import base64
from typing import Tuple


def int_to_bytes(value: int, length: int = None) -> bytes:
    """
    Convert integer to bytes (big-endian).
    
    Args:
        value: Integer to convert
        length: Optional fixed length (pads with zeros if needed)
    
    Returns:
        Bytes representation
    """
    if value == 0:
        return b'\x00' if length is None else b'\x00' * length
    
    byte_length = (value.bit_length() + 7) // 8
    if length is not None and byte_length < length:
        result = value.to_bytes(length, 'big')
    else:
        result = value.to_bytes(byte_length, 'big')
    
    return result


def encode_der_integer(value: int) -> bytes:
    """
    Encode integer in DER (Distinguished Encoding Rules) format.
    
    Args:
        value: Integer to encode
    
    Returns:
        DER-encoded integer
    """
    # Convert to bytes
    data = int_to_bytes(value)
    
    # Ensure first bit is not set (for positive numbers)
    if data[0] & 0x80:
        data = b'\x00' + data
    
    # DER INTEGER tag (0x02) + length + data
    length = len(data)
    if length < 128:
        return bytes([0x02, length]) + data
    else:
        # Long form length encoding
        length_bytes = int_to_bytes(length)
        return bytes([0x02, 0x80 | len(length_bytes)]) + length_bytes + data


def encode_der_sequence(elements: list) -> bytes:
    """
    Encode sequence in DER format.
    
    Args:
        elements: List of DER-encoded elements
    
    Returns:
        DER-encoded sequence
    """
    content = b''.join(elements)
    length = len(content)
    
    if length < 128:
        return bytes([0x30, length]) + content
    else:
        length_bytes = int_to_bytes(length)
        return bytes([0x30, 0x80 | len(length_bytes)]) + length_bytes + content


def rsa_private_key_to_pem(private_key: Tuple[int, int]) -> bytes:
    """
    Convert RSA private key to PEM format.
    
    Args:
        private_key: RSA private key (n, d)
    
    Returns:
        PEM-encoded private key
    """
    n, d = private_key
    
    # For simplicity, we'll create a minimal RSA private key structure
    # In full implementation, we'd include p, q, dP, dQ, qInv
    # This is a simplified version for educational purposes
    
    # RSAPrivateKey structure (simplified):
    # SEQUENCE {
    #   version INTEGER (0)
    #   modulus INTEGER (n)
    #   publicExponent INTEGER (e) - we'll use 65537
    #   privateExponent INTEGER (d)
    #   prime1 INTEGER (p) - omitted in simplified version
    #   prime2 INTEGER (q) - omitted in simplified version
    #   ...
    # }
    
    version = encode_der_integer(0)
    modulus = encode_der_integer(n)
    public_exp = encode_der_integer(65537)  # Common public exponent
    private_exp = encode_der_integer(d)
    
    # Create sequence
    key_seq = encode_der_sequence([version, modulus, public_exp, private_exp])
    
    # Base64 encode
    key_b64 = base64.b64encode(key_seq).decode('ascii')
    
    # Add PEM headers
    pem_lines = ['-----BEGIN RSA PRIVATE KEY-----']
    # Split into 64-character lines
    for i in range(0, len(key_b64), 64):
        pem_lines.append(key_b64[i:i+64])
    pem_lines.append('-----END RSA PRIVATE KEY-----')
    
    return '\n'.join(pem_lines).encode('ascii')


def rsa_public_key_to_pem(public_key: Tuple[int, int]) -> bytes:
    """
    Convert RSA public key to PEM format (SubjectPublicKeyInfo).
    
    Args:
        public_key: RSA public key (n, e)
    
    Returns:
        PEM-encoded public key
    """
    n, e = public_key
    
    # RSAPublicKey structure:
    # SEQUENCE {
    #   modulus INTEGER (n)
    #   publicExponent INTEGER (e)
    # }
    
    modulus = encode_der_integer(n)
    public_exp = encode_der_integer(e)
    
    # RSA public key sequence
    rsa_pub_key = encode_der_sequence([modulus, public_exp])
    
    # SubjectPublicKeyInfo structure:
    # SEQUENCE {
    #   algorithm SEQUENCE {
    #     algorithm OBJECT IDENTIFIER (rsaEncryption)
    #     parameters NULL
    #   }
    #   subjectPublicKey BIT STRING (RSAPublicKey)
    # }
    
    # Algorithm OID for rsaEncryption: 1.2.840.113549.1.1.1
    # Encoded as: 0x06 0x09 0x2a 0x86 0x48 0x86 0xf7 0x0d 0x01 0x01 0x01
    algorithm_oid = bytes([0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x01])
    null_params = bytes([0x05, 0x00])  # NULL
    algorithm_seq = encode_der_sequence([algorithm_oid, null_params])
    
    # BIT STRING: 0x03 + length + unused bits (0) + data
    bit_string_data = rsa_pub_key
    bit_string = bytes([0x03, len(bit_string_data) + 1, 0x00]) + bit_string_data
    
    # SubjectPublicKeyInfo sequence
    spki = encode_der_sequence([algorithm_seq, bit_string])
    
    # Base64 encode
    key_b64 = base64.b64encode(spki).decode('ascii')
    
    # Add PEM headers
    pem_lines = ['-----BEGIN PUBLIC KEY-----']
    for i in range(0, len(key_b64), 64):
        pem_lines.append(key_b64[i:i+64])
    pem_lines.append('-----END PUBLIC KEY-----')
    
    return '\n'.join(pem_lines).encode('ascii')


def parse_der_integer(data: bytes, offset: int = 0) -> Tuple[int, int]:
    """
    Parse DER-encoded integer.
    
    Args:
        data: DER-encoded data
        offset: Starting offset
    
    Returns:
        Tuple (value, next_offset)
    """
    if data[offset] != 0x02:
        raise ValueError("Not an INTEGER tag")
    
    offset += 1
    length = data[offset]
    offset += 1
    
    if length & 0x80:
        # Long form
        length_bytes = length & 0x7f
        length = int.from_bytes(data[offset:offset+length_bytes], 'big')
        offset += length_bytes
    
    value = int.from_bytes(data[offset:offset+length], 'big')
    return value, offset + length


def parse_der_sequence(data: bytes, offset: int = 0) -> Tuple[list, int]:
    """
    Parse DER-encoded sequence.
    
    Args:
        data: DER-encoded data
        offset: Starting offset
    
    Returns:
        Tuple (elements, next_offset)
    """
    if data[offset] != 0x30:
        raise ValueError("Not a SEQUENCE tag")
    
    offset += 1
    length = data[offset]
    offset += 1
    
    if length & 0x80:
        length_bytes = length & 0x7f
        length = int.from_bytes(data[offset:offset+length_bytes], 'big')
        offset += length_bytes
    
    end_offset = offset + length
    elements = []
    
    while offset < end_offset:
        # Parse next element (simplified - assumes INTEGER)
        if data[offset] == 0x02:
            value, offset = parse_der_integer(data, offset)
            elements.append(value)
        elif data[offset] == 0x30:
            # Nested sequence
            seq_data, offset = parse_der_sequence(data, offset)
            elements.append(seq_data)
        else:
            # Skip unknown tags (simplified parser)
            offset += 1
    
    return elements, end_offset


def pem_to_rsa_private_key(pem_data: bytes) -> Tuple[int, int]:
    """
    Parse PEM-encoded RSA private key.
    
    Args:
        pem_data: PEM-encoded private key
    
    Returns:
        RSA private key (n, d)
    """
    # Remove PEM headers
    pem_str = pem_data.decode('ascii')
    pem_str = pem_str.replace('-----BEGIN RSA PRIVATE KEY-----', '')
    pem_str = pem_str.replace('-----END RSA PRIVATE KEY-----', '')
    pem_str = pem_str.replace('\n', '').replace('\r', '').replace(' ', '')
    
    # Decode base64
    der_data = base64.b64decode(pem_str)
    
    # Parse DER sequence
    elements, _ = parse_der_sequence(der_data)
    
    # Simplified: assume structure is [version, n, e, d, ...]
    if len(elements) < 4:
        raise ValueError("Invalid RSA private key structure")
    
    n = elements[1]  # modulus
    d = elements[3]  # private exponent
    
    return (n, d)


def pem_to_rsa_public_key(pem_data: bytes) -> Tuple[int, int]:
    """
    Parse PEM-encoded RSA public key.
    
    Args:
        pem_data: PEM-encoded public key
    
    Returns:
        RSA public key (n, e)
    """
    # Remove PEM headers
    pem_str = pem_data.decode('ascii')
    pem_str = pem_str.replace('-----BEGIN PUBLIC KEY-----', '')
    pem_str = pem_str.replace('-----END PUBLIC KEY-----', '')
    pem_str = pem_str.replace('\n', '').replace('\r', '').replace(' ', '')
    
    # Decode base64
    der_data = base64.b64decode(pem_str)
    
    # Parse SubjectPublicKeyInfo
    # This is a simplified parser - full implementation would handle all cases
    # For now, we'll extract the RSA public key from the bit string
    
    # Find the RSAPublicKey sequence within the SPKI
    # Look for the sequence containing modulus and exponent
    try:
        # Simplified: search for the pattern
        # In practice, you'd properly parse the ASN.1 structure
        offset = 0
        while offset < len(der_data) - 10:
            if der_data[offset] == 0x30:  # SEQUENCE
                try:
                    elements, _ = parse_der_sequence(der_data, offset)
                    if len(elements) >= 2 and isinstance(elements[0], int) and isinstance(elements[1], int):
                        # Likely found RSA public key
                        n = elements[0]
                        e = elements[1]
                        return (n, e)
                except:
                    pass
            offset += 1
        
        raise ValueError("Could not parse RSA public key")
    except Exception as e:
        raise ValueError(f"Failed to parse public key: {e}")


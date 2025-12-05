"""
RSA Cryptosystem Implementation
Implements RSA key generation, encryption, and decryption from scratch.

RSA is an asymmetric cryptographic algorithm based on the difficulty of
factoring large integers. This implementation includes:
- Key generation using prime number generation
- RSA encryption/decryption
- RSA-OAEP padding for secure encryption
"""

import os
import random
from typing import Tuple


def gcd(a: int, b: int) -> int:
    """
    Compute Greatest Common Divisor using Euclidean algorithm.
    
    Args:
        a: First integer
        b: Second integer
    
    Returns:
        GCD of a and b
    """
    while b:
        a, b = b, a % b
    return a


def extended_gcd(a: int, b: int) -> Tuple[int, int, int]:
    """
    Extended Euclidean Algorithm.
    Returns (gcd, x, y) such that ax + by = gcd(a, b).
    
    Args:
        a: First integer
        b: Second integer
    
    Returns:
        Tuple (gcd, x, y)
    """
    if a == 0:
        return b, 0, 1
    gcd_val, x1, y1 = extended_gcd(b % a, a)
    x = y1 - (b // a) * x1
    y = x1
    return gcd_val, x, y


def mod_inverse(a: int, m: int) -> int:
    """
    Compute modular inverse of a modulo m.
    Returns x such that (a * x) % m == 1.
    
    Args:
        a: Integer
        m: Modulus
    
    Returns:
        Modular inverse of a modulo m
    
    Raises:
        ValueError: If modular inverse doesn't exist
    """
    gcd_val, x, _ = extended_gcd(a % m, m)
    if gcd_val != 1:
        raise ValueError("Modular inverse doesn't exist")
    return (x % m + m) % m


def miller_rabin(n: int, k: int = 40) -> bool:
    """
    Miller-Rabin primality test.
    Probabilistic test to determine if a number is prime.
    
    Args:
        n: Number to test
        k: Number of iterations (higher = more accurate)
    
    Returns:
        True if n is probably prime, False if composite
    """
    if n < 2:
        return False
    if n == 2 or n == 3:
        return True
    if n % 2 == 0:
        return False
    
    # Write n-1 as d * 2^r
    d = n - 1
    r = 0
    while d % 2 == 0:
        d //= 2
        r += 1
    
    # Test k times
    for _ in range(k):
        a = random.randrange(2, n - 1)
        x = pow(a, d, n)
        
        if x == 1 or x == n - 1:
            continue
        
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    
    return True


def generate_prime(bits: int) -> int:
    """
    Generate a random prime number of specified bit length.
    
    Args:
        bits: Number of bits for the prime
    
    Returns:
        A prime number
    """
    while True:
        # Generate random odd number of specified bit length
        candidate = random.getrandbits(bits)
        candidate |= (1 << (bits - 1))  # Set MSB to ensure correct bit length
        candidate |= 1  # Make it odd
        
        if miller_rabin(candidate):
            return candidate


def generate_rsa_keypair(key_size: int = 2048) -> Tuple[Tuple[int, int], Tuple[int, int]]:
    """
    Generate RSA key pair.
    
    The key generation process:
    1. Generate two large prime numbers p and q
    2. Compute n = p * q (modulus)
    3. Compute φ(n) = (p-1) * (q-1) (Euler's totient)
    4. Choose e (public exponent, typically 65537)
    5. Compute d (private exponent) such that e*d ≡ 1 (mod φ(n))
    
    Args:
        key_size: Size of the key in bits (default 2048)
    
    Returns:
        Tuple ((n, e), (n, d)) where (n, e) is public key and (n, d) is private key
    """
    if key_size < 512:
        raise ValueError("Key size must be at least 512 bits for security")
    
    print(f"Generating RSA-{key_size} key pair...")
    print("  Generating prime p...")
    p = generate_prime(key_size // 2)
    print("  Generating prime q...")
    q = generate_prime(key_size // 2)
    
    # Ensure p and q are different
    while p == q:
        q = generate_prime(key_size // 2)
    
    # Compute modulus
    n = p * q
    
    # Compute Euler's totient function
    phi_n = (p - 1) * (q - 1)
    
    # Choose public exponent (commonly 65537)
    e = 65537
    while gcd(e, phi_n) != 1:
        e += 2
    
    # Compute private exponent
    d = mod_inverse(e, phi_n)
    
    public_key = (n, e)
    private_key = (n, d)
    
    print(f"  Key generation complete. Modulus: {n.bit_length()} bits")
    return public_key, private_key


def rsa_encrypt(message: int, public_key: Tuple[int, int]) -> int:
    """
    RSA encryption: c = m^e mod n
    
    Args:
        message: Plaintext as integer (must be < n)
        public_key: Public key (n, e)
    
    Returns:
        Ciphertext as integer
    """
    n, e = public_key
    if message >= n:
        raise ValueError("Message must be less than modulus")
    return pow(message, e, n)


def rsa_decrypt(ciphertext: int, private_key: Tuple[int, int]) -> int:
    """
    RSA decryption: m = c^d mod n
    
    Args:
        ciphertext: Ciphertext as integer
        private_key: Private key (n, d)
    
    Returns:
        Plaintext as integer
    """
    n, d = private_key
    return pow(ciphertext, d, n)


def mgf1(seed: bytes, length: int, hash_func=None) -> bytes:
    """
    Mask Generation Function 1 (MGF1) as used in RSA-OAEP.
    Generates a mask of specified length from a seed.
    
    Note: This is a simplified version. Full OAEP uses SHA-1 or SHA-256.
    For educational purposes, we use a simple hash-like function.
    
    Args:
        seed: Input seed bytes
        length: Desired output length in bytes
        hash_func: Hash function (not used in simplified version)
    
    Returns:
        Mask bytes
    """
    # Simplified MGF1: use a simple hash-like function
    # In production, use proper hash function like SHA-256
    mask = bytearray()
    counter = 0
    while len(mask) < length:
        # Simple hash: XOR of seed with counter
        hash_input = seed + counter.to_bytes(4, 'big')
        # Simple hash function (XOR-based)
        hash_output = bytearray(32)  # 32-byte output
        for i in range(len(hash_input)):
            hash_output[i % 32] ^= hash_input[i]
        mask.extend(hash_output)
        counter += 1
    return bytes(mask[:length])


def simple_hash(data: bytes) -> bytes:
    """
    Simple hash function for OAEP (educational purposes).
    In production, use SHA-256 or similar.
    
    Args:
        data: Input data
    
    Returns:
        32-byte hash
    """
    # Simple hash: XOR-based with rotation
    result = bytearray(32)
    for i, byte in enumerate(data):
        result[i % 32] ^= byte
        result[(i + 1) % 32] ^= (byte << 1) | (byte >> 7)
    return bytes(result)


def oaep_encode(message: bytes, key_size_bits: int, label: bytes = b'') -> bytes:
    """
    RSA-OAEP encoding (simplified version for educational purposes).
    
    OAEP (Optimal Asymmetric Encryption Padding) adds padding and randomness
    to messages before RSA encryption to prevent certain attacks.
    
    Args:
        message: Message to encode
        key_size_bits: RSA key size in bits
        label: Optional label (typically empty)
    
    Returns:
        Encoded message ready for RSA encryption
    """
    key_size_bytes = key_size_bits // 8
    max_message_length = key_size_bytes - 2 * 32 - 2  # Simplified calculation
    
    if len(message) > max_message_length:
        raise ValueError(f"Message too long for OAEP encoding with {key_size_bits}-bit key")
    
    # Hash the label
    l_hash = simple_hash(label)
    
    # Generate random seed
    seed = os.urandom(32)
    
    # Create data block: lHash || PS || 0x01 || M
    ps_length = max_message_length - len(message)
    data_block = l_hash + b'\x00' * ps_length + b'\x01' + message
    
    # Generate mask for data block
    db_mask = mgf1(seed, len(data_block))
    masked_db = bytes(a ^ b for a, b in zip(data_block, db_mask))
    
    # Generate mask for seed
    seed_mask = mgf1(masked_db, 32)
    masked_seed = bytes(a ^ b for a, b in zip(seed, seed_mask))
    
    # Combine: 0x00 || masked_seed || masked_db
    encoded = b'\x00' + masked_seed + masked_db
    
    return encoded


def oaep_decode(encoded: bytes, key_size_bits: int, label: bytes = b'') -> bytes:
    """
    RSA-OAEP decoding (simplified version).
    
    Args:
        encoded: OAEP-encoded message
        key_size_bits: RSA key size in bits
        label: Optional label (must match encoding)
    
    Returns:
        Decoded message
    
    Raises:
        ValueError: If decoding fails
    """
    key_size_bytes = key_size_bits // 8
    
    if len(encoded) != key_size_bytes:
        raise ValueError("Encoded message has wrong length")
    
    if encoded[0] != 0:
        raise ValueError("Invalid OAEP encoding: first byte must be 0")
    
    # Extract components
    masked_seed = encoded[1:33]
    masked_db = encoded[33:]
    
    # Recover seed
    seed_mask = mgf1(masked_db, 32)
    seed = bytes(a ^ b for a, b in zip(masked_seed, seed_mask))
    
    # Recover data block
    db_mask = mgf1(seed, len(masked_db))
    data_block = bytes(a ^ b for a, b in zip(masked_db, db_mask))
    
    # Verify and extract message
    l_hash = simple_hash(label)
    if data_block[:32] != l_hash:
        raise ValueError("Invalid OAEP encoding: label hash mismatch")
    
    # Find 0x01 separator
    try:
        separator_idx = data_block.index(b'\x01', 32)
    except ValueError:
        raise ValueError("Invalid OAEP encoding: separator not found")
    
    # Extract message
    message = data_block[separator_idx + 1:]
    return message


def rsa_oaep_encrypt(message: bytes, public_key: Tuple[int, int]) -> bytes:
    """
    RSA-OAEP encryption.
    Encrypts a message using RSA with OAEP padding.
    
    Args:
        message: Plaintext message
        public_key: RSA public key (n, e)
    
    Returns:
        Encrypted ciphertext as bytes
    """
    n, e = public_key
    key_size_bits = n.bit_length()
    
    # OAEP encode
    encoded = oaep_encode(message, key_size_bits)
    
    # Convert to integer
    message_int = int.from_bytes(encoded, 'big')
    
    # RSA encrypt
    ciphertext_int = rsa_encrypt(message_int, public_key)
    
    # Convert back to bytes
    key_size_bytes = (key_size_bits + 7) // 8
    return ciphertext_int.to_bytes(key_size_bytes, 'big')


def rsa_oaep_decrypt(ciphertext: bytes, private_key: Tuple[int, int]) -> bytes:
    """
    RSA-OAEP decryption.
    Decrypts a ciphertext using RSA with OAEP padding.
    
    Args:
        ciphertext: Encrypted ciphertext
        private_key: RSA private key (n, d)
    
    Returns:
        Decrypted plaintext message
    """
    n, d = private_key
    key_size_bits = n.bit_length()
    
    # Convert to integer
    ciphertext_int = int.from_bytes(ciphertext, 'big')
    
    # RSA decrypt
    encoded_int = rsa_decrypt(ciphertext_int, private_key)
    
    # Convert back to bytes
    key_size_bytes = (key_size_bits + 7) // 8
    encoded = encoded_int.to_bytes(key_size_bytes, 'big')
    
    # OAEP decode
    message = oaep_decode(encoded, key_size_bits)
    
    return message


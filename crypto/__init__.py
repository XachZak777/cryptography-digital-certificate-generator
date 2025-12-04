"""
Cryptographic Primitives Module
Contains all custom cryptographic implementations.
"""

from .aes import (
    aes_encrypt_block,
    aes_decrypt_block,
    aes_cbc_encrypt,
    aes_cbc_decrypt
)

from .pkcs7 import pkcs7_pad, pkcs7_unpad

from .rsa_crypto import (
    generate_rsa_keypair,
    rsa_encrypt,
    rsa_decrypt,
    rsa_oaep_encrypt,
    rsa_oaep_decrypt
)

from .simple_certificate import SimpleCertificate

from .key_serialization import (
    rsa_private_key_to_pem,
    rsa_public_key_to_pem,
    pem_to_rsa_private_key,
    pem_to_rsa_public_key
)

__all__ = [
    'aes_encrypt_block',
    'aes_decrypt_block',
    'aes_cbc_encrypt',
    'aes_cbc_decrypt',
    'pkcs7_pad',
    'pkcs7_unpad',
    'generate_rsa_keypair',
    'rsa_encrypt',
    'rsa_decrypt',
    'rsa_oaep_encrypt',
    'rsa_oaep_decrypt',
    'SimpleCertificate',
    'rsa_private_key_to_pem',
    'rsa_public_key_to_pem',
    'pem_to_rsa_private_key',
    'pem_to_rsa_public_key'
]


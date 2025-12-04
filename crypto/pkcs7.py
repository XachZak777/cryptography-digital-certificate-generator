"""
PKCS#7 Padding Implementation
Implements PKCS#7 padding scheme for block ciphers.

PKCS#7 padding adds bytes to the end of data to make it a multiple of the block size.
The value of each padding byte is the number of padding bytes added.
"""


def pkcs7_pad(data: bytes, block_size: int = 16) -> bytes:
    """
    Add PKCS#7 padding to data.
    
    The padding scheme works as follows:
    - If data length is already a multiple of block_size, add a full block of padding
    - Otherwise, add (block_size - (len(data) % block_size)) bytes
    - Each padding byte has the value equal to the number of padding bytes
    
    Example:
        If block_size=16 and data is 10 bytes, add 6 bytes, each with value 0x06
        If block_size=16 and data is 16 bytes, add 16 bytes, each with value 0x10
    
    Args:
        data: Data to pad
        block_size: Block size in bytes (default 16 for AES)
    
    Returns:
        Padded data
    """
    if block_size < 1 or block_size > 255:
        raise ValueError("Block size must be between 1 and 255")
    
    padding_length = block_size - (len(data) % block_size)
    if padding_length == 0:
        padding_length = block_size
    
    padding = bytes([padding_length] * padding_length)
    return data + padding


def pkcs7_unpad(data: bytes, block_size: int = 16) -> bytes:
    """
    Remove PKCS#7 padding from data.
    
    Args:
        data: Padded data (must be multiple of block_size)
        block_size: Block size in bytes (default 16 for AES)
    
    Returns:
        Unpadded data
    
    Raises:
        ValueError: If padding is invalid
    """
    if len(data) == 0:
        raise ValueError("Cannot unpad empty data")
    
    if len(data) % block_size != 0:
        raise ValueError(f"Data length ({len(data)}) must be multiple of block size ({block_size})")
    
    # Get padding length from last byte
    padding_length = data[-1]
    
    # Validate padding length
    if padding_length < 1 or padding_length > block_size:
        raise ValueError(f"Invalid padding length: {padding_length}")
    
    # Validate all padding bytes have the same value
    padding_start = len(data) - padding_length
    for i in range(padding_start, len(data)):
        if data[i] != padding_length:
            raise ValueError("Invalid padding: padding bytes are not consistent")
    
    # Return data without padding
    return data[:padding_start]


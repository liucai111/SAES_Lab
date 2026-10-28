"""Multiple encryption, byte transport, PKCS#7 padding and CBC."""
import secrets
from .core import decrypt_block, encrypt_block, validate_word


def _keys(keys, count):
    keys = tuple(keys)
    if len(keys) != count:
        raise ValueError(f"必须提供 {count} 个 16 bit 密钥")
    for key in keys:
        validate_word(key, "密钥")
    return keys


def double_encrypt(block: int, key1: int, key2: int) -> int:
    return encrypt_block(encrypt_block(block, key1), key2)


def double_decrypt(block: int, key1: int, key2: int) -> int:
    return decrypt_block(decrypt_block(block, key2), key1)


def triple_encrypt(block: int, keys) -> int:
    """48-bit, three-key EEE: E_K3(E_K2(E_K1(P)))."""
    key1, key2, key3 = _keys(keys, 3)
    return encrypt_block(encrypt_block(encrypt_block(block, key1), key2), key3)


def triple_decrypt(block: int, keys) -> int:
    key1, key2, key3 = _keys(keys, 3)
    return decrypt_block(decrypt_block(decrypt_block(block, key3), key2), key1)


def _bytes(data):
    if not isinstance(data, bytes):
        raise ValueError("数据必须为 bytes")
    return data


def pad(data: bytes) -> bytes:
    """PKCS#7 with a 2-byte block: always append 1 or 2 bytes."""
    _bytes(data)
    count = 2 - len(data) % 2
    return data + bytes([count]) * count


def unpad(data: bytes) -> bytes:
    _bytes(data)
    if not data or len(data) % 2 or data[-1] not in (1, 2) or data[-data[-1]:] != bytes([data[-1]]) * data[-1]:
        raise ValueError("PKCS#7 填充无效：请检查密钥、IV、密文或是否发生篡改")
    return data[:-data[-1]]


def bytes_to_blocks(data: bytes) -> list[int]:
    _bytes(data)
    if len(data) % 2:
        raise ValueError("数据长度必须为 2 字节的整数倍；需要时先填充")
    return [int.from_bytes(data[index:index + 2], "big") for index in range(0, len(data), 2)]


def blocks_to_bytes(blocks) -> bytes:
    return b"".join(validate_word(block).to_bytes(2, "big") for block in blocks)


def encrypt_bytes(data: bytes, key: int, *, padding: bool = True) -> bytes:
    validate_word(key, "密钥")
    return blocks_to_bytes(encrypt_block(block, key) for block in bytes_to_blocks(pad(data) if padding else data))


def decrypt_bytes(data: bytes, key: int, *, padding: bool = True) -> bytes:
    validate_word(key, "密钥")
    plaintext = blocks_to_bytes(decrypt_block(block, key) for block in bytes_to_blocks(data))
    return unpad(plaintext) if padding else plaintext


def encrypt_ascii(text: str, key: int, *, padding: bool = True) -> bytes:
    """Strict 7-bit ASCII input. Ciphertext remains arbitrary 8-bit bytes."""
    try:
        data = text.encode("ascii")
    except UnicodeEncodeError as error:
        raise ValueError("本关只接收 ASCII 字符（U+0000~U+007F）") from error
    return encrypt_bytes(data, key, padding=padding)


def decrypt_ascii(data: bytes, key: int, *, padding: bool = True) -> str:
    plaintext = decrypt_bytes(data, key, padding=padding)
    try:
        return plaintext.decode("ascii")
    except UnicodeDecodeError as error:
        raise ValueError("解密结果不是 ASCII，请检查密钥或密文") from error


def cbc_encrypt(blocks, key: int, iv: int) -> list[int]:
    validate_word(key, "密钥")
    previous = validate_word(iv, "IV")
    output = []
    for block in blocks:
        previous = encrypt_block(validate_word(block) ^ previous, key)
        output.append(previous)
    return output


def cbc_decrypt(blocks, key: int, iv: int) -> list[int]:
    validate_word(key, "密钥")
    previous = validate_word(iv, "IV")
    output = []
    for block in blocks:
        block = validate_word(block, "密文分组")
        output.append(decrypt_block(block, key) ^ previous)
        previous = block
    return output


def cbc_encrypt_bytes(data: bytes, key: int, iv: int) -> bytes:
    return blocks_to_bytes(cbc_encrypt(bytes_to_blocks(pad(data)), key, iv))


def cbc_decrypt_bytes(data: bytes, key: int, iv: int) -> bytes:
    return unpad(blocks_to_bytes(cbc_decrypt(bytes_to_blocks(data), key, iv)))


def generate_iv() -> int:
    return secrets.randbits(16)

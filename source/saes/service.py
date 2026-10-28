"""Shared application service for the GUI, CLI and integration tests."""
import base64
import binascii
import re
from .core import encrypt_block, decrypt_block, encryption_trace, decryption_trace, expand_key
from .modes import (double_encrypt, double_decrypt, triple_encrypt, triple_decrypt,
                    encrypt_ascii, decrypt_ascii, cbc_encrypt, cbc_decrypt,
                    cbc_encrypt_bytes, cbc_decrypt_bytes)


def parse_word(text: str, width: int = 16) -> int:
    """Accept exact-width binary (optional 0b) or exact-width hex prefixed 0x."""
    if width not in (16, 32, 48):
        raise ValueError("位宽只支持 16、32、48")
    compact = "".join(text.split())
    if compact.lower().startswith("0x"):
        body, base, count, pattern = compact[2:], 16, width // 4, r"[0-9a-fA-F]+"
    else:
        body = compact[2:] if compact.lower().startswith("0b") else compact
        base, count, pattern = 2, width, r"[01]+"
    if len(body) != count or re.fullmatch(pattern, body) is None:
        raise ValueError(f"请输入恰好 {width} 位二进制，或 0x 开头的 {width // 4} 位十六进制")
    return int(body, base)


def parse_blocks(text: str) -> list[int]:
    """Binary blocks may be contiguous/whitespace separated; hex uses one 0x prefix per block."""
    if "0x" in text.lower():
        tokens = text.split()
        if not tokens or any(not token.lower().startswith("0x") for token in tokens):
            raise ValueError("十六进制分组须写作 0x1234 0xABCD")
        return [parse_word(token) for token in tokens]
    compact = "".join(text.split())
    if not compact or len(compact) % 16 or re.fullmatch("[01]+", compact) is None:
        raise ValueError("请输入非空的 16 位整数倍二进制串，或 0x 开头的分组")
    return [int(compact[index:index + 16], 2) for index in range(0, len(compact), 16)]


def parse_pairs(text: str) -> list[tuple[int, int]]:
    result = []
    for number, line in enumerate(text.splitlines(), 1):
        if not line.strip():
            continue
        parts = line.split()
        if len(parts) != 2:
            raise ValueError(f"第 {number} 行须为：明文 密文（两列，每列无内部空格）")
        result.append((parse_word(parts[0]), parse_word(parts[1])))
    if not result:
        raise ValueError("至少输入一行已知明密文对")
    return result


def word_result(value):
    return {"hex": f"0x{value:04X}", "binary": f"{value:016b}"}


def _decode_cipher(text, encoding):
    try:
        if encoding == "hex":
            return bytes.fromhex(text)
        if encoding == "base64":
            return base64.b64decode("".join(text.split()), validate=True)
        if encoding == "latin1":
            return text.encode("latin1")
    except (ValueError, UnicodeEncodeError, binascii.Error) as error:
        raise ValueError("密文编码无效，请检查 Hex、Base64 或 Latin-1 原始字节") from error
    raise ValueError("密文编码只支持 hex、base64、latin1")


def execute(operation: str, data: str, key: str, *, decrypt=False, iv="0x0000",
            padding=True, encoding="hex") -> dict:
    """Validated user-facing operation. No UI objects or file side effects."""
    if operation in ("block", "double", "triple"):
        width = {"block": 16, "double": 32, "triple": 48}[operation]
        combined_key = parse_word(key, width)
        keys = tuple((combined_key >> shift) & 65535 for shift in range(width - 16, -1, -16))
        block = parse_word(data)
        if operation == "block":
            value = decrypt_block(block, keys[0]) if decrypt else encrypt_block(block, keys[0])
        elif operation == "double":
            value = (double_decrypt if decrypt else double_encrypt)(block, *keys)
        else:
            value = (triple_decrypt if decrypt else triple_encrypt)(block, keys)
        result = word_result(value)
        if operation == "block":
            result["round_keys"] = [f"0x{k:04X}" for k in expand_key(keys[0])]
            result["trace"] = (decryption_trace if decrypt else encryption_trace)(block, keys[0])
        return result
    single_key = parse_word(key)
    if operation == "ascii":
        if decrypt:
            return {"plaintext": decrypt_ascii(_decode_cipher(data, encoding), single_key, padding=padding)}
        cipher = encrypt_ascii(data, single_key, padding=padding)
    elif operation == "cbc-blocks":
        blocks = parse_blocks(data)
        initial = parse_word(iv)
        output = (cbc_decrypt if decrypt else cbc_encrypt)(blocks, single_key, initial)
        return {"iv": word_result(initial), "blocks": [word_result(value) for value in output],
                "binary": "".join(f"{value:016b}" for value in output),
                "hex": " ".join(f"0x{value:04X}" for value in output)}
    elif operation == "cbc-text":
        initial = parse_word(iv)
        if decrypt:
            try:
                plaintext = cbc_decrypt_bytes(_decode_cipher(data, encoding), single_key, initial).decode("ascii")
            except UnicodeDecodeError as error:
                raise ValueError("解密结果不是 ASCII，请检查密钥、IV 或密文") from error
            return {"plaintext": plaintext, "iv": word_result(initial)}
        try:
            raw = data.encode("ascii")
        except UnicodeEncodeError as error:
            raise ValueError("文本请输入 ASCII 字符") from error
        cipher = cbc_encrypt_bytes(raw, single_key, initial)
    else:
        raise ValueError("未知操作")
    result = {"hex": cipher.hex().upper(), "base64": base64.b64encode(cipher).decode("ascii"),
              "latin1_raw": cipher.decode("latin1"), "latin1_repr": repr(cipher.decode("latin1")),
              "binary": "".join(f"{byte:08b}" for byte in cipher), "byte_length": len(cipher)}
    if operation == "cbc-text":
        result["iv"] = word_result(initial)
    return result

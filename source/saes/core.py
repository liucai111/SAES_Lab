"""S-AES 16-bit block cipher. State order: [s00, s10, s01, s11]."""
from functools import lru_cache

SBOX = (9, 4, 10, 11, 13, 1, 8, 5, 6, 2, 0, 3, 12, 14, 15, 7)
INV_SBOX = tuple(SBOX.index(value) for value in range(16))


def validate_word(value: int, name: str = "数据") -> int:
    """Reject non-integers, bools, negatives and values outside 16 bits."""
    if type(value) is not int or not 0 <= value <= 0xFFFF:
        raise ValueError(f"{name}必须是 0~65535 的整数（16 bit）")
    return value


def gf_mul(left: int, right: int) -> int:
    """Multiply nibbles in GF(2^4), modulo x^4+x+1 (0b10011)."""
    if type(left) is not int or type(right) is not int or not (0 <= left < 16 and 0 <= right < 16):
        raise ValueError("有限域乘法的两个参数必须为 0~15 的整数")
    result = 0
    for _ in range(4):
        if right & 1:
            result ^= left
        left <<= 1
        if left & 0x10:
            left ^= 0x13
        right >>= 1
    return result & 15


def sub_nibbles(state: int, inverse: bool = False) -> int:
    table = INV_SBOX if inverse else SBOX
    return sum(table[(state >> shift) & 15] << shift for shift in (12, 8, 4, 0))


def shift_rows(state: int) -> int:
    # Swap the lower row s10 and s11; this operation is its own inverse.
    return (state & 0xF0F0) | ((state & 0x0F00) >> 8) | ((state & 0x000F) << 8)


_MUL4 = tuple(gf_mul(4, value) for value in range(16))
_MUL9 = tuple(gf_mul(9, value) for value in range(16))
_MUL2 = tuple(gf_mul(2, value) for value in range(16))


def mix_columns(state: int, inverse: bool = False) -> int:
    first, second, third, fourth = ((state >> shift) & 15 for shift in (12, 8, 4, 0))
    if inverse:
        output = (_MUL9[first] ^ _MUL2[second], _MUL2[first] ^ _MUL9[second],
                  _MUL9[third] ^ _MUL2[fourth], _MUL2[third] ^ _MUL9[fourth])
    else:
        output = (first ^ _MUL4[second], _MUL4[first] ^ second,
                  third ^ _MUL4[fourth], _MUL4[third] ^ fourth)
    return sum(value << shift for value, shift in zip(output, (12, 8, 4, 0)))


@lru_cache(maxsize=4096)
def expand_key(key: int) -> tuple[int, int, int]:
    """Return round keys (K0,K1,K2); round constants are 0x80 and 0x30."""
    validate_word(key, "密钥")
    words = [key >> 8, key & 255]
    for constant in (0x80, 0x30):
        previous = words[-1]
        rotated_substituted = (SBOX[previous & 15] << 4) | SBOX[previous >> 4]
        next_word = words[-2] ^ constant ^ rotated_substituted
        words.extend((next_word, next_word ^ previous))
    return tuple((words[index] << 8) | words[index + 1] for index in (0, 2, 4))


def encrypt_block(plaintext: int, key: int) -> int:
    """Encrypt one 16-bit integer with one 16-bit key."""
    validate_word(plaintext, "明文")
    validate_word(key, "密钥")
    key0, key1, key2 = expand_key(key)
    state = plaintext ^ key0
    state = mix_columns(shift_rows(sub_nibbles(state))) ^ key1
    return shift_rows(sub_nibbles(state)) ^ key2


def decrypt_block(ciphertext: int, key: int) -> int:
    """Reverse encryption, including inverse MixColumns after K1 addition."""
    validate_word(ciphertext, "密文")
    validate_word(key, "密钥")
    key0, key1, key2 = expand_key(key)
    state = sub_nibbles(shift_rows(ciphertext ^ key2), inverse=True)
    state = mix_columns(state ^ key1, inverse=True)
    return sub_nibbles(shift_rows(state), inverse=True) ^ key0


def encryption_trace(plaintext: int, key: int) -> list[dict]:
    """Return every encryption state for teaching and debugging."""
    validate_word(plaintext, "明文")
    validate_word(key, "密钥")
    key0, key1, key2 = expand_key(key)
    state = plaintext
    records = [{"step": "Input", "hex": f"{state:04X}", "bits": f"{state:016b}"}]
    operations = (("AddRoundKey K0", lambda x: x ^ key0),
                  ("SubNib R1", sub_nibbles), ("ShiftRows R1", shift_rows),
                  ("MixColumns R1", mix_columns), ("AddRoundKey K1", lambda x: x ^ key1),
                  ("SubNib R2", sub_nibbles), ("ShiftRows R2", shift_rows),
                  ("AddRoundKey K2", lambda x: x ^ key2))
    for label, operation in operations:
        state = operation(state)
        records.append({"step": label, "hex": f"{state:04X}", "bits": f"{state:016b}"})
    return records


def decryption_trace(ciphertext: int, key: int) -> list[dict]:
    """Return the inverse round states in actual execution order."""
    validate_word(ciphertext, "密文")
    validate_word(key, "密钥")
    key0, key1, key2 = expand_key(key)
    state = ciphertext
    records = [{"step": "Input", "hex": f"{state:04X}", "bits": f"{state:016b}"}]
    operations = (("AddRoundKey K2", lambda x: x ^ key2),
                  ("InvShiftRows R2", shift_rows),
                  ("InvSubNib R2", lambda x: sub_nibbles(x, True)),
                  ("AddRoundKey K1", lambda x: x ^ key1),
                  ("InvMixColumns R1", lambda x: mix_columns(x, True)),
                  ("InvShiftRows R1", shift_rows),
                  ("InvSubNib R1", lambda x: sub_nibbles(x, True)),
                  ("AddRoundKey K0", lambda x: x ^ key0))
    for label, operation in operations:
        state = operation(state)
        records.append({"step": label, "hex": f"{state:04X}", "bits": f"{state:016b}"})
    return records


def key_schedule_trace(key: int) -> list[dict]:
    """Explain every expanded byte without changing the key schedule."""
    validate_word(key, "密钥")
    first, second = key >> 8, key & 255
    records = [{"step": "w0 高字节", "hex": f"{first:02X}", "bits": f"{first:08b}"},
               {"step": "w1 低字节", "hex": f"{second:02X}", "bits": f"{second:08b}"}]
    for index, constant in ((2, 0x80), (4, 0x30)):
        rotated = ((second & 15) << 4) | (second >> 4)
        substituted = (SBOX[rotated >> 4] << 4) | SBOX[rotated & 15]
        next_first = first ^ constant ^ substituted
        next_second = next_first ^ second
        for label, value in ((f"RotNib(w{index-1})", rotated),
                             ("SubNib", substituted), (f"RCON {index//2}", constant),
                             (f"w{index}", next_first), (f"w{index+1}", next_second)):
            records.append({"step": label, "hex": f"{value:02X}", "bits": f"{value:08b}"})
        first, second = next_first, next_second
    return records

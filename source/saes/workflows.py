"""UI-independent cross-check, intermediate rounds and CBC tampering experiments."""
import random
import time
from .core import encrypt_block, decrypt_block, validate_word
from .modes import cbc_encrypt, cbc_decrypt
from .service import parse_word, parse_blocks
from . import reference


def combine_keys(texts) -> str:
    """Join two or three separately entered 16-bit subkeys, highest key first."""
    texts = tuple(texts)
    if len(texts) not in (2, 3):
        raise ValueError("请提供两个或三个子密钥")
    values = []
    for index, text in enumerate(texts, 1):
        try:
            values.append(parse_word(text))
        except ValueError as error:
            raise ValueError(f"子密钥 K{index}：{error}") from error
    return "0x" + "".join(f"{value:04X}" for value in values)


def multiple_trace(block: int, keys, decrypt=False) -> list[dict]:
    validate_word(block)
    keys = tuple(keys)
    if len(keys) not in (2, 3):
        raise ValueError("多重加密需两个或三个子密钥")
    for key in keys:
        validate_word(key, "子密钥")
    state = block
    rows = [{"step": "输入分组", "hex": f"{state:04X}", "bits": f"{state:016b}"}]
    order = reversed(list(enumerate(keys, 1))) if decrypt else enumerate(keys, 1)
    for index, key in order:
        state = (decrypt_block if decrypt else encrypt_block)(state, key)
        rows.append({"step": f"{'解密' if decrypt else '加密'} K{index} ({key:04X})",
                     "hex": f"{state:04X}", "bits": f"{state:016b}"})
    return rows


def compare_peer(plaintext: str, key: str, peer_ciphertext: str) -> dict:
    plain, secret, peer = parse_word(plaintext), parse_word(key), parse_word(peer_ciphertext)
    ours = encrypt_block(plain, secret)
    decrypted = decrypt_block(peer, secret)
    return {"plaintext": f"0x{plain:04X}", "key": f"0x{secret:04X}",
            "local_cipher": f"0x{ours:04X}", "peer_cipher": f"0x{peer:04X}",
            "peer_decrypted": f"0x{decrypted:04X}",
            "passed": ours == peer and decrypted == plain,
            "evidence_type": "manually entered peer output; peer provenance not verified"}


def independent_check(count=1024, seed=20261020) -> dict:
    if type(count) is not int or not 1 <= count <= 10000:
        raise ValueError("对照样本数量须为1~10000的整数")
    generator = random.Random(seed)
    started = time.perf_counter()
    passed = 0
    failures = []
    for index in range(count):
        plain, key = generator.randrange(65536), generator.randrange(65536)
        ours, theirs = encrypt_block(plain, key), reference.encrypt(plain, key)
        ok = ours == theirs and reference.decrypt(ours, key) == plain and decrypt_block(theirs, key) == plain
        passed += int(ok)
        if not ok:
            failures.append({"index": index, "plaintext": plain, "key": key})
    return {"count": count, "passed": passed, "failed": count-passed, "seed": seed,
            "elapsed_seconds": time.perf_counter()-started, "failures": failures,
            "evidence_type": "same-host independent implementation; not an external group test"}


def cbc_tamper_compare(plaintext: str, key: str, iv: str, *, kind="xor", block_index=2,
                       value="0x0001") -> dict:
    """Compare a fresh CBC baseline to exactly one mutation. Index is 1-based."""
    blocks = parse_blocks(plaintext)
    secret, initial, change = parse_word(key), parse_word(iv), parse_word(value)
    cipher = cbc_encrypt(blocks, secret, initial)
    modified = cipher[:]
    modified_iv = initial
    if kind == "iv":
        modified_iv ^= change
    elif kind in ("xor", "replace"):
        if type(block_index) is not int or not 1 <= block_index <= len(cipher):
            raise ValueError(f"分组序号须为1~{len(cipher)}")
        offset = block_index-1
        modified[offset] = modified[offset] ^ change if kind == "xor" else change
    else:
        raise ValueError("未知的篡改方式")
    normal = cbc_decrypt(cipher, secret, initial)
    after = cbc_decrypt(modified, secret, modified_iv)
    rows = [{"index": i+1, "original": f"0x{a:04X}", "normal": f"0x{b:04X}",
             "modified": f"0x{c:04X}", "xor_delta": f"0x{a^c:04X}", "changed": a != c}
            for i, (a, b, c) in enumerate(zip(blocks, normal, after))]
    return {"kind": kind, "block_index": None if kind == "iv" else block_index,
            "change": f"0x{change:04X}", "key": f"0x{secret:04X}",
            "iv": f"0x{initial:04X}", "modified_iv": f"0x{modified_iv:04X}",
            "ciphertext": " ".join(f"0x{v:04X}" for v in cipher),
            "modified_ciphertext": " ".join(f"0x{v:04X}" for v in modified),
            "rows": rows, "changed_blocks": [row["index"] for row in rows if row["changed"]]}

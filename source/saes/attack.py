"""Full 2^16 x 2^16 double S-AES meet-in-the-middle search."""
import time
from .core import encrypt_block, decrypt_block, validate_word
from .modes import double_encrypt


def meet_in_the_middle(pairs, progress=None, cancelled=None) -> dict:
    """Return ALL matching (K1,K2). A single pair normally does not identify a unique key.

    progress(phase, done, total) is optional and runs in the caller's thread.
    cancelled() is optional; when true, raise InterruptedError without partial results.
    """
    pairs = tuple(tuple(pair) for pair in pairs)
    if not pairs or any(len(pair) != 2 for pair in pairs):
        raise ValueError("至少提供一组 (明文, 密文)，每组必须恰好有两个数")
    for plaintext, ciphertext in pairs:
        validate_word(plaintext, "已知明文")
        validate_word(ciphertext, "已知密文")
    started = time.perf_counter()
    plaintext, ciphertext = pairs[0]
    middle_table = {}
    candidates = []
    first_pair_matches = 0

    def update(phase, done):
        if done % 1024 == 0 or done == 65536:
            if cancelled and cancelled():
                raise InterruptedError("中间相遇攻击已取消")
            if progress:
                progress(phase, done, 65536)

    for key1 in range(65536):
        update("建立前向表", key1)
        # A list is essential: different K1 values can produce the same middle value.
        middle_table.setdefault(encrypt_block(plaintext, key1), []).append(key1)
    update("建立前向表", 65536)
    for key2 in range(65536):
        update("反向搜索", key2)
        middle = decrypt_block(ciphertext, key2)
        matches = middle_table.get(middle, ())
        first_pair_matches += len(matches)
        for key1 in matches:
            if all(double_encrypt(known_plain, key1, key2) == known_cipher
                   for known_plain, known_cipher in pairs[1:]):
                candidates.append((key1, key2))
    update("反向搜索", 65536)
    return {"candidates": candidates, "candidate_count": len(candidates),
            "first_pair_matches": first_pair_matches, "pair_count": len(pairs),
            "forward_keys": 65536, "backward_keys": 65536,
            "middle_values": len(middle_table), "elapsed_seconds": time.perf_counter() - started}

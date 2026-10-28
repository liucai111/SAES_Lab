"""Generate reproducible five-stage records; execute from the project root."""
import hashlib
import json
import platform
import sys
from datetime import datetime, timezone
from pathlib import Path
from saes.core import encrypt_block, decrypt_block, encryption_trace, expand_key
from saes.modes import (encrypt_ascii, decrypt_ascii, double_encrypt, double_decrypt,
                        triple_encrypt, triple_decrypt, cbc_encrypt, cbc_decrypt)
from saes.service import execute
from saes.attack import meet_in_the_middle
from tests import reference_saes as reference

ROOT = Path(__file__).resolve().parent


def hexes(values):
    return [f'0x{value:04X}' for value in values]


def main():
    destination = ROOT.parent / 'test_results'
    destination.mkdir(exist_ok=True)
    known = []
    inputs = [(0xD728, 0x4AF5), (0x6F6B, 0xA73B), (0, 0), (65535, 65535), (0x1234, 0x1A2B)]
    for plaintext, key in inputs:
        cipher = encrypt_block(plaintext, key)
        known.append({'plaintext': f'0x{plaintext:04X}', 'key': f'0x{key:04X}',
                      'ciphertext': f'0x{cipher:04X}', 'decrypted': f'0x{decrypt_block(cipher, key):04X}',
                      'reference_ciphertext': f'0x{reference.encrypt(plaintext, key):04X}',
                      'reference_decrypted': f'0x{reference.decrypt(cipher, key):04X}'})
    ascii_examples = []
    for text in ('', 'A', 'AB', 'ABC', 'Hello S-AES!', '  A\n'):
        record = execute('ascii', text, '0x4AF5')
        ascii_examples.append(dict(plaintext=text, ciphertext_hex=record['hex'],
                                   ciphertext_base64=record['base64'], ciphertext_latin1_repr=record['latin1_repr'],
                                   byte_length=record['byte_length'],
                                   decrypted=decrypt_ascii(bytes.fromhex(record['hex']), 0x4AF5)))
    plaintext, keys = 0x1234, (0x1A2B, 0x3C4D, 0x5E6F)
    double = double_encrypt(plaintext, *keys[:2])
    triple = triple_encrypt(plaintext, keys)
    pairs = [(plain, double_encrypt(plain, *keys[:2])) for plain in (0x1234, 0x5678, 0x9ABC)]
    (ROOT / 'pairs.txt').write_text(''.join(f'0x{p:04X} 0x{c:04X}\n' for p, c in pairs), encoding='utf-8')
    single = meet_in_the_middle(pairs[:1])
    multiple = meet_in_the_middle(pairs)
    (destination / 'mitm_single_candidates.json').write_text(json.dumps(
        {'candidate_count': single['candidate_count'],
         'candidates': [{'key1': f'0x{k1:04X}', 'key2': f'0x{k2:04X}'} for k1, k2 in single['candidates']]}, indent=2), encoding='utf-8')
    for result in (single, multiple):
        candidates = result.pop('candidates')
        result['contains_original_key'] = keys[:2] in candidates
        result['candidate_preview'] = [{'key1': f'0x{k1:04X}', 'key2': f'0x{k2:04X}'} for k1, k2 in candidates[:10]]
    blocks, key, iv = [0x1234, 0x5678, 0x9ABC, 0xDEF0], 0x4AF5, 0x1234
    cipher = cbc_encrypt(blocks, key, iv)
    flipped = cipher[:]
    flipped[1] ^= 1
    replaced = cipher[:]
    replaced[1] = 0
    flip_plain = cbc_decrypt(flipped, key, iv)
    replace_plain = cbc_decrypt(replaced, key, iv)
    report = {'generated_at_utc': datetime.now(timezone.utc).isoformat(), 'platform': platform.platform(),
              'python': sys.version, 'stage1': {'vectors': known,
              'round_keys': hexes(expand_key(0x4AF5)), 'trace': encryption_trace(0xD728, 0x4AF5)},
              'stage2': {'type': 'independent implementation comparison on same host',
                         'random_seed': 20261020, 'random_pairs_checked': 1024,
                         'external_group_cross_test': 'pending; no group B data supplied'},
              'stage3': {'examples': ascii_examples, 'raw_ok_cipher': encrypt_ascii('ok', 0xA73B, padding=False).hex().upper()},
              'stage4': {'plaintext': '0x1234', 'keys': hexes(keys), 'double_cipher': f'0x{double:04X}',
                         'double_decrypted': f'0x{double_decrypt(double, *keys[:2]):04X}',
                         'triple_cipher': f'0x{triple:04X}', 'triple_decrypted': f'0x{triple_decrypt(triple, keys):04X}',
                         'known_pairs': [{'plaintext': f'0x{p:04X}', 'ciphertext': f'0x{c:04X}'} for p, c in pairs],
                         'mitm_single': single, 'mitm_multiple': multiple},
              'stage5': {'key': f'0x{key:04X}', 'iv': f'0x{iv:04X}', 'plaintext': hexes(blocks),
                         'ciphertext': hexes(cipher), 'decrypted': hexes(cbc_decrypt(cipher, key, iv)),
                         'flip_second_cipher_lsb': {'ciphertext': hexes(flipped), 'decrypted': hexes(flip_plain),
                         'plaintext_xor_delta': hexes(a ^ b for a, b in zip(blocks, flip_plain))},
                         'replace_second_cipher_zero': {'ciphertext': hexes(replaced), 'decrypted': hexes(replace_plain),
                         'plaintext_xor_delta': hexes(a ^ b for a, b in zip(blocks, replace_plain))},
                         'flip_iv_lsb_decrypted': hexes(cbc_decrypt(cipher, key, iv ^ 1))}}
    (destination / 'experiments.json').write_text(json.dumps(report, ensure_ascii=True, indent=2), encoding='utf-8')
    checksums = {}
    for path in sorted(ROOT.rglob('*.py')):
        checksums[str(path.relative_to(ROOT))] = hashlib.sha256(path.read_bytes()).hexdigest()
    (destination / 'source_sha256.json').write_text(json.dumps(checksums, indent=2), encoding='utf-8')
    print(json.dumps({'stage4': report['stage4'], 'stage5': report['stage5']}, indent=2))


if __name__ == '__main__':
    main()

import json
import random
import subprocess
import sys
import unittest
from pathlib import Path
from saes.core import (SBOX, INV_SBOX, gf_mul, sub_nibbles, shift_rows, mix_columns,
                       encrypt_block, decrypt_block, expand_key, encryption_trace)
from saes.modes import *
from saes.service import execute, parse_word, parse_blocks, parse_pairs
from saes.attack import meet_in_the_middle
from tests import reference_saes as reference

ROOT = Path(__file__).resolve().parents[1]


class Stage1Basic(unittest.TestCase):
    def test_known_answers(self):
        for plaintext, key, expected in ((0xD728, 0x4AF5, 0x24EC), (0x6F6B, 0xA73B, 0x0738)):
            with self.subTest(p=plaintext, k=key):
                self.assertEqual(encrypt_block(plaintext, key), expected)
                self.assertEqual(decrypt_block(expected, key), plaintext)

    def test_key_schedule(self):
        self.assertEqual(expand_key(0x4AF5), (0x4AF5, 0xDD28, 0x87AF))
        self.assertEqual(expand_key(0xA73B), (0xA73B, 0x1C27, 0x7651))

    def test_trace(self):
        self.assertEqual([row['hex'] for row in encryption_trace(0xD728, 0x4AF5)],
                         ['D728', '9DDD', '2EEE', '2EEE', 'F633', '2B1B', 'A343', 'A343', '24EC'])

    def test_all_plaintexts_one_key(self):
        # Exhaust all 2^16 inputs, check inverse and permutation rather than sampled round trips.
        ciphertexts = set()
        for plaintext in range(65536):
            ciphertext = encrypt_block(plaintext, 0x4AF5)
            self.assertEqual(decrypt_block(ciphertext, 0x4AF5), plaintext)
            ciphertexts.add(ciphertext)
        self.assertEqual(len(ciphertexts), 65536)

    def test_all_keys_one_plaintext(self):
        for key in range(65536):
            self.assertEqual(decrypt_block(encrypt_block(0x1234, key), key), 0x1234)

    def test_component_inverses(self):
        self.assertEqual(tuple(INV_SBOX[SBOX[i]] for i in range(16)), tuple(range(16)))
        for word in range(65536):
            self.assertEqual(sub_nibbles(sub_nibbles(word), True), word)
            self.assertEqual(shift_rows(shift_rows(word)), word)
            self.assertEqual(mix_columns(mix_columns(word), True), word)

    def test_invalid_words(self):
        for value in (-1, 65536, True, 1.5, '1234', None):
            with self.subTest(value=value):
                with self.assertRaises(ValueError): encrypt_block(value, 0)
                with self.assertRaises(ValueError): encrypt_block(0, value)
                with self.assertRaises(ValueError): decrypt_block(value, 0)
                with self.assertRaises(ValueError): decrypt_block(0, value)

    def test_parsers(self):
        self.assertEqual(parse_word('1101 0111 0010 1000'), 0xD728)
        self.assertEqual(parse_word('0x4aF5'), 0x4AF5)
        self.assertEqual(parse_word('0b'+'1'*16), 65535)
        for text in ('1010', '2'*16, '0x123', '0x10000', '', '0xZZZZ'):
            with self.assertRaises(ValueError): parse_word(text)
        self.assertEqual(parse_blocks('0x1234 0xABCD'), [0x1234, 0xABCD])
        self.assertEqual(parse_blocks('0000000000000001'+'0000000000000010'), [1, 2])
        for text in ('', '0101', '0x1234 ABCD', '0x1234 0101010101010101'):
            with self.assertRaises(ValueError): parse_blocks(text)
        self.assertEqual(parse_pairs('0x1234 0x5678\n\n'), [(0x1234, 0x5678)])
        with self.assertRaises(ValueError): parse_pairs('')
        with self.assertRaises(ValueError): parse_pairs('0x1234 0x5678 extra')


class Stage2CrossImplementation(unittest.TestCase):
    def test_independent_matrix_implementation(self):
        randomizer = random.Random(20261020)
        for _ in range(1024):
            plaintext, key = randomizer.randrange(65536), randomizer.randrange(65536)
            expected = reference.encrypt(plaintext, key)
            self.assertEqual(encrypt_block(plaintext, key), expected)
            self.assertEqual(decrypt_block(expected, key), plaintext)
            self.assertEqual(reference.decrypt(encrypt_block(plaintext, key), key), plaintext)
            self.assertEqual(expand_key(key), tuple(reference.round_keys(key)))

    def test_all_finite_field_pairs(self):
        for a in range(16):
            for b in range(16):
                self.assertEqual(gf_mul(a, b), reference.multiply(a, b))
        for value in (-1, 16, True):
            with self.assertRaises(ValueError): gf_mul(value, 1)


class Stage3ASCII(unittest.TestCase):
    def test_padded_ascii_roundtrip(self):
        for text in ('', 'A', 'AB', 'ABC', 'Hello S-AES!', '  A\n', '\x00\x01', ''.join(map(chr, range(128)))):
            encrypted = encrypt_ascii(text, 0x4AF5)
            self.assertEqual(len(encrypted) % 2, 0)
            self.assertEqual(decrypt_ascii(encrypted, 0x4AF5), text)
            self.assertEqual(encrypted.decode('latin1').encode('latin1'), encrypted)

    def test_raw_two_byte_mode(self):
        self.assertEqual(encrypt_ascii('ok', 0xA73B, padding=False).hex(), '0738')
        self.assertEqual(decrypt_ascii(bytes.fromhex('0738'), 0xA73B, padding=False), 'ok')
        with self.assertRaises(ValueError): encrypt_ascii('A', 0, padding=False)
        with self.assertRaises(ValueError): encrypt_ascii('中文', 0)

    def test_all_cipher_byte_values_and_padding(self):
        raw = bytes(range(256))
        self.assertEqual(decrypt_bytes(encrypt_bytes(raw, 0x4AF5), 0x4AF5), raw)
        self.assertEqual(pad(b'AB'), b'AB\x02\x02')
        self.assertEqual(pad(b'A'), b'A\x01')
        self.assertEqual(unpad(pad(b'')), b'')
        for raw in (b'', b'A', b'AB\x02\x01\x02\x02X', b'AB\x00\x00', b'AB\x01\x02'):
            with self.assertRaises(ValueError): unpad(raw)
        with self.assertRaises(ValueError): decrypt_bytes(b'X', 0)

    def test_transport_encodings(self):
        encrypted = execute('ascii', 'Hello!', '0x4AF5')
        for encoding, field in (('hex', 'hex'), ('base64', 'base64'), ('latin1', 'latin1_raw')):
            self.assertEqual(execute('ascii', encrypted[field], '0x4AF5', decrypt=True, encoding=encoding)['plaintext'], 'Hello!')
        with self.assertRaises(ValueError): execute('ascii', '???', '0x4AF5', decrypt=True, encoding='base64')
        with self.assertRaises(ValueError): execute('ascii', 'GG', '0x4AF5', decrypt=True)


class Stage4Multiple(unittest.TestCase):
    def test_double_and_triple(self):
        randomizer = random.Random(414)
        for _ in range(256):
            plain, k1, k2, k3 = [randomizer.randrange(65536) for _ in range(4)]
            double = double_encrypt(plain, k1, k2)
            triple = triple_encrypt(plain, (k1, k2, k3))
            self.assertEqual(double, reference.encrypt(reference.encrypt(plain, k1), k2))
            self.assertEqual(triple, reference.encrypt(reference.encrypt(reference.encrypt(plain, k1), k2), k3))
            self.assertEqual(double_decrypt(double, k1, k2), plain)
            self.assertEqual(triple_decrypt(triple, (k1, k2, k3)), plain)
        with self.assertRaises(ValueError): triple_encrypt(0, (1, 2))
        with self.assertRaises(ValueError): execute('double', '0x1234', '0x1234')
        with self.assertRaises(ValueError): execute('triple', '0x1234', '0x12345678')

    def test_mitm_full_space(self):
        pairs = [(p, double_encrypt(p, 0x1A2B, 0x3C4D)) for p in (0x1234, 0x5678, 0x9ABC)]
        result = meet_in_the_middle(pairs)
        self.assertIn((0x1A2B, 0x3C4D), result['candidates'])
        self.assertEqual(result['forward_keys'], 65536)
        self.assertEqual(result['backward_keys'], 65536)
        for k1, k2 in result['candidates']:
            self.assertTrue(all(double_encrypt(p, k1, k2) == c for p, c in pairs))
        # Contradictory observations for a deterministic cipher cannot have a key.
        self.assertEqual(meet_in_the_middle([(0x1234, 0), (0x1234, 1)])['candidates'], [])

    def test_mitm_validation_cancel(self):
        for pairs in ([], [(0,)], [(0, 0, 0)], [(65536, 1)]):
            with self.assertRaises(ValueError): meet_in_the_middle(pairs)
        with self.assertRaises(InterruptedError): meet_in_the_middle([(0, 0)], cancelled=lambda: True)


class Stage5CBC(unittest.TestCase):
    def test_roundtrip_and_equation(self):
        blocks, key, iv = [0x1234, 0x5678, 0x9ABC, 0xDEF0], 0x4AF5, 0x1234
        cipher = cbc_encrypt(blocks, key, iv)
        self.assertEqual(cbc_decrypt(cipher, key, iv), blocks)
        previous = iv
        for plain, encrypted in zip(blocks, cipher):
            self.assertEqual(encrypted, reference.encrypt(plain ^ previous, key))
            previous = encrypted
        self.assertEqual(cbc_encrypt([], key, iv), [])
        self.assertEqual(cbc_decrypt([], key, iv), [])
        self.assertNotEqual(cipher, cbc_encrypt(blocks, key, iv ^ 1))

    def test_flip_cipher_bit(self):
        blocks, key, iv = [0x1234, 0x5678, 0x9ABC, 0xDEF0], 0x4AF5, 0x1234
        cipher = cbc_encrypt(blocks, key, iv)
        cipher[1] ^= 1
        actual = cbc_decrypt(cipher, key, iv)
        self.assertEqual(actual[0], blocks[0])
        self.assertNotEqual(actual[1], blocks[1])
        self.assertEqual(actual[2], blocks[2] ^ 1)
        self.assertEqual(actual[3], blocks[3])

    def test_replace_cipher_block(self):
        blocks, key, iv = [0x1234, 0x5678, 0x9ABC, 0xDEF0], 0x4AF5, 0x1234
        cipher = cbc_encrypt(blocks, key, iv)
        modified = cipher[:]
        modified[1] = 0
        actual = cbc_decrypt(modified, key, iv)
        self.assertEqual(actual[0], blocks[0])
        self.assertNotEqual(actual[1], blocks[1])
        self.assertEqual(actual[2], blocks[2] ^ cipher[1])
        self.assertEqual(actual[3], blocks[3])

    def test_flip_iv_bit(self):
        blocks = [0x1234, 0x5678, 0x9ABC, 0xDEF0]
        cipher = cbc_encrypt(blocks, 0x4AF5, 0x1234)
        self.assertEqual(cbc_decrypt(cipher, 0x4AF5, 0x1235), [blocks[0] ^ 1] + blocks[1:])

    def test_text_and_validation(self):
        for text in ('', 'A', 'Hello CBC!', '\x00ABC\x00', ' '):
            result = execute('cbc-text', text, '0x4AF5', iv='0x1234')
            actual = execute('cbc-text', result['hex'], '0x4AF5', iv='0x1234', decrypt=True)
            self.assertEqual(actual['plaintext'], text)
        with self.assertRaises(ValueError): cbc_encrypt([0], 0, 65536)
        with self.assertRaises(ValueError): cbc_decrypt([65536], 0, 0)
        with self.assertRaises(ValueError): execute('cbc-text', '中文', '0x4AF5')
        # The wrong IV corrupts the last padding byte of the one-block empty message.
        cipher = cbc_encrypt_bytes(b'', 0x4AF5, 0x1234)
        with self.assertRaises(ValueError): cbc_decrypt_bytes(cipher, 0x4AF5, 0x1235)


class IntegrationCLI(unittest.TestCase):
    def test_cli_encrypt_decrypt(self):
        def run(*args):
            return subprocess.run([sys.executable, '-m', 'saes', *args], cwd=ROOT,
                                  capture_output=True, text=True, encoding='utf-8')
        encrypted = run('block', '--data', '0xD728', '--key', '0x4AF5')
        self.assertEqual(encrypted.returncode, 0, encrypted.stderr)
        self.assertEqual(json.loads(encrypted.stdout)['hex'], '0x24EC')
        decrypted = run('block', '--data', '0x24EC', '--key', '0x4AF5', '--decrypt')
        self.assertEqual(json.loads(decrypted.stdout)['hex'], '0xD728')
        self.assertEqual(run('block', '--data', 'abc', '--key', '0x4AF5').returncode, 2)

    def test_gui_import_and_service(self):
        # Does not create a desktop window; native GUI manual tests are separate.
        from saes.gui import SAESApp, MODES
        self.assertEqual(len(MODES), 6)
        self.assertTrue(callable(SAESApp.start_attack))
        self.assertEqual(execute('double', '0x1234', '0x1A2B3C4D')['hex'], '0xF04D')
        self.assertEqual(execute('triple', execute('triple', '0x1234', '0x1A2B3C4D5E6F')['hex'],
                                 '0x1A2B3C4D5E6F', decrypt=True)['hex'], '0x1234')

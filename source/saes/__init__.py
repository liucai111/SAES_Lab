"""S-AES educational laboratory, standard-library-only runtime."""
from .core import encrypt_block, decrypt_block, expand_key, encryption_trace
from .modes import (double_encrypt, double_decrypt, triple_encrypt, triple_decrypt,
                    cbc_encrypt, cbc_decrypt, encrypt_ascii, decrypt_ascii)
from .attack import meet_in_the_middle
__version__ = "2.0.0"

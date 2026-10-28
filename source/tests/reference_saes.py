"""Independent matrix/polynomial oracle; deliberately imports nothing from saes.

This is same-host implementation comparison, not evidence of another group's work.
"""
_BOX = [0x9, 0x4, 0xA, 0xB, 0xD, 0x1, 0x8, 0x5,
        0x6, 0x2, 0x0, 0x3, 0xC, 0xE, 0xF, 0x7]


def multiply(a, b):
    polynomial = 0
    for position in range(4):
        if b & (1 << position):
            polynomial ^= a << position
    for degree in range(6, 3, -1):
        if polynomial & (1 << degree):
            polynomial ^= 0b10011 << (degree - 4)
    return polynomial


def round_keys(key):
    words = [key // 256, key % 256]
    for i in range(2, 6):
        if i % 2:
            words.append(words[i-2] ^ words[i-1])
        else:
            byte = words[i-1]
            transformed = _BOX[byte % 16] * 16 + _BOX[byte // 16]
            words.append(words[i-2] ^ transformed ^ (0x80 if i == 2 else 0x30))
    return [words[i] * 256 + words[i+1] for i in (0, 2, 4)]


def matrix(word):
    digits = [int(char, 16) for char in f'{word:04x}']
    return [[digits[0], digits[2]], [digits[1], digits[3]]]


def pack(state):
    return state[0][0] * 4096 + state[1][0] * 256 + state[0][1] * 16 + state[1][1]


def add(state, key):
    key_matrix = matrix(key)
    return [[state[row][col] ^ key_matrix[row][col] for col in range(2)] for row in range(2)]


def substitute(state, inverse=False):
    lookup = [_BOX.index(i) for i in range(16)] if inverse else _BOX
    return [[lookup[item] for item in row] for row in state]


def shift(state):
    return [state[0][:], state[1][::-1]]


def mix(state, inverse=False):
    coefficients = [[9, 2], [2, 9]] if inverse else [[1, 4], [4, 1]]
    return [[multiply(coefficients[row][0], state[0][col]) ^
             multiply(coefficients[row][1], state[1][col]) for col in range(2)] for row in range(2)]


def encrypt(plaintext, key):
    keys = round_keys(key)
    state = add(matrix(plaintext), keys[0])
    state = add(mix(shift(substitute(state))), keys[1])
    state = add(shift(substitute(state)), keys[2])
    return pack(state)


def decrypt(ciphertext, key):
    keys = round_keys(key)
    state = substitute(shift(add(matrix(ciphertext), keys[2])), True)
    state = mix(add(state, keys[1]), True)
    state = substitute(shift(state), True)
    return pack(add(state, keys[0]))

from functools import partial
from Crypto.Hash import SHA256

masks = [0b10000000, 0b11000000, 0b11100000, 0b11110000, 0b11111000, 0b11111100, 0b11111110]


def sha_xx(data, n_bits=16):
    """ Truncated SHA-XX hash with 0-padding to the closest byte """
    h = SHA256.SHA256Hash(data).digest()[:(n_bits+7)//8]
    mod = n_bits % 8
    if mod:
        h_tail = h[-1] & masks[mod-1]
        return h[:-1] + h_tail.to_bytes(1, "big")
    return h


def get_sha_xx(n_bits):
    """ Get SHA-XX function with embedded n_bits parameter """
    return partial(sha_xx, n_bits=n_bits)

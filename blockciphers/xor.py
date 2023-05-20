def xor(obj1, obj2) -> bytes:
    return bytes(a ^ b for a, b in zip(obj1, obj2))

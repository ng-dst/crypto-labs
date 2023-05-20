from ciphermode import CipherMode
from padding import PaddingType


class BlockCipher:
    """ Abstract class for a multi-mode block cipher """
    KEY_SIZE = ...
    BLOCK_SIZE = ...

    def __init__(self, mode=None, key=None):
        self._key = self._checkKey(key)
        self._mode = self._checkMode(mode)

    def setKey(self, key: bytes):
        self._key = self._checkKey(key)

    def setMode(self, mode: CipherMode):
        self._mode = self._checkMode(mode)

    def _checkKey(self, key):
        if key is not None:
            if not isinstance(key, bytes):
                raise TypeError("Key type must be bytes")
            if len(key) != self.KEY_SIZE:
                raise ValueError(f"Key length mismatch: expected {self.KEY_SIZE}, got {len(key)}")
        return key

    @staticmethod
    def _checkMode(mode):
        if mode is not None:
            if not isinstance(mode, CipherMode):
                raise TypeError("Mode type must be CipherMode")
        return mode

    def blockCipherEncrypt(self, data: bytes) -> bytes:
        """ Encryption box E(m,k) for a single block """
        ...

    def blockCipherDecrypt(self, data: bytes) -> bytes:
        """ Decryption box D(c,k) for a single block """
        ...

    def processBlockEncrypt(self, data: bytes, is_final_block: bool, padding: PaddingType) -> bytes:
        """ Single iteration: E(m,k) + apply chain mode (and padding) """
        ...

    def processBlockDecrypt(self, data: bytes, is_final_block: bool, padding: PaddingType) -> bytes:
        """ Single iteration: D(c,k) + apply chain mode (and unpad if needed) """
        ...

    def encrypt(self, data: bytes, iv: bytes = None) -> bytes:
        """ Main encryption method """
        ...

    def decrypt(self, data: bytes, iv: bytes = None) -> bytes:
        """ Main decryption method """
        ...

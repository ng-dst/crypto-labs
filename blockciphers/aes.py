from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes

from blockcipher import BlockCipher
from ciphermode import CipherMode
from padding import PaddingType
from xor import xor


class MyAES (BlockCipher):
    """ 128-bit AES implementation. Supported modes: ECB, CBC, CFB, OFB, CTR """
    KEY_SIZE = 16
    BLOCK_SIZE = 16
    CTR_NONCE_SIZE = 4
    CTR_IV_SIZE = 8
    CTR_SIZE = 4

    __aes_provider = None
    __last_block = None
    __ctr = None

    def __init__(self, mode=None, key=None, nonce=None):
        """ It is possible to set mode, key and nonce later"""
        super().__init__(mode, key)
        if key is not None:
            self.__aes_provider = AES.new(key, mode=AES.MODE_ECB)
        if nonce is None:
            self.__nonce = get_random_bytes(self.CTR_NONCE_SIZE)
        elif not isinstance(nonce, bytes) or len(nonce) != self.BLOCK_SIZE:
            raise ValueError(f"Invalid nonce, expected bytes of length {self.BLOCK_SIZE}")

    def setKey(self, key: bytes):
        self._key = self._checkKey(key)
        self.__aes_provider = AES.new(key, mode=AES.MODE_ECB)

    def _pad(self, data: bytes, padding: PaddingType) -> bytes:
        if padding == PaddingType.NON:
            return data
        if padding == PaddingType.PKCS7:
            res = (-len(data)) % self.BLOCK_SIZE
            if res == 0:
                res = self.BLOCK_SIZE
            data += chr(res).encode() * res
            return data
        else:
            raise NotImplementedError("Unsupported padding type")

    def _unpad(self, data: bytes, padding: PaddingType) -> bytes:
        if padding == PaddingType.NON:
            return data
        if padding == PaddingType.PKCS7:
            if len(data) % self.BLOCK_SIZE != 0:
                raise ValueError("Data length not divisible by block size")
            res = data[-1]
            return data[:self.BLOCK_SIZE - res]
        else:
            raise NotImplementedError("Unsupported padding type")

    def _ctr_inc(self) -> bytes:
        ctr_old = self.__ctr
        int_ctr = int.from_bytes(self.__ctr, byteorder='big')
        int_ctr += 1
        int_ctr &= (1 << (self.BLOCK_SIZE * 8)) - 1
        self.__ctr = int.to_bytes(int_ctr, self.BLOCK_SIZE, byteorder='big')
        return ctr_old

    @property
    def usedPadding(self) -> PaddingType:
        if self._mode in (CipherMode.ECB, CipherMode.CBC):
            return PaddingType.PKCS7
        if self._mode in (CipherMode.CFB, CipherMode.OFB, CipherMode.CTR):
            return PaddingType.NON
        raise ValueError("Can't find padding type for current cipher mode")

    def blockCipherEncrypt(self, data: bytes) -> bytes:
        if len(data) != self.BLOCK_SIZE:
            raise ValueError("Data length expected to be equal block size")
        return self.__aes_provider.encrypt(data)

    def blockCipherDecrypt(self, data: bytes) -> bytes:
        if len(data) != self.BLOCK_SIZE:
            raise ValueError("Data length expected to be equal block size")
        return self.__aes_provider.decrypt(data)

    def processBlockEncrypt(self, data: bytes, is_final_block: bool, padding: PaddingType) -> bytes:
        leftover = b''
        if len(data) > self.BLOCK_SIZE:
            raise ValueError("Expected only one block of data")
        if is_final_block:
            data = self._pad(data, padding)
            if len(data) == 2*self.BLOCK_SIZE:
                data, leftover = data[:self.BLOCK_SIZE], data[self.BLOCK_SIZE:]

        if self._mode in (CipherMode.ECB, CipherMode.CBC) or not is_final_block:
            if len(data) != self.BLOCK_SIZE:
                raise ValueError("Data length must be equal to block")

        # inspired from the example in tg chat
        if self._mode == CipherMode.ECB:
            res = self.blockCipherEncrypt(data)
            if leftover: leftover = self.blockCipherEncrypt(leftover)

        elif self._mode == CipherMode.CBC:
            self.__last_block = self.blockCipherEncrypt(xor(data, self.__last_block))
            res = self.__last_block
            if leftover: leftover = self.blockCipherEncrypt(xor(leftover, res))

        elif self._mode == CipherMode.CFB:
            self.__last_block = xor(data, self.blockCipherEncrypt(self.__last_block)[:len(data)])
            res = self.__last_block
            if leftover: leftover = xor(leftover, self.blockCipherEncrypt(res))

        elif self._mode == CipherMode.OFB:
            self.__last_block = self.blockCipherEncrypt(self.__last_block)
            res = xor(data, self.__last_block[:len(data)])
            if leftover: leftover = xor(leftover, self.blockCipherEncrypt(self.__last_block))

        elif self._mode == CipherMode.CTR:
            res = xor(data, self.blockCipherEncrypt(self._ctr_inc())[:len(data)])
            if leftover: leftover = xor(leftover, self.blockCipherEncrypt(self._ctr_inc()))

        else:
            raise NotImplementedError("Unsupported cipher mode")

        return res + leftover

    def processBlockDecrypt(self, data: bytes, is_final_block: bool, padding: PaddingType) -> bytes:
        if len(data) > self.BLOCK_SIZE:
            raise ValueError("Only one block of data expected")
        if self._mode in (CipherMode.ECB, CipherMode.CBC) or not is_final_block:
            if len(data) != self.BLOCK_SIZE:
                raise ValueError("Data length expected to be equal block size")

        if self._mode == CipherMode.ECB:
            res = self.blockCipherDecrypt(data)

        elif self._mode == CipherMode.CBC:
            res = xor(self.blockCipherDecrypt(data), self.__last_block)
            self.__last_block = data

        elif self._mode == CipherMode.CFB:
            res = xor(data, self.blockCipherEncrypt(self.__last_block)[:len(data)])
            self.__last_block = data

        elif self._mode == CipherMode.OFB:
            self.__last_block = self.blockCipherEncrypt(self.__last_block)
            res = xor(data, self.__last_block[:len(data)])

        elif self._mode == CipherMode.CTR:
            res = xor(data, self.blockCipherEncrypt(self._ctr_inc())[:len(data)])

        else:
            raise NotImplementedError("Unsupported cipher mode")

        if is_final_block:
            return self._unpad(res, padding)
        else:
            return res

    def encrypt(self, data: bytes, iv: bytes = None) -> tuple:
        iv_len = self.CTR_IV_SIZE if self._mode == CipherMode.CTR else self.BLOCK_SIZE
        if iv is None:
            iv = get_random_bytes(iv_len)
        if len(iv) != iv_len:
            raise ValueError(f"Invalid IV length: expected {iv_len}, got {len(iv)}")

        padding = self.usedPadding
        self.__last_block = iv
        if self._mode == CipherMode.CTR:
            self.__ctr = self.__nonce + iv + bytes(self.CTR_SIZE)
            iv = self.__ctr

        blocks_count = (len(data) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        blocks = (data[i:i+self.BLOCK_SIZE] for i in range(0, len(data), self.BLOCK_SIZE))
        enc = (self.processBlockEncrypt(block, ind + 1 == blocks_count, padding) for ind, block in enumerate(blocks))
        return iv, b''.join(enc)

    def decrypt(self, data: bytes, iv: bytes = None) -> bytes:
        if iv is None and self._mode != CipherMode.ECB:
            raise ValueError("No IV specified for block cipher mode")

        padding = self.usedPadding
        if padding == PaddingType.PKCS7 and len(data) % self.BLOCK_SIZE != 0:
            raise ValueError("Unpadded ciphertext when padding is set")

        # treating IV as CTR block when operating in CTR mode
        self.__ctr = iv
        self.__last_block = iv

        blocks_count = (len(data) + self.BLOCK_SIZE - 1) // self.BLOCK_SIZE
        blocks = (data[i:i + self.BLOCK_SIZE] for i in range(0, len(data), self.BLOCK_SIZE))
        dec = (self.processBlockDecrypt(block, ind + 1 == blocks_count, padding) for ind, block in enumerate(blocks))
        return b''.join(dec)

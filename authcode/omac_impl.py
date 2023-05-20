from Crypto.Cipher import AES

from mac_interface import MacInterface


class OMAC (MacInterface):
    """ Implementation of CMAC calculator (AES) """

    KEY_LENGTH = 16
    _BSIZE = 16
    _ZERO = bytes(16)

    def __init__(self, key: bytes = None):
        """ Initialize key if given, initial state is 0^128 """
        self._key = self.__k1 = self.__k2 = None
        self._state = bytes(self._BSIZE)
        self._aes_provider = None
        self._last_block = None
        if key is not None:
            self.setKey(key)

    def __generateSubkeys(self) -> (bytes, bytes):
        """
        Subroutine to generate k1, k2 for CMAC

        input: key (128-bit),
        output: k1, k2 (128-bit).

        ZERO = 0^128,
        RB   = 0x87 = 0^120 10000111.

        1. L = AES-128(key, 0^128)

        2. if MSB(L) == 0:
             k1 = L << 1
           else:
             k1 = (L << 1) xor RB

        3. if MSB(k1) == 0:
             k2 = k1 << 1
           else:
             k2 = (k1 << 1) xor RB

        4. return k1, k2

        """
        mask = (1 << (self._BSIZE*8)) - 1
        rb = 0x87

        L = self._aes_provider.encrypt(self._ZERO)  # AesBlockEncrypt(self._ZERO, self._key)
        L = int.from_bytes(L, byteorder='big')

        k1 = (L << 1) & mask
        if L >> 127 == 1:
            k1 ^= rb

        k2 = (k1 << 1) & mask
        if k1 >> 127 == 1:
            k2 ^= rb

        k1 = k1.to_bytes(self._BSIZE, byteorder='big')
        k2 = k2.to_bytes(self._BSIZE, byteorder='big')

        return k1, k2

    def __encLastBlock(self) -> bytes:
        """
        Process last block - pad & xor
        if padding is needed:   pad(block) xor k2
        else:   block xor k1

        :return: processed block
        """
        if self.__k1 is None:
            raise ValueError("Key is not set")

        lb = self._last_block
        if not lb:
            lb = b''
            need_padding = True
        elif len(lb) == self._BSIZE:
            need_padding = False
        else:
            need_padding = True

        if need_padding:
            block = self._pad(lb)
            block = self._xor(block, self.__k2)
        else:
            block = self._xor(lb, self.__k1)

        return block

    @staticmethod
    def _xor(obj1: bytes, obj2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(obj1, obj2))

    def _pad(self, msg: bytes):
        """ 10...000 padding """
        pad_len = self._BSIZE - len(msg)
        if pad_len <= 0:
            return msg
        return msg + b'\x80' + b'\x00' * (pad_len - 1)

    # Interface implementation

    def setKey(self, key: bytes):
        if len(key) != self.KEY_LENGTH:
            raise ValueError("Invalid key length")
        self._key = key
        self._aes_provider = AES.new(key, AES.MODE_ECB)
        self.__k1, self.__k2 = self.__generateSubkeys()

    def addBlock(self, block: bytes):
        """
        Update internal state with a new block of message

        input: M (128-bit block)

        y = STATE xor M
        STATE = AES(y, key)

        this method works with 1-block delay in order to allow to finalize MAC properly
        """
        if self._key is None:
            raise ValueError("Key is not set")
        if self._last_block is not None:
            y = self._xor(self._state, self._last_block)
            self._state = self._aes_provider.encrypt(y)  # AesBlockEncrypt(y, self._key)
            if len(self._last_block) != self._BSIZE:
                raise OverflowError("Cannot append a new block after an incomplete block")
        self._last_block = block

    def finalize(self) -> bytes:
        """
        Returns the resultant tag of the given message

        :return: MAC of the message given with addBlock()
        """
        block = self.__encLastBlock()
        y = self._xor(self._state, block)
        return self._aes_provider.encrypt(y)  # AesBlockEncrypt(y, self._key)

    def computeMac(self, data: bytes) -> bytes:
        """
        Compute MAC for arbitrary message

        :param data: message to compute MAC from
        :return: 128-bit tag
        """
        if self._key is None:
            raise ValueError("Key is not set")

        blocks = [data[i:i+self._BSIZE] for i in range(0, len(data), self._BSIZE)]
        mac_provider = OMAC(self._key)
        for block in blocks:
            mac_provider.addBlock(block)
        return mac_provider.finalize()

    def verifyMac(self, data: bytes, tag: bytes) -> bool:
        """
        Verify MAC for arbitrary message

        :param data: message
        :param tag: MAC value to verify
        :return: True / False, whether MAC is valid
        """
        true_mac = self.computeMac(data)
        return true_mac == tag

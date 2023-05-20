from Crypto.Hash import SHA256

from mac_interface import MacInterface


class HMAC (MacInterface):
    """ Implementation of HMAC calculator (sha256) """

    _BSIZE = 64

    def __init__(self, key: bytes = None):
        """ Initialize key if given, initial state is 0^128 """
        self._key = None
        self._i_key_pad = None
        self._o_key_pad = None
        self.__i_sha_provider = None
        self._last_block = None
        if key is not None:
            self.setKey(key)

    @staticmethod
    def _xor(obj1: bytes, obj2: bytes) -> bytes:
        return bytes(a ^ b for a, b in zip(obj1, obj2))

    def _computeBlockKey(self, key):
        """
        Compute Block-sized key.
        len(key) > BLOCK_SIZE  ->  sha256(key)
        else  ->  key + padding with 0's

        :return: 512-bit key
        """
        if len(key) > self._BSIZE:
            sha = SHA256.new(key)
            return sha.digest()
        return key + b'\x00'*(self._BSIZE - len(key))

    # Interface implementation

    def setKey(self, key: bytes):
        """ Key setter, pre-computes initial sha256 state """
        self._key = key
        block_key = self._computeBlockKey(key)
        self._o_key_pad = self._xor(block_key, b'\x5c'*self._BSIZE)
        self._i_key_pad = self._xor(block_key, b'\x36'*self._BSIZE)
        self.__i_sha_provider = SHA256.new(self._i_key_pad)

    def addBlock(self, block: bytes):
        """
        Update internal state with a new block of message

        input: M (512-bit block)

        updates SHA state to compute  sha256( i_key_pad + message )
        """
        if self._key is None:
            raise ValueError("Key is not set")
        if self._last_block is not None and len(self._last_block) != self._BSIZE:
            raise OverflowError("Cannot append a new block after an incomplete (final) block")
        self._last_block = block
        self.__i_sha_provider.update(block)

    def finalize(self) -> bytes:
        """
        Returns the resultant tag of the given message

        computes  sha256( o_key_pad + i_sha256_state )
        where i_256_state = sha256( i_key_pad + message )

        :return: MAC of the message given with addBlock()
        """
        if self._key is None:
            raise ValueError("Key is not set")
        i_hash = self.__i_sha_provider.digest()
        return SHA256.new(self._o_key_pad + i_hash).digest()

    def computeMac(self, data: bytes) -> bytes:
        """
        Compute MAC for arbitrary message

        :param data: message to compute MAC from
        :return: 128-bit tag
        """
        blocks = [data[i:i+self._BSIZE] for i in range(0, len(data), self._BSIZE)]
        mac_provider = HMAC(self._key)
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

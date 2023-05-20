from Crypto.Cipher import AES

from omac_impl import OMAC


class TMAC (OMAC):
    """ Implementation of 64-bit Truncated MAC (TCBC) based on OMAC """

    KEY_LENGTH = 16
    _BSIZE = 16
    _ZERO = bytes(16)
    _MAC_LEN = 8

    def _pad(self, msg: bytes):
        """ PCKS7 padding """
        pad_len = self._BSIZE - len(msg)
        if pad_len < 0:
            return msg
        if pad_len == 0:
            pad_len = self._BSIZE
        return msg + pad_len.to_bytes(1, byteorder='big') * pad_len

    # Interface override

    def finalize(self) -> bytes:
        """
        Returns the resultant tag of the given message

        :return: Truncated MAC of the message given with addBlock()
        """
        if self._key is None:
            raise ValueError("Key is not set")
        if self._last_block is None:
            self._last_block = b''
        block = self._pad(self._last_block)

        if len(block) == 2*self._BSIZE:
            prev_block, block = block[:self._BSIZE], block[self._BSIZE:]
            y = self._xor(self._state, prev_block)
            self._state = self._aes_provider.encrypt(y)  # AesBlockEncrypt(y, self._key)

        y = self._xor(self._state, block)
        return self._aes_provider.encrypt(y)[:self._MAC_LEN]

    def computeMac(self, data: bytes) -> bytes:
        """
        Compute TMAC for arbitrary message

        :param data: message to compute MAC from
        :return: 64-bit tag
        """
        if self._key is None:
            raise ValueError("Key is not set")
        blocks = [data[i:i+self._BSIZE] for i in range(0, len(data), self._BSIZE)]
        mac_provider = TMAC(self._key)
        for block in blocks:
            mac_provider.addBlock(block)
        return mac_provider.finalize()

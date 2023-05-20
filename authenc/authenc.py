from Crypto.Cipher import AES
from Crypto.Hash import HMAC
from Crypto.Util import Counter

from encmode import EncryptorMode


class AuthenticEncryptor:

    AES_KEY_LENGTH = 16
    BLOCK_SIZE = 16

    def __init__(self, mode: EncryptorMode, key: bytes = None):
        self.mode = mode
        self._aes_provider = None
        self._hmac_provider = None
        self._key_enc = None
        self._key_mac = None
        self._is_first_block = True
        self._iv = None
        self._ctr = None
        if key is not None:
            self.setKey(key)

    def setKey(self, key: bytes):
        """ Key setter:  AES_Key(16) || AES_IV(16) || HMAC_Key(any) """
        if len(key) < self.AES_KEY_LENGTH + self.BLOCK_SIZE + 1:
            raise ValueError(f"Key is too short ({len(key)} bytes), minimum length is {self.AES_KEY_LENGTH+self.BLOCK_SIZE+1} bytes")
        aes_key = key[:self.AES_KEY_LENGTH]
        aes_iv = key[self.AES_KEY_LENGTH:self.AES_KEY_LENGTH + self.BLOCK_SIZE]
        hmac_key = key[self.AES_KEY_LENGTH + self.BLOCK_SIZE:]
        self.setKeyAes(aes_key, aes_iv)
        self.setKeyMac(hmac_key)

    def setKeyAes(self, key: bytes, iv: bytes):
        """ AES-CTR key setter:  Key (16 bytes),  IV (16 bytes) """
        if len(key) != self.AES_KEY_LENGTH or len(iv) != self.BLOCK_SIZE:
            raise ValueError("Incorrect AES key/iv length")
        self._key_enc = key
        self._iv = iv
        self._ctr = Counter.new(8*self.BLOCK_SIZE, initial_value=int.from_bytes(iv, 'big'))
        self._aes_provider = AES.new(key, AES.MODE_CTR, counter=self._ctr)

    def setKeyMac(self, key: bytes):
        """ HMAC key setter:  Key (any bytes) """
        self._key_mac = key
        self._hmac_provider = HMAC.new(key)
        self._is_first_block = True

    def addBlock(self, block: bytes, is_final: bool = False):
        """ Process one block of message and update HMAC state. Last block should be passed with is_final=1 """
        if self._key_enc is None or self._key_mac is None:
            raise ValueError("Key is not set")

        if self.mode == EncryptorMode.Encrypt:
            if self._is_first_block:
                self._hmac_provider.update(self._iv)

            block = self._aes_provider.encrypt(block)
            self._hmac_provider.update(block)

            if is_final:
                # appending HMAC message tag
                block += self._hmac_provider.digest()

            if self._is_first_block:
                # adding IV prefix in the beginning of message
                block = self._iv + block
                self._is_first_block = False

            return block

        elif self.mode == EncryptorMode.Decrypt:
            if self._is_first_block:
                # retrieving IV from the first block
                self.setKeyAes(self._key_enc, iv=block)
                self._hmac_provider.update(block)
                self._is_first_block = False
                return b''

            if is_final:
                # now just check HMAC
                self._hmac_provider.verify(block)
                return b''
            else:
                # standard block decryption
                self._hmac_provider.update(block)
                dec = self._aes_provider.decrypt(block)
                return dec

        else:
            raise NotImplementedError("Unknown encryptor mode")

    def processData(self, data: bytes):
        """ Process an arbitrary message (separately from current state) """
        def split_blocks(msg: bytes):
            return [msg[i:i + self.BLOCK_SIZE] for i in range(0, len(msg), self.BLOCK_SIZE)]

        if self._key_enc is None or self._key_mac is None:
            raise ValueError("Key is not set")

        if self.mode == EncryptorMode.Decrypt:
            data, mac = data[:-self.BLOCK_SIZE], data[-self.BLOCK_SIZE:]
            blocks = split_blocks(data)
            blocks.append(mac)
        else:
            blocks = split_blocks(data)

        res = []
        ae_provider = AuthenticEncryptor(self.mode, self._key_enc + self._iv + self._key_mac)

        for block in blocks[:-1]:
            res.append(ae_provider.addBlock(block))
        res.append(ae_provider.addBlock(blocks[-1], is_final=True))

        res = b''.join(res)
        return res

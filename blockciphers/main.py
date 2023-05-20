#!/usr/bin/env python3

from binascii import hexlify, unhexlify

from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad

from aes import MyAES
from ciphermode import CipherMode


# task 2.5

def test_compare_cbc():
    print('Task 2.5, CBC Test:')
    pt = b'... and drink some tea.'
    key = get_random_bytes(MyAES.KEY_SIZE)
    iv = get_random_bytes(MyAES.KEY_SIZE)
    aes1 = MyAES(mode=CipherMode.CBC, key=key)
    aes2 = AES.new(mode=AES.MODE_CBC, key=key, iv=iv)
    pt_padded = pad(pt, MyAES.BLOCK_SIZE)
    ct1 = aes1.encrypt(pt, iv=iv)[1]
    ct2 = aes2.encrypt(pt_padded)
    print(f'Plaintext:     {pt}')
    print(f'Key:           {key}')
    print(f'IV:            {iv}')
    print(f'My AES-CBC:    {ct1}')
    print(f'PyCryptoDome:  {ct2}')
    print()


# task 3
def test_cbc():
    print('Task 3, CBC Test:')
    key = unhexlify(b'140b41b22a29beb4061bda66b6747e14')
    aes = MyAES(mode=CipherMode.CBC, key=key)

    ct1 = unhexlify(b'4ca00ff4c898d61e1edbf1800618fb2828a226d160dad07883d04e008a7897ee2e4b7465d5290d0c0e6c6822236e1daafb94ffe0c5da05d9476be028ad7c1d81')
    print(aes.decrypt(ct1[16:], iv=ct1[:16]).decode())

    ct2 = unhexlify(b'5b68629feb8606f9a6667670b75b38a5b4832d0f26e1ab7da33249de7d4afc48e713ac646ace36e872ad5fb8a512428a6e21364b0c374df45503473c5242a253')
    print(aes.decrypt(ct2[16:], iv=ct2[:16]).decode())
    print()


def test_ctr():
    print('Task 3, CTR Test:')
    key = unhexlify(b'36f18357be4dbd77f050515c73fcf9f2')
    aes = MyAES(mode=CipherMode.CTR, key=key)

    ct1 = unhexlify(b'69dda8455c7dd4254bf353b773304eec0ec7702330098ce7f7520d1cbbb20fc388d1b0adb5054dbd7370849dbf0b88d393f252e764f1f5f7ad97ef79d59ce29f5f51eeca32eabedd9afa9329')
    print(aes.decrypt(ct1[16:], iv=ct1[:16]).decode())

    ct2 = unhexlify(b'770b80259ec33beb2561358a9f2dc617e46218c0a53cbeca695ae45faa8952aa0e311bde9d4e01726d3184c34451')
    print(aes.decrypt(ct2[16:], iv=ct2[:16]).decode())
    print()


# task 4

def test_modes():
    # 2.5 blocks sized text
    pt = b'Eat some more of these soft french buns...'
    print('Task 4:')
    print(f'plaintext: "{pt.decode()}" ({len(pt)} bytes)')
    key = get_random_bytes(MyAES.KEY_SIZE)
    aes = MyAES(key=key)
    print(f'Key: {hexlify(key)} (random)\n')

    # ECB
    aes.setMode(CipherMode.ECB)
    print(f'Mode: ECB')
    ct = aes.encrypt(pt)[1]
    print(f'ciphertext: {hexlify(ct)}')
    print(f'decrypted: {aes.decrypt(ct)}\n')

    # CBC
    aes.setMode(CipherMode.CBC)
    print(f'Mode: CBC')
    run_test(aes, pt)

    # CFB
    aes.setMode(CipherMode.CFB)
    print(f'Mode: CFB')
    run_test(aes, pt)

    # OFB
    aes.setMode(CipherMode.OFB)
    print(f'Mode: OFB')
    run_test(aes, pt)

    aes.setMode(CipherMode.CTR)
    print(f'Mode: CTR')
    run_test(aes, pt)


def run_test(aes, pt):
    iv, ct = aes.encrypt(pt, iv=None)
    print(f'iv / ctr block: {hexlify(iv)}')
    print(f'ciphertext: {hexlify(ct)}')
    print(f'decrypted: {aes.decrypt(ct, iv)}\n')


if __name__ == '__main__':
    test_compare_cbc()
    test_cbc()
    test_ctr()
    test_modes()

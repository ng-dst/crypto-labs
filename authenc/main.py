#!/usr/bin/env python3

from binascii import hexlify
from Crypto.Random import get_random_bytes

from authenc import AuthenticEncryptor
from encmode import EncryptorMode

default_size = 100 * 1024 * 1024
enc_key = b'super-secret-key'
iv = b'AAAABBBBCCCCDDDD'
mac_key = b'sample_mac_key'


def test_enc(size=default_size):
    print(f"[*] Generating {size} bytes of data...")
    data = get_random_bytes(size)
    print(f"  Data: {hexlify(data[:32])}...")
    print("[*] Initializing AuthenticEncryptor...")
    encryptor = AuthenticEncryptor(EncryptorMode.Encrypt, key=enc_key + iv + mac_key)
    print("[*] Encrypting data...")
    enc = encryptor.processData(data)
    print(f"[+] Encryption is done!\n  MAC:  {hexlify(enc[-16:])}    Enc:  {hexlify(enc[:32])}...")
    print(f"[*] Decrypting and verifying...")
    decryptor = AuthenticEncryptor(EncryptorMode.Decrypt, key=enc_key + bytes(16) + mac_key)
    dec = decryptor.processData(enc)
    print(f"[+] Decryption is done! MAC is valid.\n  Dec:  {hexlify(dec[:32])}...")


test_enc(size=7)

"""
[*] Generating 104857600 bytes of data...
  Data: b'3d7e45bbde2e0c3880875156240fae92bf7f372ff018b31bc00145cc5e7495e9'...
[*] Initializing AuthenticEncryptor...
[*] Encrypting data...
[+] Encryption is done!
  MAC:  b'a5da7dd62871ee4d45ae6b782eba3c96'    Enc:  b'41414141424242424343434344444444d015b1ecee92d4919e09283115d1c907'...
[*] Decrypting and verifying...
[+] Decryption is done! MAC is valid.
  Dec:  b'3d7e45bbde2e0c3880875156240fae92bf7f372ff018b31bc00145cc5e7495e9'...
"""
from Crypto.Hash import CMAC, HMAC
from Crypto.Cipher import AES
from Crypto.Hash import SHA256

from binascii import unhexlify, hexlify

from omac_impl import OMAC as MyOMAC
from tmac_impl import TMAC as MyTMAC
from hmac_impl import HMAC as MyHMAC

key = unhexlify(b"B8B34DA2D4C4D578D8494390E3DFE7A7")
msg1 = b'Test MAC'
msg2 = b'sixteen-byte-msg'
msg3 = b'Eat some more of these soft french buns'
msg3a= b'Eat some more of these soft french buos'  # changed 1 bit
msg4 = b'HMAC does not encrypt the message. Instead, the message (encrypted or not) must be sent alongside the HMAC ' \
       b'hash. Parties with the secret key will hash the message again themselves'


def testOMAC(msg):
    omac_lib = CMAC.new(key, ciphermod=AES)
    omac_my = MyOMAC(key)
    blocks = [msg[i:i+16] for i in range(0, len(msg), 16)]
    for block in blocks:
        omac_lib.update(block)
        omac_my.addBlock(block)
    print(f"msg:    {msg}")
    print(f"OMAC lib: {omac_lib.hexdigest()}")
    print(f"OMAC my:  {hexlify(omac_my.finalize()).decode()}")
    print()


def testHMAC(msg):
    hmac_lib = HMAC.new(key, digestmod=SHA256)
    hmac_my = MyHMAC(key)
    blocks = [msg[i:i+64] for i in range(0, len(msg), 64)]
    for block in blocks:
        hmac_lib.update(block)
        hmac_my.addBlock(block)
    print(f"msg:    {msg}")
    print(f"HMAC lib: {hmac_lib.hexdigest()}")
    print(f"HMAC my:  {hexlify(hmac_my.finalize()).decode()}")
    print()


def testModifiedNotValid(msg, msg_mod):
    omac = MyOMAC(key)
    tmac = MyTMAC(key)
    hmac = MyHMAC(key)
    true_omac = omac.computeMac(msg)
    true_tmac = tmac.computeMac(msg)
    true_hmac = hmac.computeMac(msg)
    print(f"Message: {msg}  ({bin(msg[0])[2:].zfill(8)} ... {' '.join(bin(i)[2:].zfill(8) for i in msg[-3:])})")
    print(f"Modded:  {msg_mod}  ({bin(msg_mod[0])[2:].zfill(8)} ... {' '.join(bin(i)[2:].zfill(8) for i in msg_mod[-3:])})")
    print(f"Verify OMAC: {omac.verifyMac(msg_mod, true_omac)}")
    print(f"Verify TMAC: {tmac.verifyMac(msg_mod, true_tmac)}")
    print(f"Verify HMAC: {hmac.verifyMac(msg_mod, true_hmac)}")


testOMAC(msg1)
testOMAC(msg2)
testOMAC(msg3)
testOMAC(msg4)

testHMAC(msg1)
testHMAC(msg2)
testHMAC(msg3)
testHMAC(msg4)

testModifiedNotValid(msg3, msg3a)

"""
msg:    b'Test MAC'
OMAC lib: 4a63c389f4ed79bbf19d9f42c3c212a0
OMAC my:  4a63c389f4ed79bbf19d9f42c3c212a0

msg:    b'sixteen-byte-msg'
OMAC lib: 136b7a6c96eac9252f903832f1e6a066
OMAC my:  136b7a6c96eac9252f903832f1e6a066

msg:    b'Eat some more of these soft french buns'
OMAC lib: 467ed7b3e8ea3324961f03f09b6cf726
OMAC my:  467ed7b3e8ea3324961f03f09b6cf726

msg:    b'HMAC does not encrypt the message. Instead, the message (encrypted or not) must be sent alongside the HMAC hash. Parties with the secret key will hash the message again themselves'
OMAC lib: 8f9c5df300fb3bbd343956e9524eaa93
OMAC my:  8f9c5df300fb3bbd343956e9524eaa93

msg:    b'Test MAC'
HMAC lib: 3bfbe75e59c2a9630a3c40ea6e3adce00f78485195991984c8fe98ad65951d1b
HMAC my:  3bfbe75e59c2a9630a3c40ea6e3adce00f78485195991984c8fe98ad65951d1b

msg:    b'sixteen-byte-msg'
HMAC lib: 5e22f8b2fca200e0b45a4e7c751be4c56a92add055d9f8f06449228e6d99191d
HMAC my:  5e22f8b2fca200e0b45a4e7c751be4c56a92add055d9f8f06449228e6d99191d

msg:    b'Eat some more of these soft french buns'
HMAC lib: f0006a13543e734213f40bba7b58edf690c30132f96d001addeeaa7d48ea4781
HMAC my:  f0006a13543e734213f40bba7b58edf690c30132f96d001addeeaa7d48ea4781

msg:    b'HMAC does not encrypt the message. Instead, the message (encrypted or not) must be sent alongside the HMAC hash. Parties with the secret key will hash the message again themselves'
HMAC lib: 0fb6fc64c4ca8c8d82dfc2c13ef1b3c7c7136701802b000a642c824f4d1e709d
HMAC my:  0fb6fc64c4ca8c8d82dfc2c13ef1b3c7c7136701802b000a642c824f4d1e709d

Message: b'Eat some more of these soft french buns'  (01000101 ... 01110101 01101110 01110011)
Modded:  b'Eat some more of these soft french buos'  (01000101 ... 01110101 01101111 01110011)
Verify OMAC: False
Verify TMAC: False
Verify HMAC: False
"""


from pwn import xor

RC4_DATA_SIZE = 0xda8
RC4_DATA_START = 0xd75

# known plaintext // 'the blob decrypted....'
XOR_KEY = 'pV4\x12'

with open("stage5.bin", "rb") as fp:
    fp.seek(RC4_DATA_START)
    data = fp.read(RC4_DATA_SIZE)

assert len(data) == RC4_DATA_SIZE

#print(c.decrypt(data))
with open("stage6.bin", "wb") as fp:
    fp.write(xor(data, XOR_KEY))

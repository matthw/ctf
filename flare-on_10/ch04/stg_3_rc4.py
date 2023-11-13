from Crypto.Cipher import ARC4

RC4_DATA_SIZE = 0x2ba8
RC4_DATA_START = 0xf30

#RC4_KEY = b'"InstallConfigSt'
RC4_KEY = b'SQLite format 3\x00'
print(RC4_KEY)

with open("stage3.bin", "rb") as fp:
    fp.seek(RC4_DATA_START)
    data = fp.read(RC4_DATA_SIZE)

assert len(data) == RC4_DATA_SIZE

c = ARC4.new(key=RC4_KEY)
#print(c.decrypt(data))
with open("stage4.bin", "wb") as fp:
    fp.write(c.decrypt(data))

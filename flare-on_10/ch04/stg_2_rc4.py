from Crypto.Cipher import ARC4

RC4_DATA_SIZE = 0x3b19
RC4_DATA_START = 0x953

RC4_KEY = b'"InstallConfigSt'
print(RC4_KEY)

with open("stage2.bin", "rb") as fp:
    fp.seek(RC4_DATA_START)
    data = fp.read(RC4_DATA_SIZE)

assert len(data) == RC4_DATA_SIZE

c = ARC4.new(key=RC4_KEY)
with open("stage3.bin", "wb") as fp:
    fp.write(c.decrypt(data))

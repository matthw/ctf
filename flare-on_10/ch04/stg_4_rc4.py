from Crypto.Cipher import ARC4

RC4_DATA_SIZE = 0x1bcc
RC4_DATA_START = 0xfdb

RC4_KEY = b'recentWalletFiles'

print(RC4_KEY)

with open("stage4.bin", "rb") as fp:
    fp.seek(RC4_DATA_START)
    data = fp.read(RC4_DATA_SIZE)

assert len(data) == RC4_DATA_SIZE

penis = open("sparrow.conf", "rb").read()

c = ARC4.new(key=RC4_KEY)
#print(c.decrypt(data))
with open("stage5.bin", "wb") as fp:
    fp.write(c.decrypt(data))

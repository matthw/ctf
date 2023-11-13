
import zlib
from Crypto.Cipher import AES

s1 = b"https://flare-on.com/evilc2server/report_token/report_token.php?token="
s2 = b"wednesday"

s = b""
s += s1[4:10]
s += s2[2:5]

c = str(zlib.crc32(s))
out = c + c
print(out)
key = bytes(out[0:16], 'ascii')
print(key)

iv = b'abcdefghijklmnop'

c = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
data = open("out/res/raw/ps.png", "rb").read()
open("ps.png", "wb").write(c.decrypt(data))

c = AES.new(key=key, mode=AES.MODE_CBC, iv=iv)
data = open("out/res/raw/iv.png", "rb").read()
open("iv.png", "wb").write(c.decrypt(data))


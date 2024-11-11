
from Crypto.Cipher import ChaCha20
from pwn import p32

offset = 0x23960
size =   0xf96


#key_marker = 0xc5407a48

"""
pwndbg> search -t dword 0xc5407a48
Searching for value: b'Hz@\xc5'
load7           0x55b46d51dde0 0x38f63d94c5407a48
load7           0x55b46d58ca40 0x38f63d94c5407a48
load7           0x55b46d58da0f 0x38f63d94c5407a48
load7           0x55b46d58dd34 0x38f63d94c5407a48
pwndbg> x/16dx 0x55b46d51dde0
0x55b46d51dde0:	0xc5407a48	0x38f63d94	0xe21318a8	0xa51863de
0x55b46d51ddf0:	0xbaa0f907	0x7b8abb2d	0xd06636a6	0x5ea6118d
0x55b46d51de00:	0x6fd614c9	0x9f8336f2	0x1a71cd4d	0x55298652
0x55b46d51de10:	0xb7d15858	0x0dc2a7f9	0x190ede36	0x9605a3ea
"""

key = [0x38f63d94, 0xe21318a8, 0xa51863de, 0xbaa0f907,
       0x7b8abb2d, 0xd06636a6, 0x5ea6118d, 0x6fd614c9]

nonce = [0x9f8336f2, 0x1a71cd4d, 0x55298652]

key_ = b''.join([p32(_) for _ in key])
nonce_ = b''.join([p32(_) for _ in nonce])

print(key_.hex())
print(nonce_.hex())



with open("liblzma.so.5.4.1", "rb") as fp:
    fp.seek(offset)
    data = fp.read(size)


c = ChaCha20.new(key=key_, nonce=nonce_)

print(data.hex())
with open("shellcode.1", "wb") as fp:
    fp.write(c.decrypt(data))

#!/usr/bin/env python3

from Crypto.Cipher import ChaCha20
import lief

# objdump -M intel -j .text -d libdance.so

dance = lief.ELF.parse("libdance.so")
s = dance.get_section(".text")

start_offset = s.virtual_address
end_offset   = start_offset + s.size - 1

data = bytearray(open('libdance.so', 'rb').read())

# pad to some size - that helps keeping the crc OK :^)
pad = 14300
lol = b'this is so lame '*256
data = data + lol[:pad - len(data)]

while start_offset <= end_offset:
    data[start_offset] = 0xcc
    start_offset += 1

key = bytes.fromhex("48656c6c6f2c2074686174206973206f6e65206b657920666f7220796f752e2e")
nonce = bytes.fromhex("6e6963655f6d6f76655f3a29")
c = ChaCha20.new(key=key, nonce=nonce)
enc_data = c.encrypt(data)

with open('libdance.so_patched', 'wb') as fp:
    fp.write(enc_data)


with open('libdance.so_patched_clear', 'wb') as fp:
    fp.write(data)

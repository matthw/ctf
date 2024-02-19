
from pwn import *

flag = b'0xL4ugh{3z_n4n0mites_t0_g3t_st4rt3d}'
fake = b'watch : https://youtu.be/dQw4w9WgXcQ'

k = []
for x in range(1, 37):
    v = (x << 3) & 0xff
    v ^= 0xca
    v |= (x >> 5)
    v ^= 0xfe
    k.append(v)


f = xor(flag, k)
print("flag")
print([_ for _ in f])
print("key")
print([_ for _ in xor(f, fake)])

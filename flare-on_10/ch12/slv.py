
from pwn import u64, p64, xor
import base64
from z3 import *

flag_enc = b'\x19v7/=\x1d&?{\x069X\x12#%k*\x07<8\x18h\x16\x1c0\t4#\x08[!$6aj&j\x0fD]\x06\x00'

def split(line, n):
    return [line[i:i+n] for i in range(0, len(line), n)]

# from test_array.py
table = b'\x02a$\xf5m\x84\x0cx\xfa\xfa\x18\xa3\xb9\x1c$_\xb9\x1c$_\x02a$\xf5m\x84\x0cx\xfa\xfa\x18\xa3\xfa\xfa\x18\xa3\xb9\x1c$_\x02a$\xf5m\x84\x0cxm\x84\x0cx\xfa\xfa\x18\xa3\xb9\x1c$_\x02a$\xf5'

output = b'FLARE2023FLARE2023FLARE2023FLARE2023\x00\x00\x00\x00'
output += b'\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00'

table = [u64(_) for _ in split(table, 8)]
output = [u64(_) for _ in split(output, 8)]
inputs = []
in_back = []
for x in range(len(output)):
    v = BitVec("i%x"%x, 64)
    in_back.append(v)
    inputs.append(v)

print(inputs)

for i in range(0, 7, 2):
    for j in range(7, -1, -1):
        tmp1 = inputs[i]
        tmp2 = table[j] ^ inputs[i+1]
        inputs[i] ^= tmp2
        inputs[i+1] = tmp1
        #print(inputs)
        #input()

s = Solver()
for i in range(len(inputs)):
    s.add(inputs[i] == output[i])
#print(s)
print(s.check())
m = s.model()

out = b''
for v in in_back:
    out += p64(m[v].as_long())

xx = base64.b64encode(out[:48])
print(xor(flag_enc, xx)[:41])


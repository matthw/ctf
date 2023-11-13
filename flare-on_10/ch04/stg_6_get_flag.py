
from pwn import xor, p32
import string
import zlib
import sys

found = "computer_ass1sted_ctf"
allow = b'0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!$&*+,-./:;?_'

for a in string.printable:
    for b in string.printable:
        for c in string.printable:
            for d in string.printable:
                s = bytes(found+a+b+c+d, 'ascii')
                if zlib.crc32(s) == 0xa5561586:
                    print(s + b'flare-on.com') 
                    sys.exit(0)

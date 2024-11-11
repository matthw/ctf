
from hashlib import sha256, md5
from itertools import permutations
from zlib import crc32

md = [
        "89484b14b36a8d5329426a3d944d2983",
        "f98ed07a4d5f50f7de1410d905f1477f",
        "657dae0913ee12be6fb2a6f687aae1c7",
        "738a656e8e8ec272ca17cd51e12f558b",
        ]

crc = [
        0x61089c5c,
        0x5888fc1b,
        0x66715919,
        0x7cab8d64
        ]

sha = [
        "403d5f23d149670348b147a15eeb7010914701a7e99aad2e43f90cfa0325c76f",
        "593f2d04aab251f60c9e4b8bbc1e05a34e920980ec08351a18459b2bc7dbf2f6"
        ]


for x in permutations(range(0x100), 2):
    if sha256(bytearray(x)).hexdigest() in sha:
        print(sha256(bytearray(x)).hexdigest())
        print(bytearray(x))
        print("----")


    if md5(bytearray(x)).hexdigest() in md:
        print(md5(bytearray(x)).hexdigest())
        print(bytearray(x))
        print("----")

    if crc32(bytearray(x)) in crc:
        print(hex(crc32(bytearray(x))))
        print(bytearray(x))
        print("----")




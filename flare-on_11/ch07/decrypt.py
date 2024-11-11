from ecpy.curves import Curve, Point, WeierstrassCurve
from ecpy.keys import ECPublicKey, ECPrivateKey
from Crypto.Util.number import getRandomInteger, bytes_to_long, long_to_bytes
from Crypto.Cipher import ChaCha20
from hashlib import sha512


def xor(number):
    return number ^ 0x133713371337133713371337133713371337133713371337133713371337133713371337133713371337133713371337

curve_def = { 
        'name':      "flare",
        'type':      "weierstrass",
        'size':      384,
        'field':     0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e5576a7a56976c2baeca47809765283aa078583e1e65172a3fd,
        'generator': (0x087b5fe3ae6dcfb0e074b40f6208c8f6de4f4f0679d6933796d3b9bd659704fb85452f041fff14cf0e9aa7e45544f9d8,
                      0x127425c1d330ed537663e87459eaa1b1b53edfe305f6a79b184b3180033aab190eb9aa003e02e9dbf6d593c5e3b08182),
        'order':     0xc90102faa48f18b5eac1f76bb40a1b9fb0d841712bbe3e547761ec3ea549979d50c95478998110005c8c2b7f3498ee71,
        'cofactor':  1,  
        'a':         0xa079db08ea2470350c182487b50f7707dd46a58a1d160ff79297dcc9bfad6cfc96a81c4a97564118a40331fe0fc1327f,
        'b':         0x9f939c02a7bd7fc263a4cce416f4c575f28d0c1315c4f0c282fca6709a5f9f7f9c251c9eede9eb1baa31602167fa5380
    }   


fc = WeierstrassCurve(curve_def)

# random private key on the curve
privKey = ECPrivateKey(168606034648973740214207039875253762473, fc) 

# derive public key from the private one
pubKey = privKey.get_public_key()

r_x = xor(0xa0d2eba817e38b03cd063227bd32e353880818893ab02378d7db3c71c5c725c6bba0934b5d5e2d3ca6fa89ffbb374c31)
r_y = xor(0x96a35eaf2a5e0b430021de361aa58f8015981ffd0d9824b50af23b5ccf16fa4e323483602d0754534d2e7a8aaf8174dc)

remote_pubKey = ECPublicKey(Point(r_x, r_y, fc))
meh = remote_pubKey.W * privKey.d
h = sha512(long_to_bytes(meh.x)).digest()
key = h[:32]
nonce = b'\x00\x00\x00\x00' + h[32:32+8]
print("key: %s"%key.hex())
print("nonce: %s"%nonce.hex())

c = ChaCha20.new(key=key, nonce=nonce)

data = [
        "f272d54c31860f", 
        "3fbd43da3ee325",
        "86dfd7",
        "c50cea1c4aa064c35a7f6e3ab0258441ac1585c36256dea83cac93007a0c3a29864f8e285ffa79c8eb43976d5b587f8f35e699547116",
        "fcb1d2cdbba979c989998c",
        "61490b",
        "ce39da",
        "577011e0d76ec8eb0b8259331def13ee6d86723eac9f0428924ee7f8411d4c701b4d9e2b3793f6117dd30dacba",
        "2cae600b5f32cea193e0de63d709838bd6",
        "a7fd35",
        "edf0fc",
        "802b15186c7a1b1a475daf94ae40f6bb81afcedc4afb158a5128c28c91cd7a8857d12a661acaec",
        "aec8d27a7cf26a17273685",
        "35a44e",
        "2f3917",
        "ed09447ded797219c966ef3dd5705a3c32bdb1710ae3b87fe66669e0b4646fc416c399c3a4fe1edc0a3ec5827b84db5a79b81634e7c3afe528a4da15457b637815373d4edcac2159d056",
        "f5981f71c7ea1b5d8b1e5f06fc83b1def38c6f4e694e3706412eabf54e3b6f4d19e8ef46b04e399f2c8ece8417fa",
        "4008bc",
        "54e41e",
        "f701fee74e80e8dfb54b487f9b2e3a277fa289cf6cb8df986cdd387e342ac9f5286da11ca2784084",
        "5ca68d1394be2a4d3d4d7c82e5",
        "31b6dac62ef1ad8dc1f60b79265ed0deaa31ddd2d53aa9fd9343463810f3e2232406366b48415333d4b8ac336d4086efa0f15e6e59",
        "0d1ec06f36",
]

for msg in data:
    msg = bytes.fromhex(msg)
    print(c.decrypt(msg))


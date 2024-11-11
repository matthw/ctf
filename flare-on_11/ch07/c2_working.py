#!/usr/bin/env python
import socket
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
privKey = ECPrivateKey(getRandomInteger(128), fc)

# derive public key from the private one
pubKey = privKey.get_public_key()

print(privKey)
print(pubKey)

with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
    s.bind(("0.0.0.0", 31337))
    s.listen()

    while True:
        conn, addr = s.accept()
        with conn:
            print(f"Connected by {addr}")

            #
            # receive client's pubkey (x, y)
            rem_x = xor(bytes_to_long(conn.recv(48)))
            rem_y = xor(bytes_to_long(conn.recv(48)))

            print(hex(rem_x))
            print(hex(rem_y))

            #
            # send out public key x and y
            conn.send(long_to_bytes(xor(pubKey.W.x)))
            conn.send(long_to_bytes(xor(pubKey.W.y)))

            #
            # Curve generator * Point(client_x, client_y)
            remote_pubKey = ECPublicKey(Point(rem_x, rem_y, fc))
            meh = remote_pubKey.W * privKey.d

            print(meh)
            
            #
            # sha512(meh.x) is our chacha20 key and iv
            #
            h = sha512(long_to_bytes(meh.x)).digest()
            key = h[:32]
            nonce = b'\x00\x00\x00\x00' + h[32:32+8]
            print("key: %s"%key.hex())
            print("nonce: %s"%nonce.hex())

            c = ChaCha20.new(key=key, nonce=nonce)

            conn.send(c.encrypt(b'verify\x00'))

        print("bye")

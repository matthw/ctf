from Crypto.Cipher import ChaCha20

flag = b'0xL4ugh{i_h0p3_you_l1k3d_ptr4c3_and_lat1n_danc3s}'
key = b'l{\xb1\xee\nLG\x9d\xed\xd7[\xbc\xd2C\xdd@\x1d\xb2w\xb85nYK\xf8c&\xd7\xe2P\xed\xdb'
nonce = b'\x96\xbf\xeb\xca\x8e|\xfb\xbc\xd9r\xa8S'

c = ChaCha20.new(key=key, nonce=nonce)
enc = c.encrypt(flag)

print("enc")
print([_ for _ in enc])
print("key")
print([_ for _ in key])
print("nonce")
print([_ for _ in nonce])


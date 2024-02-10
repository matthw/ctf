import struct
import io
from Crypto.Cipher import ChaCha20
from zlib import crc32
from pwn import u64, p32

binary = "../dance"

def get_lib():
    with open(binary, "rb") as fp:

        # get libsize
        fp.seek(0x40a0)
        libsize = u64(fp.read(8))
        
        # lib data
        fp.seek(0x40c0)
        libdata_enc = fp.read(libsize)

    c = ChaCha20.new(key=bytes.fromhex("48656c6c6f2c2074686174206973206f6e65206b657920666f7220796f752e2e"),
                     nonce=bytes.fromhex("6e6963655f6d6f76655f3a29"))
    libdata = c.decrypt(libdata_enc)

    return libdata


def get_nano_table():
    _struct = "<IB19B"
    _size = struct.calcsize(_struct)

    nanomites = {}
    crc_table = {}

    # build crc32 rainbow table of 'nanomited' address space
    for i in range(0xfff+1):
        crc_table[crc32(p32(i))] = i


    with open(binary, "rb") as fp:
        # nanomite table
        fp.seek(0x78a0)

        while True:
            _v = struct.unpack(_struct, fp.read(_size))
            crc = _v[0]
            sz  = _v[1]
            ops = bytes(_v[2:])

            # end
            if crc == 0 and sz == 0:
                break
            
            # build table for reconstruction
            nanomites[crc_table[crc]] = ops[:sz]

    return nanomites

def main():
    data = get_lib()
    with open("raw_lib.so", "wb") as fp:
        fp.write(data)

    nanomites = get_nano_table()

    # reconstruction
    data_fp = io.BytesIO(data)
    for addr, ops in nanomites.items():
        data_fp.seek(0x1000 + addr)
        data_fp.write(ops)

    with open("reconstructed_lib.so", "wb") as fp:
        fp.write(data_fp.getvalue())

if __name__ == "__main__":
    main()

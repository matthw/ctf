from unicorn import *
from unicorn.x86_const import *
from capstone import *
import sys



# victim id = 3487B3B41F20
# input key addr: 0x2a4c
# 1/ first check if xor ^ 0x5555
# 2/ key = 61d2e6e14a75
# 3/ bf last 2 chrs


# gef➤  x/16bx 0x2a4c
# 0x2a4c:	0x0a	0x0b	0x0c	0x0d	0x0e	0x0f	0x01	0x02
# 0x2a54:	0x03	0x04	0x05	0x06	0x07	0x08	0x09	0x00


def trykey(key):
    base_key = bytes.fromhex("06010d020e060e01040a0705")
    key = base_key + key

    code = open("0x1000.dump", "rb").read()

    mu = Uc(UC_ARCH_X86, UC_MODE_16)
    mu.mem_map(0x1000, 0x8000)
    mu.mem_map(0xf000, 0x1000)

    mu.mem_write(0x1000, code)
    mu.mem_write(0x2a4c, key)

    mu.reg_write(UC_X86_REG_SP, 0xfff4)
    mu.reg_write(UC_X86_REG_BP, 0x1)
    mu.reg_write(UC_X86_REG_ES, 0x0)
    
    mu.reg_write(UC_X86_REG_AX, 0x1c0d)
    mu.reg_write(UC_X86_REG_CX, 0x1)
    mu.reg_write(UC_X86_REG_DX, 0x1224)
    mu.reg_write(UC_X86_REG_SI, 0x0)
    mu.reg_write(UC_X86_REG_DI, 0x2a5c)
    mu.reg_write(UC_X86_REG_CR0, 0x10)


    mu.emu_start(0x1296, 0x130b)
    return mu.reg_read(UC_X86_REG_AX)



i = 0
for a in range(0x10):
    for b in range(0x10):
        for c in range(0x10):
            for d in range(0x10):

                kk = bytes([a, b, c, d])

                if not i % 1000:
                    print(i)
                i += 1
                res = trykey(kk)
                if res == 0:
                    print("found!!!")
                    print(kk)
                    sys.exit(0)


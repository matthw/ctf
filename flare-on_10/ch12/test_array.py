from unicorn import *
from unicorn.x86_const import *
from capstone import *
from Crypto.Cipher import ARC4
from pwn import p64


def decrypt(key, data):
    c = ARC4.new(key)
    return c.decrypt(data)

def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, addr):
        return (i.address, i.mnemonic, i.op_str)

def disas_all(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    for i in md.disasm(code, addr):
        print("0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))


def hook_code(mu, addr, size, user_data):
    mem = mu.mem_read(addr, size)
    dis = disas_single(mem, addr)
    addr, mnemonic, op_str = dis
    #print(">> %-32s 0x%x\t%s\t%s"%(mem.hex(), addr, mnemonic, op_str))
    if addr in [0x51f0, 0x552, 0x55a]:
        rbp = mu.reg_read(UC_X86_REG_RBP)
        # a8 / 28
        print(mu.mem_read(rbp - 0xa0, 64))
        print(mu.mem_read(rbp - 0x60, 64))
    if addr == 0x5df:
        #print("ooo")
        #print(hex(mu.reg_read(UC_X86_REG_RDI)))
        #print(hex(mu.reg_read(UC_X86_REG_RSI)))
        print(mu.mem_read(0xb000, 48))

    if addr == 0x5e0:
        mu.emu_stop()


def emu():
    entry = 0x4af
    code = open('rsrc_fixed.bin', 'rb').read()

    mu = Uc(UC_ARCH_X86, UC_MODE_64)
    mu.mem_map(0x0, 0x1000)
    mu.mem_map(0x7000, 0x1000)  # stack
    mu.mem_map(0xa000, 0x1000)   # s1
    mu.mem_map(0xb000, 0x1000)   # s2
    mu.mem_write(0x0, code)
    mu.mem_write(0x7000, b'\x00'*0x1000)

    inp1 = b'FLARE2023FLARE2023FLARE2023FLARE2023'
    inp2 = b'\xcc\x16)L\x15\x16&\xf7\xfd1A\xf8*\xd7\x18\xbf\xbb\x1dQU\x0fr3\x82\x89NF\xe6.\xb7m\xbf\x8b,\x16l\x02a$\xf5\x89M2\x99o\xe5(\x8d'

    mu.reg_write(UC_X86_REG_RSP, 0x7500)
    mu.reg_write(UC_X86_REG_RBP, 0x7500)
    mu.reg_write(UC_X86_REG_RDX, 0x52414c46)    # FLAR
    mu.reg_write(UC_X86_REG_RDI, 0xb000)
    mu.mem_write(0xa000, inp1)
    mu.mem_write(0xb000, inp2)
    mu.reg_write(UC_X86_REG_ESI, len(inp2))

    mu.hook_add(UC_HOOK_CODE, hook_code)
    mu.emu_start(entry, 0x1000)
    #print(mu.mem_read(0xa000, 0x100))
    #print(mu.reg_read(UC_X86_REG_RAX))


if __name__ == "__main__":
    emu()

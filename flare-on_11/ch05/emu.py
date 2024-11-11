
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *


def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for i in md.disasm(code, addr):
        print("        >>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))
        return


def hook_code(mu, addr, size, user_data):
    mem = mu.mem_read(addr, size)
    disas_single(mem, addr)
        

mu = Uc(UC_ARCH_X86, UC_MODE_64)
mu.mem_map(0x00000,  0x1000)
mu.mem_map(0x700000,  0x10000)

mu.mem_write(0x00000, open("shellcode.1", "rb").read())




rbp = 0x704000

mu.reg_write(UC_X86_REG_RBP, rbp)
mu.reg_write(UC_X86_REG_RSP, 0x701000)


content = rbp - 0x1148
key = rbp - 0x1278
nonce = rbp - 0x1258

mu.mem_write(key, b'\x8d\xec\x91\x12\xeb\x76\x0e\xda\x7c\x7d\x87\xa4\x43\x27\x1c\x35\xd9\xe0\xcb\x87\x89\x93\xb4\xd9\x04\xae\xf9\x34\xfa\x21\x66\xd7')
mu.mem_write(nonce, b'\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11\x11')
mu.mem_write(content, b'\xa9\xf6\x34\x08\x42\x2a\x9e\x1c\x0c\x03\xa8\x08\x94\x70\xbb\x8d\xaa\xdc\x6d\x7b\x24\xff\x7f\x24\x7c\xda\x83\x9e\x92\xf7\x07\x1d\x02\x63\x90\x2e\xc1\x58')

#mu.hook_add(UC_HOOK_CODE, hook_code)

mu.emu_start(0x00000 + 0xe7f, 0x00000 + 0xecf)

#print(mu.mem_read(0x700000, 0x10000).replace(b'\x00', b''))
print(mu.mem_read(content, 0x80))

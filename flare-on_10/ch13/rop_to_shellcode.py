
# cursed because too much copy/paste during flareon ;)

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import sys
import base64



r9 = base64.b64decode("BawAAADDBeQAAADDBegAAADDg8Baw4PAYMODwHDDg8B7wwWPAAAAwwWWAAAAwwNFJMNIg8U4wzlFJMP/wMOIBArDiVUQw0yJRRjDiEUgw4lFJMNIiU0Iw8dFJAAAAADDi0Ukw4tFSMOLTSTDSItNQMNIi1VAw0iLVVDDD7YEAcMPtkUgww+2DArDD7ZNIMP32MP30MMLwcPR+MPB+ALDwfgDw8H4BcPB+AbDwfgHw9Hhw8HhAsPB4QPDweEFw8HhBsPB4QfDLbEAAADDLbIAAADDLcMAAADDLcUAAADDLdwAAADDLfMAAADDLf8AAADDg+gYw4PoGsOD6B7Dg+gow4PoNsOD6ATDg+hJw4PoVsOD6FjDLYEAAADDLZAAAADDLZoAAADDK0Ukw0iD7TjDNaMAAADDNbYAAADDNb8AAADDNcIAAADDNckAAADDNcsAAADDg/ANwzXhAAAAwzXrAAAAw4PwFsOD8CDDg/Aiw4PwJcOD8EDDg/B4w4PwfMM1jwAAAMMzRSTDM8DDM8HD/8HDi8nDgeH/AAAAw4tVJMODwgLDi9LDTItFUMNBD7YUEMPR+sOB4v8AAADDI8rDg8EDww==")



def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for i in md.disasm(code, addr):
        return i
        #return (i.address, i.mnemonic, i.op_str)

shellcode = []
def dis_gadget(addr, code):
    global shellcode
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    size = 0
    for i in md.disasm(code, addr):
        if i.mnemonic == "ret":
            shellcode.append(code[:size])
            break
        size += i.size
        print("%s\t%s" %(i.mnemonic, i.op_str))


class Emu:
    def __init__(self):
        fp = open(sys.argv[1], "rb")
        fp.seek(0x400)
        self.code = fp.read(0x65000)
        fp.close()


    def log_instruction(self, mu, i):
        #print("        >>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))
        match i.mnemonic:
            case 'push':
                rsi = mu.reg_read(UC_X86_REG_RSI)
                #print(hex(rsi)[2:].rjust(8, "0"))
                data = mu.mem_read(rsi, 0x100)
                dis_gadget(rsi, data)
            case "ret":
                mu.emu_stop()
            case _:
                pass
        
        #print("        >>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))



    def hook_code(self, mu, addr, size, user_data):
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)
        
        self.log_instruction(mu, dis)

    def emu(self):
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x1e70000,   0x1000)
        mu.mem_map(0x180001000, 0x100000)
        mu.mem_map(0x7f0a00000, 0x10000)

        mu.mem_write(0x180001000, self.code)
        mu.mem_write(0x1e70000, r9)
        mu.reg_write(UC_X86_REG_R9, 0x1e70000)
        mu.reg_write(UC_X86_REG_RBP, 0x7f0a04000)
        mu.reg_write(UC_X86_REG_RSP, 0x7f0a04000)
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        mu.emu_start(0x18001d361, 0x18009a81b)

if __name__ == "__main__":
    e = Emu()
    e.emu()

    with open("shellcode.bin", "wb") as fp:
        for gadget in shellcode[::-1]:
            fp.write(gadget)

from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from pwn import p64
from Crypto.Cipher import ARC4
import sys
import base64
import pefile


def extract_rsrc(pe):
    """ stolen from binref, thx Jesko
    """
    def _search(pe: pefile.PE, directory, level=0, *parts):
        for entry in directory.entries:
            if entry.name:
                identifier = str(entry.name)
            elif entry.id is not None:
                identifier = entry.id
            else:
                identifier = "lol"

            if entry.struct.DataIsDirectory:
                yield from _search(pe, entry.directory, level + 1, *parts, identifier)
            else:
                rva = entry.data.struct.OffsetToData
                size = entry.data.struct.Size
                path = '/'.join(str(p) for p in (*parts, identifier))
                extract = None
                if extract is None:
                    def extract(pe=pe):
                        return pe.get_data(rva, size)
                yield {
                        'path': path,
                        'name': path.split("/")[1],
                        'extract': extract,
                        'offset': pe.get_offset_from_rva(rva)
                        }

    pe.parse_data_directories(directories=pefile.DIRECTORY_ENTRY['IMAGE_DIRECTORY_ENTRY_RESOURCE'])
    rsrc = pe.DIRECTORY_ENTRY_RESOURCE
    return _search(pe, rsrc)




def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for i in md.disasm(code, addr):
        return i
        #return (i.address, i.mnemonic, i.op_str)



class Emu:
    def __init__(self):
        self.extract_rsrc()

        # load .text section
        fp = open("y0da.exe", "rb")
        fp.seek(0x400)
        self.ropchain = []
        self.code = fp.read(0x65000)
        fp.close()

    def extract_rsrc(self):
        pe = pefile.PE('y0da.exe')
        print("getting resource...")
        for rsrc in extract_rsrc(pe):
            if rsrc['path'] == 'M4ST3R/Y0D4/0':
                enc_res = rsrc['extract']()
                print("got %s"%rsrc['path'])

        key = b'patience_y0u_must_h4v3' # from md5 check
        print("decrypting (ARC4 with key %s)"%key)
        c = ARC4.new(key)
        dec_res = c.decrypt(enc_res)

        with open("y0da.jpg", "wb") as fp:
            fp.write(dec_res)
            print("saved as y0da.jpg for the lulz")

        overlay = dec_res[-516:]

        self.encrypted_flag = overlay[4:0x3d]
        self.rop_data = overlay[0x3d+4:]

        print("got this from the jpg overlay")
        print("  enc_flag: %s"%self.encrypted_flag.hex())
        print("  rop_data: %s"%self.rop_data.hex())


    def get_gadget_code(self, addr, code):
        md = Cs(CS_ARCH_X86, CS_MODE_64)
        size = 0
        for i in md.disasm(code, addr):
            if i.mnemonic == "ret":
                break
            size += i.size
            #print("%s\t%s" %(i.mnemonic, i.op_str))
        self.ropchain.append(code[:size])

    def log_instruction(self, mu, i):
        #print("        >>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))
        match i.mnemonic:
            case "jmp":
                return
            case "call":
                if '[' in i.op_str:
                    dest = i.op_str.split()[-1]
                    mu.reg_write(UC_X86_REG_EIP, mu.reg_read(UC_X86_REG_EIP) + i.size)
            case 'push':
                rsi = mu.reg_read(UC_X86_REG_RSI)
                #print(hex(rsi)[2:].rjust(8, "0"))
                data = mu.mem_read(rsi, 0x100)
                self.get_gadget_code( rsi, data)
            case "ret":
                mu.emu_stop()
            case _:
                pass
        
        #print("        >>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))



    def hook_code(self, mu, addr, size, user_data):
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)
        
        self.log_instruction(mu, dis)

    def build_rop(self):
        """ emulates the ropchain creation
            grabs gadgets addr from the stack and convert
            them a working shellcode
        """
        mu = Uc(UC_ARCH_X86, UC_MODE_64)
        mu.mem_map(0x1e70000,   0x1000)
        mu.mem_map(0x180001000, 0x100000)
        mu.mem_map(0x7f0a00000, 0x10000)

        mu.mem_write(0x180001000, self.code)
        mu.mem_write(0x1e70000, self.rop_data)
        mu.reg_write(UC_X86_REG_R9, 0x1e70000)
        mu.reg_write(UC_X86_REG_RBP, 0x7f0a04000)
        mu.reg_write(UC_X86_REG_RSP, 0x7f0a04000)
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        print("emulating ropchain builder 0x18001d361 -> 0x18009a81b and convert chain to shellcode...")
        mu.emu_start(0x18001d361, 0x18009a81b)
        
        print("got %d gadgets"%(len(self.ropchain)))
        self.ropchain = b''.join(self.ropchain[::-1])

    def emu_rop(self):
        flag_addr  = 0x1E60000
        twist_addr = 0x1E50000
        
        stack_addr = 0xf000000
        code_addr  = 0x2000000

        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        mu.mem_map(flag_addr,  0x1000)
        mu.mem_map(twist_addr, 0x1000)  # dot not init, must zeros
        mu.mem_map(stack_addr, 0x1000)
        mu.mem_map(code_addr,  0x1000)

        mu.mem_write(code_addr, self.ropchain)
        mu.mem_write(flag_addr, self.encrypted_flag)

        rbp = stack_addr+0x100
        mu.reg_write(UC_X86_REG_RBP, rbp)
        mu.reg_write(UC_X86_REG_RSP, rbp)

        mu.mem_write(rbp+0x40, p64(flag_addr))
        mu.mem_write(rbp+0x50, p64(twist_addr))

        print("emulating ropchain 0x39 times...")

        for index in range(0x39):
            mu.mem_write(rbp+0x24, p64(index))      # char index to decrypt
            mu.emu_start(code_addr, code_addr + len(self.ropchain))


        return mu.mem_read(flag_addr, 0x40).rstrip(b'\x00').decode('ascii')
            




if __name__ == "__main__":
    e = Emu()
    e.build_rop()
    flag = e.emu_rop()
    print(flag)


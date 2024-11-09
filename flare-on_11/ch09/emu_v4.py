#!/usr/bin/env python3
#
# this gives interesting results:
# python emu_v2.py 2>/dev/null| grep -v rip | grep -Pv 'push|pop|lea|mov       *rax, 0|call|ret'
#
# https://doxygen.reactos.org/d8/d2f/unwind_8c_source.html
import io
import sys
from enum import Enum
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
import hexdump
import pefile
from malduck import p64, p32, p16, u64, u32, u16

DEBUG = True

class UWND_CODE(Enum):
    UWOP_PUSH_NONVOL = 0
    UWOP_ALLOC_LARGE = 1
    UWOP_ALLOC_SMALL = 2
    UWOP_SET_FPREG = 3
    UWOP_SAVE_NONVOL = 4
    UWOP_SAVE_NONVOL_FAR = 5
    UWOP_EPILOG = 6
    UWOP_SPARE_CODE = 7
    UWOP_SAVE_XMM128 = 8
    UWOP_SAVE_XMM128_FAR = 9
    UWOP_PUSH_MACHFRAME = 10

class REGS(Enum):
    RAX = 0
    RCX = 1
    RDX = 2
    RBX = 3
    RSP = 4
    RBP = 5
    RSI = 6
    RDI = 7
    R8  = 8
    R9  = 9
    R10 = 10
    R11 = 11
    R12 = 12
    R13 = 13
    R14 = 14
    R15 = 15
    RIP = 16

UNICORN_REGS = {
        REGS.RAX: UC_X86_REG_RAX,
        REGS.RCX: UC_X86_REG_RCX,
        REGS.RDX: UC_X86_REG_RDX,
        REGS.RBX: UC_X86_REG_RBX,
        REGS.RSP: UC_X86_REG_RSP,
        REGS.RBP: UC_X86_REG_RBP,
        REGS.RSI: UC_X86_REG_RSI,
        REGS.RDI: UC_X86_REG_RDI,
        REGS.R8:  UC_X86_REG_R8,
        REGS.R9:  UC_X86_REG_R9,
        REGS.R10: UC_X86_REG_R10,
        REGS.R11: UC_X86_REG_R11,
        REGS.R12: UC_X86_REG_R12,
        REGS.R13: UC_X86_REG_R13,
        REGS.R14: UC_X86_REG_R14,
        REGS.R15: UC_X86_REG_R15,
        REGS.RIP: UC_X86_REG_RIP
}

def disas_single(code, addr):
    md = Cs(CS_ARCH_X86, CS_MODE_64)
    md.detail = True
    for i in md.disasm(code, addr):
        return i

def dbg(line):
    if DEBUG:
        print(line)

def dump_context(mu):
    if not DEBUG:
        return
    return  
    def r(r):
        return mu.reg_read(r)
    print("     rax: 0x%016x rcx: 0x%016x rdx: 0x%016x rbx: 0x%016x"%(r(UC_X86_REG_RAX), r(UC_X86_REG_RCX), r(UC_X86_REG_RDX), r(UC_X86_REG_RBX)))
    print("     rsp: 0x%016x rbp: 0x%016x rsi: 0x%016x rdi: 0x%016x"%(r(UC_X86_REG_RSP), r(UC_X86_REG_RBP), r(UC_X86_REG_RSI), r(UC_X86_REG_RDI)))
    print("     r8:  0x%016x r9:  0x%016x r10: 0x%016x r11: 0x%016x"%(r(UC_X86_REG_R8),  r(UC_X86_REG_R9),  r(UC_X86_REG_R10), r(UC_X86_REG_R11)))
    print("     r12: 0x%016x r13: 0x%016x r14: 0x%016x r15: 0x%016x"%(r(UC_X86_REG_R12), r(UC_X86_REG_R13), r(UC_X86_REG_R14), r(UC_X86_REG_R15)))
    print("     mxcsr: 0x%08x"%r(UC_X86_REG_MXCSR))

    return
    rsp = r(UC_X86_REG_RSP)
    for x in range(10):
        print("rsp+%x 0x%x"%(x*8, u64(mu.mem_read(rsp + x*8, 8))))



class Context:
    # fuckers are using MxCsr reg
    # >>  0x69b08eb	mov	r11d, dword ptr [rbx + 0x34]
    def __init__(self, mu):
        # addr = address of DISPARTCHER_CONTEXT
        dbg("saving context...")
        self.mu = mu
        self.regs = {}
        self.mxcsr = None

        for reg in REGS:
            self.regs[reg] = mu.reg_read(UNICORN_REGS[reg])
        self.mxcsr = mu.reg_read(UC_X86_REG_MXCSR)


    def to_memory(self, addr):
        # addr is DISPATCHER_CONTEXT address
        dbg("context to mem...")
        context_addr = addr + 0x1000         # arbitrary addr for CONTEXT
        offset = 0x78                        # start of regs in the struct

        # write CONTEXT struct
        for n, reg in enumerate(REGS):
            self.mu.mem_write(context_addr + offset + n*8, p64(self.regs[reg]))
        # write MxCsr
        self.mu.mem_write(context_addr + 0x34, p32(self.mxcsr))

        # fill in pointer in DISPATCHER_CONTEXT
        self.mu.mem_write(addr + 0x28, p64(context_addr))

    def dump(self):
        print("CTX  rax: 0x%016x rcx: 0x%016x rdx: 0x%016x rbx: 0x%016x"%(self.regs[REGS.RAX], self.regs[REGS.RCX], 
                                                                          self.regs[REGS.RDX], self.regs[REGS.RBX]))
        print("CTX  rsp: 0x%016x rbp: 0x%016x rsi: 0x%016x rdi: 0x%016x"%(self.regs[REGS.RSP], self.regs[REGS.RBP],
                                                                          self.regs[REGS.RSI], self.regs[REGS.RDI]))
        print("CTX  r8:  0x%016x r9:  0x%016x r10: 0x%016x r11: 0x%016x"%(self.regs[REGS.R8],  self.regs[REGS.R9],
                                                                          self.regs[REGS.R10], self.regs[REGS.R11]))
        print("CTX  r12: 0x%016x r13: 0x%016x r14: 0x%016x r15: 0x%016x"%(self.regs[REGS.R12], self.regs[REGS.R13],
                                                                          self.regs[REGS.R14], self.regs[REGS.R15]))
        print("CTX: rip: 0x%016x mxcsr: 0x%08x"%(self.regs[REGS.RIP], self.mxcsr))






class Unwinder:
    def __init__(self, mu, unwind_addr, ctx):
        self.mu   = mu              # unicorn
        self.addr = unwind_addr     # start of UNWIND_INFO
        self.ctx = ctx
        self.n_codes = None         # number of codes
        self.codes   = None         # raw codes bytes


        unwind_info = mu.mem_read(unwind_addr, 4)
        unwind_addr += 4

        flag = unwind_info[0] >> 3
        self.n_codes = unwind_info[2]
        dbg("flag: %d / opcodes: %d"%(flag, self.n_codes))

        self.frame_reg = unwind_info[3] & 0xf
        self.frame_offset = unwind_info[3] >> 4


        # if CountOfCodes is uneven, read one more short word
        codes_size = 2 * (( self.n_codes + 1) &~1)
        self.codes = io.BytesIO(mu.mem_read(unwind_addr, codes_size))
        unwind_addr += codes_size
        
        self.exception_handler = u32(mu.mem_read(unwind_addr, 4))
        dbg("exception_handler: %s"%(hex(self.exception_handler)))


    def mem_read(self, addr):
        # read a QWORD at addr
        return u64(self.mu.mem_read(addr, 8))


    def do_unwind(self):
        # https://github.com/google/orbit/blob/02f72c7311ed08e6418ecbfab4a457db67aa38d9/third_party/libunwindstack/PeCoffUnwindInfoUnwinderX86_64.cpp
        # https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
        node = 0
        while node < self.n_codes:
            unwind_code = self.codes.read(2)
            node += 1

            unwind_op_code = UWND_CODE(unwind_code[1] & 0xf )
            unwind_op_info = unwind_code[1] >> 4

            dbg("unwind_op_code: %r"%unwind_op_code)
            dbg("unwind_op_info: %d"%unwind_op_info)

            match unwind_op_code:

                case UWND_CODE.UWOP_PUSH_MACHFRAME:
                    # https://github.com/azakharchenko-msol/wine/commit/400520192284c34e5b34b52b657cd3dda084403f
                    offset = 0x20 if unwind_op_info == 1 else 0x18
                    print(" setting rsp to 0x%08x"%self.mem_read(self.ctx.regs[REGS.RSP] + offset))
                    self.ctx.regs[REGS.RSP] = self.mem_read(self.ctx.regs[REGS.RSP] + offset)

                case UWND_CODE.UWOP_PUSH_NONVOL:
                    reg = REGS(unwind_op_info)

                    # check for input reading
                    if 0x14089b8e8 <= self.ctx.regs[REGS.RSP] < 0x14089b8e8+0x20:
                        print(" reading 8 bytes of input @ offset %d into %r"%(self.ctx.regs[REGS.RSP] - 0x14089b8e8, self.ctx.regs[reg]))

                    v = self.mem_read(self.ctx.regs[REGS.RSP])   # v = [rsp]
                    print(" PUSH %r = 0x%x (from: rsp=0x%x)"%(reg, v, self.ctx.regs[REGS.RSP]))
                    self.ctx.regs[reg] = v                       # regX = v
                    self.ctx.regs[REGS.RSP] += 8                 # rsp += 8

                case UWND_CODE.UWOP_ALLOC_LARGE:
                    # alloc size = next slot * 8
                    if unwind_op_info == 0:
                        size = u16(self.codes.read(2)) * 8
                        node += 1
                    # alloc size = next 2 slot
                    elif unwind_op_info == 1:
                        size = u32(self.codes.read(4))
                        node += 2
                    self.ctx.regs[REGS.RSP] += size
                    print(" ALLOC %d"%size)

                case UWND_CODE.UWOP_ALLOC_SMALL:
                    size = unwind_op_info * 8 + 8
                    self.ctx.regs[REGS.RSP] += size
                    print(" ALLOC %d"%size)

                case UWND_CODE.UWOP_SET_FPREG:
                    self.ctx.regs[REGS.RSP] = self.ctx.regs[REGS(self.frame_reg)]
                    self.ctx.regs[REGS.RSP] -= self.frame_offset * 16
                    print(" rsp = 0x%x off=0x%x reg=%r"%(self.ctx.regs[REGS.RSP], self.frame_offset, REGS(self.frame_reg)))

                case _:
                    raise

            if DEBUG: self.ctx.dump()
                    
            
        


        # maybe a good place to return the exception handler offset
        return self.exception_handler





class Emu:
    def __init__(self):
        # load PE
        self.sections = {}

        pe = pefile.PE('serpentine.exe')
        for section in pe.sections:
            name = section.Name.rstrip(b'\x00').decode()
            self.sections[name] = section

    def log_instruction(self, mu, i):
        dump_context(mu)
        print(">>  0x%x\t%s\t%s"%(i.address, i.mnemonic, i.op_str))

    def hook_code(self, mu, addr, size, user_data):
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)

        self.log_instruction(mu, dis)

        #
        # maaaagic
        #
        if dis.mnemonic == "hlt":
            self.handle_exception(mu, addr)




    def handle_exception(self, mu, addr):
        ctx = Context(mu)   # initialize context
            
        # how many bytes to skip before findind the unwind_handle
        # byte at faulty rip + 1
        unwind_addr = mu.mem_read(addr + 1, 1)[0] + addr + 2
        # alignment
        if unwind_addr & 1:
            unwind_addr += 1

        if DEBUG:
            ctx.dump()

        unwinder = Unwinder(mu, unwind_addr, ctx)


        exception_handler_addr = unwinder.do_unwind()
        exception_handler_addr += self.code_addr

        if DEBUG:
            ctx.dump()

        print("HANDLER ADDR: 0x%x"%exception_handler_addr)

        # save CONTEXT to memory
        ctx.to_memory(self.dis_ctx_addr)
        
        #
        # setup call context
        # we might need a "call rax" trampoline instead
        #
        # https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
        # PARAMS
        # typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
        #   IN PEXCEPTION_RECORD ExceptionRecord,
        #   IN ULONG64 EstablisherFrame,
        #   IN OUT PCONTEXT ContextRecord,
        #   IN OUT PDISPATCHER_CONTEXT DispatcherContext
        #   );
        mu.reg_write(UC_X86_REG_RCX, 0)         # ExceptionRecord,
        mu.reg_write(UC_X86_REG_RDX, 0)         # EstablisherFrame,
        mu.reg_write(UC_X86_REG_R8,  0)         # ContextRecord,
        mu.reg_write(UC_X86_REG_R9, self.dis_ctx_addr)   # DispatcherContext
        mu.reg_write(UC_X86_REG_RAX, exception_handler_addr)
        mu.reg_write(UC_X86_REG_RIP, exception_handler_addr)




    def emu(self):
        def align(addr):
            return addr + 0x1000 & ~(0x1000-1)

        #
        # map all section
        #
        base_addr = 0x0000000140000000
        mu = Uc(UC_ARCH_X86, UC_MODE_64)

        for name, section in self.sections.items():
            s_addr = section.VirtualAddress + base_addr
            s_size = align(section.Misc_VirtualSize)
            print("mapping %s @ 0x%x (sz: 0x%x)"%(name, s_addr, s_size))
            mu.mem_map(s_addr, s_size)
            mu.mem_write(s_addr, section.get_data())

        #
        # stack
        #
        initial_rsp = 0x00000000067FFEB0
        mu.mem_map(0x67f0000, 0x100000)
        mu.reg_write(UC_X86_REG_RBP, 0)
        mu.reg_write(UC_X86_REG_RSP, initial_rsp)


        #
        # madness code
        #
        self.code_addr = 0x60000000
        mu.mem_map(self.code_addr, 0x800000)
        mu.mem_write(self.code_addr, bytes(mu.mem_read(self.sections[".data"].VirtualAddress + base_addr + 0x75af0, 0x800000)))
        mu.mem_write(0x14089b8e0, p64(self.code_addr))

        # to store context and stuff
        self.dis_ctx_addr = 0x90000000
        mu.mem_map(self.dis_ctx_addr, 0x2000)
        #self.call_rax_trampoline = self.dis_ctx_addr + 0x1900
        #mu.mem_write(self.call_rax_trampoline, b'\xff\xd0') # call rax

        #
        # init
        #
        #mu.reg_write(UC_X86_REG_R9, 0x00000000067FDB00) # test
        # need to setup the input key somewhere...
        #key = b'ABCDEFGHIJKLMNOPabcdefghijklmnop'
        if len(sys.argv) == 2:
            key = sys.argv[1].encode()
        else:
            key = b'AAAABBBBCCCCDDDDaaaabbbbccccdddd'
            #key = b'\xd0AAA\x0fAAA\x4aAAA\x7fAAA\xe2AAA\xd2AAA\xd2AAA\xceAAA'
            #key = b's\x00\x00\x00\xa2\x00\x00\x00h\x00\x00\x00\xf4\x00\x00\x00\x85\x00\x00\x00\x1b\x00\x00\x00=\x00\x00\x00[\x00\x00\x00'
        key_addr = 0x14089b8e8
        mu.mem_write(key_addr, key)

        #
        # go
        #
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        
        # emulate up until
        # >>  0x60017a07    cmovne    r12, r15
        # >>  0x60017a0b    jmp    r12
        mu.emu_start(0x140001642, -1)


if __name__ == "__main__":
    print(sys.argv)
    emu = Emu()
    emu.emu()


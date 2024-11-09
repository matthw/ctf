#!/usr/bin/env python3
#
# sorry, this is not pretty but it wasn't a beauty contest
#
import io
import sys
from enum import Enum
from unicorn import *
from unicorn.x86_const import *
from capstone import *
from capstone.x86 import *
from keystone import *
import pefile
from malduck import p64, p32, p16, u64, u32, u16

import tables

# vaguely controls debug output
# it worked at some point, now it prints a lot anyway.
DEBUG = False


#
# unwind opcodes
#
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

#
# registers numbers
#
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
    #RIP = 16

#
# register ids to unicorn mapping
#
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
        #REGS.RIP: UC_X86_REG_RIP
}


#
# register ids to register names
#
ASM_REGS = {
        REGS.RAX: "rax",
        REGS.RCX: "rcx",
        REGS.RDX: "rdx",
        REGS.RBX: "rbx",
        REGS.RSP: "rsp",
        REGS.RBP: "rbp",
        REGS.RSI: "rsi",
        REGS.RDI: "rdi",
        REGS.R8:  "r8",
        REGS.R9:  "r9",
        REGS.R10: "r10",
        REGS.R11: "r11",
        REGS.R12: "r12",
        REGS.R13: "r13",
        REGS.R14: "r14",
        REGS.R15: "r15",
        #REGS.RIP: "rip"
}

#
# list of 8 bits registers
#
REGS_8BITS = [
        UC_X86_REG_AL, UC_X86_REG_CL, UC_X86_REG_DL, UC_X86_REG_BL, UC_X86_REG_BPL,
        UC_X86_REG_SIL, UC_X86_REG_DIL, UC_X86_REG_R8B, UC_X86_REG_R9B,
        UC_X86_REG_R10B, UC_X86_REG_R11B, UC_X86_REG_R12B, UC_X86_REG_R13B,
        UC_X86_REG_R14B, UC_X86_REG_R15B
        ]

#
# list of 32 bits registers
#
REGS_32BITS = [
        UC_X86_REG_EAX, UC_X86_REG_ECX, UC_X86_REG_EDX, UC_X86_REG_EBX, UC_X86_REG_EBP,
        UC_X86_REG_ESI, UC_X86_REG_EDI, UC_X86_REG_R8D, UC_X86_REG_R9D,
        UC_X86_REG_R10D, UC_X86_REG_R11D, UC_X86_REG_R12D, UC_X86_REG_R13D,
        UC_X86_REG_R14D, UC_X86_REG_R15D
        ]

#
# map 8 bits registers to 64 bits
#
regs_8_to_64 = {
        "al": "rax",
        "cl": "rcx",
        "dl": "rdx",
        "bl": "rbx",
        "bpl": "rbp",
        "sil": "rsi",
        "dil": "rdi",
        "r8b": "r8",
        "r9b": "r9",
        "r10b": "r10",
        "r11b": "r11",
        "r12b": "r12",
        "r13b": "r13",
        "r14b": "r14",
        "r15b": "r15",
        }

#
# map 32 bits registers to 64 bits
#
regs_32_to_64 = {
        "eax": "rax",
        "rax": "rax",
        "ecx": "rcx",
        "rcx": "rcx",
        "edx": "rdx",
        "rdx": "rdx",
        "ebx": "rbx",
        "rbx": "rbx",
        "ebp": "rbp",
        "rbp": "rbp",
        "esi": "rsi",
        "rsi": "rsi",
        "edi": "rdi",
        "rdi": "rdi",
        "r8d": "r8",
        "r8":  "r8",
        "r9d": "r9",
        "r10d": "r10",
        "r10": "r10",
        "r11d": "r11",
        "r11": "r11",
        "r12d": "r12",
        "r12":  "r12",
        "r13d": "r13",
        "r13": "r13",
        "r14d": "r14",
        "r14": "r14",
        "r15d": "r15",
        "r15": "r15"
        }

#
# map 32/64 bits registers to 8 bits
#
to_8bit_reg = {
        "eax": "al",
        "rax": "al",
        "rdi": "dil",
        "r8": "r8b",
        "r10": "r10b",
        "r11": "r11b",
        "r12": "r12b",
        "r13": "r13b",
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
    """ dump unicorn cpu context
    """
    if not DEBUG:
        return
    #return  
    def r(r):
        return mu.reg_read(r)

    print("     rax: 0x%016x rcx: 0x%016x rdx: 0x%016x rbx: 0x%016x"%(r(UC_X86_REG_RAX), r(UC_X86_REG_RCX), r(UC_X86_REG_RDX), r(UC_X86_REG_RBX)))
    print("     rsp: 0x%016x rbp: 0x%016x rsi: 0x%016x rdi: 0x%016x"%(r(UC_X86_REG_RSP), r(UC_X86_REG_RBP), r(UC_X86_REG_RSI), r(UC_X86_REG_RDI)))
    print("     r8:  0x%016x r9:  0x%016x r10: 0x%016x r11: 0x%016x"%(r(UC_X86_REG_R8),  r(UC_X86_REG_R9),  r(UC_X86_REG_R10), r(UC_X86_REG_R11)))
    print("     r12: 0x%016x r13: 0x%016x r14: 0x%016x r15: 0x%016x"%(r(UC_X86_REG_R12), r(UC_X86_REG_R13), r(UC_X86_REG_R14), r(UC_X86_REG_R15)))
    print("     mxcsr: 0x%08x"%r(UC_X86_REG_MXCSR))

    return
    #rsp = r(UC_X86_REG_RSP)
    #for x in range(10):
    #    print("rsp+%x 0x%x"%(x*8, u64(mu.mem_read(rsp + x*8, 8))))




class Analyzer:
    """ analyze instructions as we disassemble them
    """
    def __init__(self):
        self.ks = Ks(KS_ARCH_X86, KS_MODE_64)

        self.inside_obfu = False
        self.next_is_good = False
        self.prev_inst = None

        self.within_interest = True
        self.stage = 0

        # instructions cache to be written
        self.insns = []

    def emit(self, ins):
        """ ins is either byte opcodes or a string
        if its a string, assemble it using keystone
        """
        if isinstance(ins, str):
            print("sc: " + ins)
            # by default keystone likes to encode instruction as rip relative when it can
            # we don't want that... https://github.com/keystone-engine/keystone/issues/295
            # i dont want to recompile, so using a huge "addr" does the trick :-)
            ins = self.ks.asm(ins, addr=0x133713371337, as_bytes=True)[0]
        
        self.insns.append(ins)
        return True

    def flush(self):
        """ write instructions cache to 'shellcode' stage file
        """
        print("dumping to stages/shellcode_%02d.bin"%self.stage)
        with open("stages/shellcode_%02d.bin"%self.stage, "wb") as fp:
            fp.write(b''.join(self.insns))

        # reset
        self.stage += 1
        self.insns = []

    def anal(self, mu, insb, i):
        """ analyze an instruction
        mu   = unicorn
        insb = instruction bytes
        i    = diassembled instruction

        return
            True if it is to be emited
            False otherwise

        this is the worst code ever
        """
        emit = False

        # i.address, i.mnemonic, i.op_str
        fulli = i.mnemonic + " " + i.op_str

        # enter obfuscator
        if i.mnemonic == "call":
            self.inside_obfu = True
            #print("skip: " + fulli)

        # out of obfuscator
        elif i.mnemonic in ("jmp", "ret", "hlt"):
            if self.prev_inst == "cmovne":
                emit = True
                #print('0x%08x %s %s'%(i.address, i.mnemonic, i.op_str))
            else:
                self.inside_obfu = False
                self.next_is_good = False
                #print("skip: " + fulli)

        # next instruction is good
        elif fulli == "pop rax" and self.inside_obfu:
            self.next_is_good = True
            #print("skip: " + fulli)

        # emit good instruction inside obfuscator + exit
        elif self.inside_obfu and self.next_is_good:
            emit = True
            self.next_is_good = False

        # skip shit
        elif self.inside_obfu:
            #print("skip: " + fulli)
            pass

        # emit non obfuscated
        elif not self.inside_obfu:
            emit = True
            #print('0x%08x %s %s'%(i.address, i.mnemonic, i.op_str))


        self.prev_inst = i.mnemonic

        if emit:
            # end of conditionnal block, flush it do disk
            if i.mnemonic == "test":
                self.within_interest = False
                self.emit(insb)
                self.flush()
                return True

            # the only jmp we should emit are the one after the cmovne, instead
            # we skip over jmp in order to reach the next conditionnal block
            elif i.mnemonic == "jmp":
                self.within_interest = True
                mu.reg_write(UC_X86_REG_RIP, mu.reg_read(UC_X86_REG_RIP) + i.size)
                #raise
                return False

            # at this stage, we should emit the instruction however...
            # let's do more check (to handle the tables)
            if i.mnemonic == "mov":
                #print(hex(mu.reg_read(i.operands[0].reg)))
                
                # table lookups seems to be always towards 8 bits regs
                if i.operands[0].reg in REGS_8BITS:
                    src_reg = i.operands[1].mem.base
                    src_addr = mu.reg_read(src_reg)

                    # check 2 instructions backward
                    p1 = disas_single(self.insns[-1], 0)
                    p2 = disas_single(self.insns[-2], 0)

                    # pattern =
                    # mov table, table_base
                    # add table, v
                    # mov res, [table]
                    #
                    # or 
                    # 
                    # mov reg.8b, v
                    # add reg, table_base
                    # mov res, [reg]
                    #
                    # = op(v)
                    if p1.mnemonic == "add" and p2.mnemonic == "mov":
                        print("BINGO_TABLE_MOVE 0x%x"%src_addr)
                        try:
                            # find op and value from table
                            op, v = tables.find(src_addr)
                            print([op, v])

                            # if first mov is a 32 bit reg, it contains the table offset
                            # otherwise it contains the base addr of the table
                            #
                            # sorry for the naming but:
                            # v       = operator value (from the table)
                            # tmp_reg = register we can use to hold a temp value
                            # var     = table index
                            # out_reg = register where the result must be stored
                            #
                            # so if the table is xor_18
                            #    v = 18
                            # and we need:
                            #    out_reg = xor(var, 18)
                            if p2.operands[0].reg in REGS_32BITS:
                                tmp_reg, var = p2.op_str.split(",")
                                out_reg = regs_8_to_64[i.op_str.split(",")[0]]
                            else:
                                tmp_reg, var = p1.op_str.split(",")
                                out_reg = regs_8_to_64[i.op_str.split(",")[0]]
                            print(tmp_reg, var, out_reg)
 
                        except:
                            #self.flush()
                            # raise and exception if we cannot find the table
                            raise
                            #op = ""
                            #pass

                        match op:
                            case "add":
                                # we need to pop the 2 previously emited instructions (add, mov)
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start add")
                                self.emit("mov %s,%s"%(tmp_reg, var))
                                self.emit("add %s, %d"%(tmp_reg, v))
                                self.emit("and %s, 0xff"%(tmp_reg))
                                self.emit("mov %s, %s"%(out_reg, regs_32_to_64[tmp_reg]))
                                print("--- end")
                                return

                            case "and":
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start and")
                                self.emit("mov %s,%s"%(tmp_reg, var))
                                self.emit("and %s, %d"%(tmp_reg, v))
                                self.emit("mov %s, %s"%(out_reg, regs_32_to_64[tmp_reg]))
                                print("--- end")
                                return

                            case "xor":
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start xor")
                                self.emit("mov %s,%s"%(tmp_reg, var))
                                self.emit("xor %s, %d"%(tmp_reg, v))
                                self.emit("mov %s, %s"%(out_reg, regs_32_to_64[tmp_reg]))
                                print("--- end")
                                return

                            case "rshift_x":
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start rshift_x")
                                self.emit("mov %s,%s"%(tmp_reg, var))
                                self.emit("shr %s, %d"%(tmp_reg, v)) 
                                self.emit("mov %s, %s"%(out_reg, regs_32_to_64[tmp_reg]))
                                print("--- end")
                                return

                            case "rshift_y":
                                # always shifting 1...
                                assert v == 1
                                # 1 >> val, return 1 if val == 0 else 0
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start rshift_y")
                                self.emit("mov %s, %s"%(tmp_reg, var))
                                self.emit("or %s, %s"%(tmp_reg, tmp_reg))
                                self.emit("setz %s"%(to_8bit_reg[tmp_reg]))
                                self.emit("movzx %s, %s"%(out_reg, to_8bit_reg[tmp_reg]))
                                print("--- end")
                                return

                            case "cmp_gt":
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start cmp_gt")
                                self.emit("mov %s, %d"%(tmp_reg, v))
                                self.emit("sub %s,%s"%(tmp_reg, var))
                                self.emit("shr %s, 8"%(tmp_reg))
                                self.emit("and %s, 1"%(tmp_reg))
                                self.emit("mov %s, %s"%(out_reg, tmp_reg))
                                print("--- end")
                                return

                            case "cmp_le":
                                self.insns.pop()
                                self.insns.pop()
                                print("--- start cmp_le")
                                self.emit("mov %s, %d"%(tmp_reg, v))
                                self.emit("sub %s,%s"%(tmp_reg, var))
                                self.emit("shr %s, 8"%(tmp_reg))
                                self.emit("and %s, 1"%(tmp_reg))
                                self.emit("xor %s, 1"%(tmp_reg))
                                self.emit("mov %s, %s"%(out_reg, tmp_reg))
                                print("--- end")
                                return
            
            # emit
            if self.within_interest:
                self.emit(insb)
                
            return True

        return False


# make it global...
ANAL = Analyzer()



class Context:
    """ deal with context
    """
    def __init__(self, mu, addr):
        # addr = address of DISPARTCHER_CONTEXT
        dbg("saving context...")
        self.mu = mu
        self.regs = {}
        self.mxcsr = None
        self.addr = addr

        self.context_addr = addr + 0x100
        offset = 0x78   # offset withing CONTEXT struct where we start storing our regs

        # store "normal" registers
        for n, reg in enumerate(REGS):
            self.regs[reg] = mu.reg_read(UNICORN_REGS[reg])
            ANAL.emit("mov [0x%x], %s"%(self.context_addr + offset + n*8, ASM_REGS[reg]))
        # store mxcsr
        self.mxcsr = mu.reg_read(UC_X86_REG_MXCSR)
        ANAL.emit("stmxcsr [0x%x]"%(self.context_addr + 0x34))

    def get_reg_addr(self, reg):
        """ get the absolute address of a register within the context struct
        """
        return self.context_addr + 0x78 + list(ASM_REGS.values()).index(reg) * 8

    def to_memory(self):
        """ save the context struct to unicorn memory
        """
        # addr is DISPATCHER_CONTEXT address
        dbg("context to mem...")
        offset = 0x78                        # start of regs in the struct

        # write CONTEXT struct
        for n, reg in enumerate(REGS):
            self.mu.mem_write(self.context_addr + offset + n*8, p64(self.regs[reg]))
        # write MxCsr
        self.mu.mem_write(self.context_addr + 0x34, p32(self.mxcsr))

        # fill in pointer in DISPATCHER_CONTEXT
        self.mu.mem_write(self.addr + 0x28, p64(self.context_addr))

    def dump(self):
        print("CTX  rax: 0x%016x rcx: 0x%016x rdx: 0x%016x rbx: 0x%016x"%(self.regs[REGS.RAX], self.regs[REGS.RCX], 
                                                                          self.regs[REGS.RDX], self.regs[REGS.RBX]))
        print("CTX  rsp: 0x%016x rbp: 0x%016x rsi: 0x%016x rdi: 0x%016x"%(self.regs[REGS.RSP], self.regs[REGS.RBP],
                                                                          self.regs[REGS.RSI], self.regs[REGS.RDI]))
        print("CTX  r8:  0x%016x r9:  0x%016x r10: 0x%016x r11: 0x%016x"%(self.regs[REGS.R8],  self.regs[REGS.R9],
                                                                          self.regs[REGS.R10], self.regs[REGS.R11]))
        print("CTX  r12: 0x%016x r13: 0x%016x r14: 0x%016x r15: 0x%016x"%(self.regs[REGS.R12], self.regs[REGS.R13],
                                                                          self.regs[REGS.R14], self.regs[REGS.R15]))
        print("CTX: mxcsr: 0x%08x"%(self.mxcsr))




class Unwinder:
    """ handle the unwinding
    """
    def __init__(self, mu, unwind_addr, ctx):
        self.mu   = mu              # unicorn
        self.addr = unwind_addr     # start of UNWIND_INFO
        self.ctx = ctx
        self.n_codes = None         # number of codes
        self.codes   = None         # raw codes bytes

    
        # parse UNWIND_INFO
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
        """ read a QWORD at addr
        i know, poor naming choice...
        """
        return u64(self.mu.mem_read(addr, 8))


    def do_unwind(self):
        """ execute unwind codes
        """
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

                    # assembly
                    rsp = self.ctx.get_reg_addr("rsp")
                    ANAL.emit("push rax")
                    ANAL.emit("mov rax, [0x%x]"%rsp)
                    ANAL.emit("add rax, %d"%offset)
                    ANAL.emit("mov rax, [rax]")
                    ANAL.emit("mov [0x%x], rax"%rsp)
                    ANAL.emit("pop rax")


                case UWND_CODE.UWOP_PUSH_NONVOL:
                    reg = REGS(unwind_op_info)

                    # check for input reading
                    if 0x14089b8e8 <= self.ctx.regs[REGS.RSP] < 0x14089b8e8+0x20:
                        print(" reading 8 bytes of input @ offset %d into %r"%(self.ctx.regs[REGS.RSP] - 0x14089b8e8, self.ctx.regs[reg]))

                    v = self.mem_read(self.ctx.regs[REGS.RSP])   # v = [rsp]
                    print(" PUSH %r = 0x%x (from: rsp=0x%x)"%(reg, v, self.ctx.regs[REGS.RSP]))
                    self.ctx.regs[reg] = v                       # regX = v
                    self.ctx.regs[REGS.RSP] += 8                 # rsp += 8

                    # emit assembly
                    rsp = self.ctx.get_reg_addr("rsp")
                    r = self.ctx.get_reg_addr(ASM_REGS[reg])
                    ANAL.emit("push rax")
                    ANAL.emit("mov rax, [0x%x]"%rsp)       # v = rsp
                    ANAL.emit("mov rax, [rax]")            # regX = [v]
                    ANAL.emit("mov [0x%x], rax"%r)         # regX = [v]

                    # add rsp, 8
                    ANAL.emit("mov rax, [0x%x]"%rsp)
                    ANAL.emit("add rax, 8")
                    ANAL.emit("mov [0x%x], rax"%rsp)
                    ANAL.emit("pop rax")


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

                    # emit assembly
                    rsp = self.ctx.get_reg_addr("rsp")
                    ANAL.emit("push rax")
                    ANAL.emit("mov rax, [0x%x]"%rsp)
                    ANAL.emit("add rax, %d"%size)
                    ANAL.emit("mov [0x%x], rax"%rsp)
                    ANAL.emit("pop rax")


                case UWND_CODE.UWOP_ALLOC_SMALL:
                    size = unwind_op_info * 8 + 8
                    self.ctx.regs[REGS.RSP] += size
                    print(" ALLOC %d"%size)

                    # emit assembly
                    rsp = self.ctx.get_reg_addr("rsp")
                    ANAL.emit("push rax")
                    ANAL.emit("mov rax, [0x%x]"%rsp)
                    ANAL.emit("add rax, %d"%size)
                    ANAL.emit("mov [0x%x], rax"%rsp)
                    ANAL.emit("pop rax")


                case UWND_CODE.UWOP_SET_FPREG:
                    self.ctx.regs[REGS.RSP] = self.ctx.regs[REGS(self.frame_reg)]
                    self.ctx.regs[REGS.RSP] -= self.frame_offset * 16
                    print(" rsp = 0x%x off=0x%x reg=%r"%(self.ctx.regs[REGS.RSP], self.frame_offset, REGS(self.frame_reg)))

                    # emit assembly
                    reg = REGS(self.frame_reg)
                    rsp = self.ctx.get_reg_addr("rsp")
                    r = self.ctx.get_reg_addr(ASM_REGS[reg])
                    ANAL.emit("push rax")
                    ANAL.emit("mov rax, [0x%x]"%r)
                    ANAL.emit("sub rax, %d"%(self.frame_offset * 16))
                    ANAL.emit("mov [0x%x], rax"%rsp)
                    ANAL.emit("pop rax")


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
        print(">>  0x%x %s %s"%(i.address, i.mnemonic, i.op_str))

    def hook_code(self, mu, addr, size, user_data):
        """ hook every instruction
        """
        mem = mu.mem_read(addr, size)
        dis = disas_single(mem, addr)


        if ANAL.anal(mu, mem, dis):
            self.log_instruction(mu, dis)
        #else:
        #    self.log_instruction(mu, dis)

        #
        # maaaagic
        #
        if dis.mnemonic == "hlt":
            self.handle_exception(mu, addr)
            return


    def handle_exception(self, mu, addr):
        """ do stuff when we run through an HLT instruction
        """
        ctx = Context(mu, self.dis_ctx_addr)   # initialize context
            
        # how many bytes to skip before findind the unwind_handle
        # byte at faulty rip + 1
        unwind_addr = mu.mem_read(addr + 1, 1)[0] + addr + 2
        # alignment
        if unwind_addr & 1:
            unwind_addr += 1

        if DEBUG:
            ctx.dump()

        # unwind
        unwinder = Unwinder(mu, unwind_addr, ctx)
        exception_handler_addr = unwinder.do_unwind()

        # unwinder returns an offset, make it absolute
        exception_handler_addr += self.code_addr

        if DEBUG:
            ctx.dump()

        print("HANDLER ADDR: 0x%x"%exception_handler_addr)

        # save CONTEXT to memory
        ctx.to_memory()
        
        #
        # setup call context
        #
        # https://learn.microsoft.com/en-us/cpp/build/exception-handling-x64?view=msvc-170
        # PARAMS
        # typedef EXCEPTION_DISPOSITION (*PEXCEPTION_ROUTINE) (
        #   IN PEXCEPTION_RECORD ExceptionRecord,
        #   IN ULONG64 EstablisherFrame,
        #   IN OUT PCONTEXT ContextRecord,
        #   IN OUT PDISPATCHER_CONTEXT DispatcherContext
        #   );
        mu.reg_write(UC_X86_REG_RCX, 0)                  # ExceptionRecord,
        mu.reg_write(UC_X86_REG_RDX, 0)                  # EstablisherFrame,
        mu.reg_write(UC_X86_REG_R8,  0)                  # ContextRecord,
        mu.reg_write(UC_X86_REG_R9, self.dis_ctx_addr)   # DispatcherContext
        mu.reg_write(UC_X86_REG_RAX, exception_handler_addr)
        mu.reg_write(UC_X86_REG_RIP, exception_handler_addr)

        # emit assembly
        ANAL.emit("mov r9, 0x%x"%self.dis_ctx_addr)




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
        initial_rsp = 0x00000000069FFEB0
        mu.mem_map(0x67f0000, 0x400000)
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
        self.dis_ctx_addr = 0x1000
        mu.mem_map(self.dis_ctx_addr, 0x2000)

        #
        # init
        #
        # need to setup the input key somewhere...
        if len(sys.argv) == 2:
            key = sys.argv[1].encode()
        else:
            key = b'AAAABBBBCCCCDDDDaaaabbbbccccdddd'
            key = b'\xd0AAA\x0fAAA\x4aAAA\x7fAAA\xe2AAA\xd2AAA\xd2AAA\xceAAA'
            #key = b"$K@ >s@@j{@@9P @BK@@'=  O~ @: @@"
            #key = b'W{F@q_K@"j4@eZD@]y|@C34 %-\'@cnL@'
            #key = b'\\q7&H?YIS7l-_!2mDd?n-D6m~"CE.gvr'
            #key = b'$$_6g"X<0E.pMR4p}e>FXST{\'hVi~2V2'

        key_addr = 0x14089b8e8
        mu.mem_write(key_addr, key)


        # install hook
        mu.hook_add(UC_HOOK_CODE, self.hook_code)
        

        # emit instructions to setup the initial context
        ANAL.emit("mov rcx, 0x%x"%(self.dis_ctx_addr+0x100))
        ANAL.emit("mov [0x%x], rcx"%(self.dis_ctx_addr + 0x28))
        ANAL.emit("mov rcx, 0x%x"%key_addr)
        mu.reg_write(UC_X86_REG_RCX, key_addr)

        # let's go, disco
        try:
            mu.emu_start(self.code_addr, 0x1400011f0)
        except unicorn.UcError as e:
            print("CRASH")
            Context(mu, self.dis_ctx_addr).dump()


if __name__ == "__main__":
    emu = Emu()
    emu.emu()
        
    ANAL.flush()


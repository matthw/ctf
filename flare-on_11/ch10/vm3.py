
import sys
from triton import *
from malduck import u32, p32, u64, p64

BYTECODE_BASE = 0x600000
BYTECODE_PTR = 0x00e85a8


with open('uefi_shell.pe', 'rb') as fp:
    fp.seek(0x31274)
    VM_CODE = fp.read(0x31933 - 0x31274 + 1)


def read_enc_file(fname):
    header_size = 0x10

    with open(fname, 'rb') as fp:
        assert fp.read(4) == b'C4TB'
        enc_data_len    = u32(fp.read(4))
        bytecode_offset = u32(fp.read(4))
        bytecode_len     = u32(fp.read(4))

        # read enc_data
        fp.seek(header_size)
        enc_data = fp.read(enc_data_len)

        # read bc
        fp.seek(bytecode_offset)
        bytecode = fp.read(bytecode_len)

    return (enc_data, bytecode)


def emulate(ctx, pc):
    while pc:
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction(pc, opcode)
        addr = instruction.getAddress()
        ctx.processing(instruction)
        #print(instruction)

        # CMP VM handler
        if addr == 0x314c6:
            r9 = ctx.getConcreteRegisterValue(ctx.registers.r9)
            v1 = u64(ctx.getConcreteMemoryAreaValue(r9, CPUSIZE.QWORD))
            v2 = u64(ctx.getConcreteMemoryAreaValue(r9 - 8, CPUSIZE.QWORD))

            print("%x CMP 0x%08x , 0x%08x"%(addr, v1, v2))
            r = ctx.getSymbolicRegister(ctx.registers.zf)
            
            # push zf == 1 if it's symbolized
            if r is not None:
                r = r.getAst()
                ctx.pushPathConstraint(r == 1)
                mod = ctx.getModel(ctx.getPathPredicate())
                for k,v in list(mod.items()):
                    ctx.setConcreteVariableValue(ctx.getSymbolicVariable(v.getId()), v.getValue())

            
        if instruction.getType() == OPCODE.X86.RET:
            break

        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)





def main(argv):
    enc_data, bytecode = read_enc_file(argv[1])

    ctx = TritonContext(ARCH.X86_64)
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    ctx.setSolver(SOLVER.BITWUZLA)

    ast = ctx.getAstContext()

    # stack crap
    ctx.setConcreteRegisterValue(ctx.registers.rbp, 0x9ffffff0)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, 0x9ffffff0)

    # load VM bytecode
    ctx.setConcreteMemoryAreaValue(BYTECODE_BASE, bytecode)
    ctx.setConcreteMemoryAreaValue(BYTECODE_PTR, p64(BYTECODE_BASE))

    # load VM interpreter
    ctx.setConcreteMemoryAreaValue(0x31274, VM_CODE)

    # key shizzle
    key = b'poopoopoopoopoop'
    sym_key = []
    key_offsets = (0x5,  0x4,  0xc,  0xb,  0x13, 0x12, 0x1a, 0x19,
                   0x21, 0x20, 0x28, 0x27, 0x2f, 0x2e, 0x36, 0x35)
    
    for n, offset in enumerate(key_offsets):
        ctx.setConcreteMemoryValue(BYTECODE_BASE + offset, key[n])
        var = ctx.symbolizeMemory(MemoryAccess(BYTECODE_BASE + offset, CPUSIZE.BYTE))

    emulate(ctx, 0x31274)


if __name__ == "__main__":
    main(sys.argv)

    


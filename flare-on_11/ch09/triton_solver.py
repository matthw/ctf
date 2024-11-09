#!/usr/bin/env python
import sys
from triton import *

# random addresses
BASE_ARGV  = 0x20000000
BASE_STACK = 0x9ffffff0
BASE_CODE  = 0x600000

# not random stuff
FLAG_ADDR = 0x14089b8e8
FLAG_LEN = 0x20


def emulate(ctx, pc):
    test_count = 0

    while pc:
        opcode = ctx.getConcreteMemoryAreaValue(pc, 16)
        instruction = Instruction(pc, opcode)
        addr = instruction.getAddress()

        ctx.processing(instruction)
        #print(instruction)

        # test instruction
        if instruction.getType() == OPCODE.X86.TEST:
            test_count += 1

            register = instruction.getOperands()[0]
            print("testing %s @ 0x%x"%(register.getName(), addr))
            r = ctx.simplify(ctx.getSymbolicRegister(register).getAst())

            # we want that register to be 0
            ctx.pushPathConstraint(r == 0)
            
        # got enough "test", get model
        if test_count == 32:
            mod = ctx.getModel(ctx.getPathPredicate())
            for k,v in list(mod.items()):
                ctx.setConcreteVariableValue(ctx.getSymbolicVariable(v.getId()), v.getValue())

            flag = ''
            for x in range(FLAG_LEN):
                flag += chr(ctx.getConcreteMemoryValue(FLAG_ADDR + x))
            print("flag: %s@flare-on.com"%flag)

            sys.exit(0)

        # set rip
        pc = ctx.getConcreteRegisterValue(ctx.registers.rip)


def main():
    ctx = TritonContext(ARCH.X86_64)
    # Set a symbolic optimization mode
    ctx.setMode(MODE.ALIGNED_MEMORY, True)
    ctx.setMode(MODE.ONLY_ON_SYMBOLIZED, True)
    ctx.setSolver(SOLVER.BITWUZLA)
    
    ast = ctx.getAstContext()

    # load code
    ctx.setConcreteMemoryAreaValue(BASE_CODE, open("stages/full.bin", "rb").read())


    # setup key
    key = b'********************************'
    ctx.setConcreteMemoryAreaValue(FLAG_ADDR, key + b'\x00')

    # symbolize key
    for i in range(len(key)):
        var = ctx.symbolizeMemory(MemoryAccess(FLAG_ADDR + i, CPUSIZE.BYTE))
        #vast = ast.variable(var)
        #ctx.pushPathConstraint(ast.land([vast >= ord(b' '), vast <= ord(b'~')]))
 

    # stack
    ctx.setConcreteRegisterValue(ctx.registers.rbp, BASE_STACK)
    ctx.setConcreteRegisterValue(ctx.registers.rsp, BASE_STACK)

    # fire
    emulate(ctx, BASE_CODE)


if __name__ == "__main__":
    main()

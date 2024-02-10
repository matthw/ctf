import sys
import zlib
from pwn import p32


print("""
typedef struct {
    uint32_t crc32;
    uint8_t  num_ins;
    uint8_t  code[16];
} instruction;


instruction insns[] =
{
""")

def print_line(crc, num, opcodes):
    print("    {0x%08x, 0x%02x, {"%(crc, num), end='')
    print(", ".join(["0x%02x"%_ for _ in opcodes]), end='')
    print("}},")


with open(sys.argv[1], 'r') as fp:
    for line in fp:
        line = line.strip().split()
        addr = int(line[0], 16)
        bytecode = bytes.fromhex(''.join(line[1:]))
        numops = len(bytecode)
        bytecode = bytecode.ljust(16, b'\x00')
        crc = zlib.crc32(p32(addr & 0xfff))
        print_line(crc, numops, bytecode)

print_line(0, 0, b'\x00'*16)

print("};")


def split(line, n):
    return [line[i:i+n] for i in range(0, len(line), n)]

data = open("libdance.so_patched", "rb").read()

print("static ssize_t libsize = %d;"%len(data))
print("uint8_t  libdata[] = {")
for line in split(data, 16):
    print("    ", end="")
    for c in line:
        print("0x%02x, "%c, end='')
    print("")
print("};")


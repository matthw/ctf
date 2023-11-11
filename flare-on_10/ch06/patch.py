data = bytearray(open("FlareSay.exe.ori", "rb").read())

# mov ah, dl; nop
data[0x674] = 0x88
data[0x675] = 0xd4
data[0x676] = 0xd0

# mov dh, dl; nop
data[0x677] = 0x88
data[0x678] = 0xd6
data[0x679] = 0x90

#data[0x9eb] = 2
open("flaresay.exe", "wb").write(data)

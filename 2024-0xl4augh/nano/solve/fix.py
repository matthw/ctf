data = open("nano", "rb").read()

# nop anti disass
data = data.replace(b"\x74\x03\x75\x01\xe8", b"\x90\x90\x90\x90\x90")

open("nano_fixed", "wb").write(data)

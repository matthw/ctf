## 10. CATBERG Ransomware

Almost complete blackbox solve.

use `uefiextract` to get the shell PE ([uefi_shell.pe](uefi_shell.pe)), then reverse it enough
to notice the VM interpreter is for the most part "self contained" into a single function
without any further function call except for the "PUTCHAR" opcode (and we can deal with it should we need it - but we don't).

Since debugging UEFI seems like a pain, we can feed that function only to an emulator and play with it=)

VM interpreter is at `0x00031274`, the rest (file format, etc...) is better described in the [official solution](https://services.google.com/fh/files/misc/flare-on11-challenge10-catbert-ransomware.pdf).


### VM 1 & 2

The 2 first VMs can be side-channel'd by counting the instructions: there's an early exit
condition whenever a password char is invalid, we can abuse that to brutefoce it character by
character.

I'm using Triton here because I was trying the symbolic way. Unicorn would probably be faster
but the runtime benefit was nullified by the time required to rewrite it :-)

```
% python vm1_and_2.py ./enc/catmeme1.jpg.c4tb
bytearray(b'D\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'Da\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaC\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCu\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCub\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubi\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubic\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubicl\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubicle\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubicleL\x00\x00\x00\x00\x00\x00')
bytearray(b'DaCubicleLi\x00\x00\x00\x00\x00')
bytearray(b'DaCubicleLif\x00\x00\x00\x00')
bytearray(b'DaCubicleLife\x00\x00\x00')
bytearray(b'DaCubicleLife1\x00\x00')
bytearray(b'DaCubicleLife10\x00')
bytearray(b'DaCubicleLife101')
```
```
% python vm1_and_2.py ./enc/catmeme2.jpg.c4tb
bytearray(b'G\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3t\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tD\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDa\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0\x00\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0b\x00\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0bD\x00\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0bD0\x00\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0bD0n\x00\x00\x00\x00\x00')
bytearray(b'G3tDaJ0bD0ne\x00\x00\x00\x00')
bytearray(b'G3tDaJ0bD0neM\x00\x00\x00')
bytearray(b'G3tDaJ0bD0neM4\x00\x00')
bytearray(b'G3tDaJ0bD0neM4t\x00')
bytearray(b'G3tDaJ0bD0neM4te')
```

### VM 3

VM 3 can't be abused this way. I made a symbolic solver with Triton, pushing path constraints
everytime there's a symbolized `CMP` VM handler (takes a while to solve: 50mins on my computer).

```
% time python vm3.py ./enc/catmeme3.jpg.c4tb
314c6 CMP 0x7c9c60e3 , 0x7c8df4cb
flag: Ves8????????????
314c6 CMP 0x7ff80fff , 0x8b681d82
flag: Ves8DumB????????
314c6 CMP 0x08e401f9 , 0x0f910374
flag: Ves8DumBs]yz_zmj
314c6 CMP 0x489fdf28 , 0x31f009d2
flag: VerYDumBpassword
314c6 CMP 0x00000004 , 0x00000004
python vm3.py ./enc/catmeme3.jpg.c4tb  3035.92s user 0.32s system 99% cpu 50:37.12 total
```

## 1. Back to the future

The real challenge here was that i was mostly reversing in sweat pants, crashing on my sofa and the PDP11 emulator liked to max out one my CPU core, having the side effect of draining my battery and having me regularly run for power. That helped reaching the 10000 steps a days fitness goal.

Anyway, I fiddled around 5 mins to attach the tape, then getting to run the binary was pretty straightfoward, as i used to type the same during my solaris 2.6 days:

```
# stty erase ^H
# cat /dev/rmt12 > readme.txt
# cat /dev/rmt12 > hell.Z
# file hell.Z
hell.Z: block compressed 12 bit code data
# uncompress hell
# chmod +x ./hell
# ./hell
MoogleForth starting. Stack: 3802
```

I took the first random hexdump.c from github and compiled it inside the guest so i could exfil the binary.

You can load it in any PDP11 capable disassembler. If it doesnt understand the oldschool `a.out` format, just skip the first 0x10 bytes.

The symbols and their addresses can be acquired with the `nm` command if you dont want to write a proper loader.


## 2. Ancient DeBugger (ADB)

I did everying using `adb`, not the android debugger, but some gdb ancestor. 

Every 5 minutes spent in there make you spend 1 minute of silence out of respect for the people who actually had to work with that. We're so spoiled with modern tooling :)

The source code lies somewhere on github and is a [piece of art](https://github.com/RetroBSD/2.11BSD/blob/master/usr/bin/adb/command.c).

Anyway, it has everything you could hope for:

- It can disassemble 34 instructions starting from the `decrypt` symbol:

```
adb> decrypt,34?ai
decrypt:        mov     r2,-(sp)
decrypt+02:     mov     r3,-(sp)
decrypt+04:     mov     r4,-(sp)
decrypt+06:     mov     r5,-(sp)
decrypt+010:    jsr     r4,bl
decrypt+014:    swab    -(r2)
decrypt+016:    mov     (sp)+,r4
decrypt+020:    jsr     r4,parse
decrypt+024:    swab    *-(r2)
decrypt+026:    mov     (sp)+,r4
decrypt+030:    mov     (r5)+,r3
decrypt+032:    mov     (r5)+,r1
decrypt+034:    mov     (r5),r2
decrypt+036:    mov     02(r5),r0
decrypt+042:    mov     r3,-(sp)
decrypt+044:    cmp     r2,r3
decrypt+046:    bgt     decrypt+054
decrypt+050:    mov     r2,r3
decrypt+052:    beq     decrypt+076
decrypt+054:    sub     r3,r2
decrypt+056:    movb    (r0),r4
decrypt+060:    movb    (r1)+,r5
decrypt+062:    xor     r4,r5
decrypt+064:    movb    r5,(r0)+
decrypt+066:    sob     r3,decrypt+056
decrypt+070:    mov     (sp),r3
decrypt+072:    sub     r3,r1
decrypt+074:    br      decrypt+044
decrypt+076:    tst     (sp)+
decrypt+0100:   mov     (sp)+,r5
decrypt+0102:   mov     (sp)+,r4
decrypt+0104:   mov     (sp)+,r3
decrypt+0106:   mov     (sp)+,r2
decrypt+0110:   mov     (r4)+,pc
``` 

- you can place breakpoints and run the program

```
adb> decode:b
adb> :r
./hell: running
MoogleForth starting. Stack: 3802
decode lol
breakpoint      decode:         jsr     r4,_docol
```

- you can single step
```
adb> :s
./hell: running
stopped at      zero:           jsr     pc,_const
adb> :s
./hell: running
stopped at      _const:         mov     *(sp)+,-(r5)
adb> :s
./hell: running
stopped at      _const+02:      mov     (r4)+,pc
adb> :s
./hell: running
stopped at      tor:            mov     (r5)+,-(sp)
adb> :s
./hell: running
stopped at      tor+02:         mov     (r4)+,pc
adb> :s
./hell: running
stopped at      dup:            mov     (r5),-(r5)
adb> :s
./hell: running
stopped at      dup+02:         mov     (r4)+,pc
adb> :s
./hell: running
stopped at      if:             mov     (r4)+,r0
adb> :s
./hell: running
stopped at      if+02:          tst     (r5)+
adb> :s
./hell: running
stopped at      if+04:          bne     if+010
adb> :s
./hell: running
stopped at      if+010:         mov     (r4)+,pc
adb> :s
./hell: running
stopped at      swap:           mov     (r5)+,r0
adb> :s
./hell: running
stopped at      swap+02:        mov     (r5),-(r5)
adb> :s
./hell: running
stopped at      swap+04:        mov     r0,02(r5)
```

- dump registers:

```
adb> $r
ps      0170000
pc      01376   swap+04
sp      0177636
r5      07332   _data_s0
r4      0246
r3      06634
r2      06427
r1      06
r0      062544
swap+04:        mov     r0,02(r5)
```

- and also dump memory:

```
adb> 07332,20?o
07332:          067543  067543  062544  066040  066157  040     0       0
                0       0       0       0       0       0       0       0
                0       0       0       0
```

Note that adb is part of a weird cult that favours octal over anything else.


## 3. Strategy (like i have one)

Even though the forth interpreter binary is kind of a piece of art, i took the dynamic route.

There's 3 interesting words: `decrypt`, `decode` and `secret`
- `secret` will load the symbol `_secret` (which is our secret, prefixed by its size).
- `decrypt` is purely written in assembly and is just xoring two buffers together
- `decode` is word made of other forth words.

i singled stepped this last one, taking note of each symbol change (as they match the forth words) and watching the forth stack (which is located +/- at an address pointed by the r5 register).

and this gets us the flag:
```python
from pwn import xor

def decode(meh):
    acc = 0
    meh = bytearray(meh)
    for n, c in enumerate(meh):
        acc += c
        meh[n] = acc % 128
    return bytes(meh)

def decrypt(meh):
    return xor(meh, b'p/q2-q4!')    # with Ken Thompson's password

# skip the first 2 bytes (the length)
secret = bytes.fromhex("2E 00 1B D5 78 C3 2F 7C C2 DA 75 2E 78 32 D6 7B D8 23 7D D9 8A 31 3D 86 CC 2C 81 2D 7C C4 D6 74 3F 27 82 F6 57 34 D8 60 C7 E9 32 D0 B1 07 21 8F 5A 0F")[2:]

print(decode(decrypt(secret)))
```


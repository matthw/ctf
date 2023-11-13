## 1. Extract MBR

```
dd if=hda.img of=mbr.bin bs=512 count=1
```

load in ghidra as `x86:LE:16:Real Mode` with base address `0x7c00`
reverse, see it does stuff, decrypts more code and jump at 0x1000


## 1. Dump stuff

```
% qemu-system-i386 -drive file=hda.img,format=raw -s -S
% gef
> set architecture i8086
> target remote localhost:1234
> break *0x1000
> dump memory 0x1000.bin 0x1000 0x8c00
```

gdb craps itself a bit at disassembling 16bit code but it's ok, we can survive.

## 2. Reverse more

load the newly acquired dump in your favorite tool and get the first part of the of decryption key by xoring the victim id

```
>>> xor(bytes.fromhex("3487B3B41F20"), 0x55).hex()
'61d2e6e14a75'
```

## 3. Bruteforce much

The function at `0x1296` is supposed to return 0 if the key is correct, we can use this to our advantage and write a quick unicorn [harness](harness.py) and bruteforce the last bytes of the key.
The script runs a couple minutes and returns `b'\x04\n\r\x0c'` which means the last part of the key is `4ADC` and the full key `61D2E6E14A754ADC`

Use the key, watch the disk being decrypted, reboot and get the flag. Easy peasy Moneypenny.

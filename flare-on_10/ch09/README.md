```
% qemu-system-i386 -drive file=hda.img,format=raw -s -S
% gef
> set architecture i8086
> target remote localhost:1234
> break *0x7c00
> break *0x1000
> dump memory 0x1000.bin 0x1000 0x8c00
```

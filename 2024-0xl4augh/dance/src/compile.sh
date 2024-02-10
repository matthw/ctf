#!/bin/sh
#
# compile lib
# this is a lame attempt at keeping the number of instruction under 0xfff
# otherwise i get screwd by ASLR and i dont want to fix it
gcc -O3 -Wno-attributes crc32.c -c -fpic
gcc -O1 -Wno-attributes chacha20.c  -c -fpic       # prevent optimization to dexor the expand32...
gcc -Wno-attributes libdance.c -c -fpic
gcc -Wno-attributes libdance.o chacha20.o crc32.o -shared -o libdance.so
strip -s libdance.so

# generate opcode table
./build_table.sh > dance_ops.h

# patch lib
python patch_lib.py

# generate lib include
python generate_include.py > dance.h

# compile bin
gcc -Wno-attributes dance.c chacha20.c crc32.c -o dance
strip -s dance

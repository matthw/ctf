#!/bin/bash

#objdump -M intel --no-addresses --wide -j .text -d libdance.so \
#    | sed 's/^\t//' \
#    | sed 's/\t/ /g' \
#    | sed 's/   *.*$//'



objdump -M intel --wide -j .text -d libdance.so \
    | sed 's/^\s*//' \
    | sed 's/:\t/: /' \
    | sed 's/\t/ /g' \
    | sed 's/   *.*$//' \
    | awk '
        BEGIN { p=0 }
        /dance_with_me@@Base-/ { p = 1; next } 
        p == 1 { print }' \
    | grep -v "^$" \
    | grep -v ">" \
    | sort -R \
    | sed 's/://' > /tmp/table.$$

python generate_include_opcode.py /tmp/table.$$


rm /tmp/table.$$


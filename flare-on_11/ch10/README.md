## 10. Catberg Ransomware

almost complete blackbox solve.

use `uefiextract` to get the shell PE ([uefi_shell.pe](uefi_shell.pe)).

### VM 1 & 2

The 2 first VM can be side-channel'd by counting the instructions: there's an early exit
condition whenever a password char is invalid, we can abuse that to brutefoce it character by
character.

i'm using Triton here because I was trying the symbolic way. Unicorn would probably be faster
but the runtime benefit was nullified by the time required to rewrite it :-)

```
% python vm1_and_2.py ./enc/catmeme1.jpg.c4tb
% python vm1_and_2.py ./enc/catmeme2.jpg.c4tb
```

### VM 3

VM 3 can't be abused this way, I made a symbolic solver with Triton, pushing path constraints
everytime there's a symbolized `CMP` VM handler (takes a while to solve...)

```
% python vm3.py ./enc/catmeme1.jpg.c4tb
```

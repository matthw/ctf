## 1. NOPE

This was enough of a pain to reverse and go through, i'm not going to do it again for a writeup.

It is tedious but there's a lot to learn for aspiring malware analysts/reverse engineers, I encourage you to do it (partly to share our pain).


## 2. Bruteforce like an idiot.

At some point you need a crc32 to match, and i missed the whole date check stuff, so i just [bruteforced](find_key_for_crc.py) it.

It uses a modified RC4, so i just emulated the function with unicorn instead of coding and testing...

It spits out the character that goes in front of `pizza`

## 3. Flag

```
C:\Users\me\Desktop\f\c03>mypassion.exe "00gRRR@brUc3E/1337pr.ost/20AAAAAAAA/!pizza/AMu$E`0R.~AZe/YPXEKCZXYIGMNOXNMXPYCXGXN/ob5cUr3/fin/"
RUECKWAERTSINGENIEURWESEN
b0rn_t0_5truc7_b4by@flare-on.com
``` 

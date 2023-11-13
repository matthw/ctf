A fun challenge that could have been slightly harder

## 1. Oh Noes... RUST.

We get a pcap and rust binary, obviously the answer lies within the pcap.

The binary embeds two full blown PE, xorred with an obvious key:

```
000ad1b0  40 63 50 65 74 65 72 72  40 63 50 65 74 65 72 72  |@cPeterr@cPeterr|
000ad200  40 63 50 65 74 65 72 72  40 63 50 65 74 65 71 72  |@cPeterr@cPeteqr|
000ad220  50 63 50 65 2c 65 72 f2  40 63 50 65 74 65 72 72  |PcPe,er.@cPeterr|
000ad230  40 63 50 65 74 65 73 72  41 63 50 65 04 65 72 f2  |@cPetesrAcPe.er.|
000ad240  40 63 50 65 74 65 72 72  40 63 50 65 74 65 73 72  |@cPeterr@cPetesr|
000ad250  41 63 50 65 fc 65 72 f2  40 63 50 65 74 65 72 72  |AcPe.er.@cPeterr|
000ad260  40 63 50 65 74 65 73 72  41 63 50 65 d4 65 72 f2  |@cPetesrAcPe.er.|
000ad270  40 63 50 65 74 65 72 72  40 63 50 65 74 65 73 72  |@cPeterr@cPetesr|
```

It will inject them into `svchost.exe`, but we just extract them and run manually run them
because we're wild.

## 2. It will ruin your VM

The first binary will infect every executable in %APPDATA%, it will most likely ruin you VM but
it is definitly worth it !

[sus](pics/sus.png)

## 3. Abuse the implant!

The second binary will run some sort of bindshell, it can be abused to decrypt the transfered files by [replaying](comm.py) the content of the pcap.

The flag is in the wallpaper.

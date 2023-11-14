## 1. The Crypto Challenge

The reversing is pretty straightforward: you get two threads.
- 1 thread looks for files with a certain extension
- 1 thread encrypts said files

OpenSSL is statically compiled but there's load of debug strings with filenames and line numbers.

A random key is generated and used to encrypt the file using a sort of ChaCha20.

The 256 bytes cipher context is then encrypted using textbook RSA with the following public key and then append to the encrypted file:

```
-----BEGIN PUBLIC KEY-----
MIIBIDANBgkqhkiG9w0BAQEFAAOCAQ0AMIIBCAKCAQEAycMwco9oCHr8YKEz5Jud
PeSfD/mZXF4S5cZcEYl7xxjj5NJy1aWM5GN1WyxjRn8NCfk8Mctn/jGICa9/yLLI
xyGrVHzk22Pb3/9dmwbIV5n97mkPkMR5xtC546P2blXWMCnOWgLvhMaq3F4iQWgw
JMxl11ZCr+C6vnbymmd86xWb5IuzJl69K9UZoq9+A2zC5kAcN1VXYagcPR0opFbD
i5G1WQNb/wE92gQ5BTuelvSyePcZ6Tnmd9BYvG6YAFr/IwgUpJerNLf6kCtmbRgN
6E4k6Q91PXnbC3IXrLXEb00apWvuVz8tR6Qzfd0eK5Z+3HA4/usJDex0ktlNlom7
YQIBAw==
-----END PUBLIC KEY-----
```

which has the following properties:

```
% openssl rsa -pubin -in pubkey.pem -text -noout
Public-Key: (2048 bit)
Modulus:
    00:c9:c3:30:72:8f:68:08:7a:fc:60:a1:33:e4:9b:
    9d:3d:e4:9f:0f:f9:99:5c:5e:12:e5:c6:5c:11:89:
    7b:c7:18:e3:e4:d2:72:d5:a5:8c:e4:63:75:5b:2c:
    63:46:7f:0d:09:f9:3c:31:cb:67:fe:31:88:09:af:
    7f:c8:b2:c8:c7:21:ab:54:7c:e4:db:63:db:df:ff:
    5d:9b:06:c8:57:99:fd:ee:69:0f:90:c4:79:c6:d0:
    b9:e3:a3:f6:6e:55:d6:30:29:ce:5a:02:ef:84:c6:
    aa:dc:5e:22:41:68:30:24:cc:65:d7:56:42:af:e0:
    ba:be:76:f2:9a:67:7c:eb:15:9b:e4:8b:b3:26:5e:
    bd:2b:d5:19:a2:af:7e:03:6c:c2:e6:40:1c:37:55:
    57:61:a8:1c:3d:1d:28:a4:56:c3:8b:91:b5:59:03:
    5b:ff:01:3d:da:04:39:05:3b:9e:96:f4:b2:78:f7:
    19:e9:39:e6:77:d0:58:bc:6e:98:00:5a:ff:23:08:
    14:a4:97:ab:34:b7:fa:90:2b:66:6d:18:0d:e8:4e:
    24:e9:0f:75:3d:79:db:0b:72:17:ac:b5:c4:6f:4d:
    1a:a5:6b:ee:57:3f:2d:47:a4:33:7d:dd:1e:2b:96:
    7e:dc:70:38:fe:eb:09:0d:ec:74:92:d9:4d:96:89:
    bb:61
Exponent: 3 (0x3)
```

Few things ring a bell here:
- the low exponent (3)
- the fact that RSA encrypted message always starts by a bunch of zeros (no proper padding)
- the last 16 bytes of that message are always `expand 32-byte k`

Googling leads to Coppersmith and few CTF writeups like:
- https://medium.com/@hva314/some-basic-rsa-challenges-in-ctf-part-2-applying-theoretical-attack-55a2cc7baa11
- https://hgarrereyn.gitbooks.io/th3g3ntl3man-ctf-writeups/content/2017/UIUCTF/problems/Cryptography/papaRSA/


which translates to the following sagemath script:
```python
# RsaCtfTool.py --dumpkey --publickey pubkey.pem
n = 25470150703730072315086034936055649836295236884601534304156993296936285040601301375939610442634162257314189499275100972455566398455602026574433195970815202585090501432569441133857842325042217925159448570072586058996240505604332536419689764920477213974406475165093073579216369638057129512420088827606714396031123135244463251843168817519429473193827165432916372277360150211932008151288302906204095482949720169306181114320172114379252171541724857670073249548632622866650173757036971232388781059615489960396402755953330835572369467647829965472365925514887194394952977362957692659807638830075891677256168792219800752995169
e = 3

# crypted message
c = 2425592482954093142911053394287864523808964564181573160646727426912420816161421295499810615636292488448086115375476578572126347389008149317940146698511301628342882097728861790163917385171608505786502099378180432350549613073164000743046053171252337966368352372410009389267473352698726296264255749133362831429534971651466910078754923485995987572417696906602747262956933918749969313809832939636800411857199483428558375468904127868025514462771636245588377871475012975670951402940280762132382274242486303138563790236596067661371781157135962527788369561955804123957047366621254000506424769282365883497834294487244664347316

# known message
msg = int(b'expand 32-byte k'.hex(), 16)
P.<x> = PolynomialRing(Zmod(n))
# ^16 = len(message)
f = (msg + ((2^8)^16)*x)^e - c
f = f.monic()
f = f.small_roots(epsilon=1/20)[0]

recovered = bytes.fromhex("0" + hex(f)[2:]) + b'expand 32-byte k'
print(recovered)
print(len(recovered))
```

This is all black magic to me and even though I found all the leads (my googling improved since challenge 4), I just couldn't make the maths work without the help of a beautiful numbers crushing nerd (to my defense, I was 18 when i last attended a mathematics course and that was 20y ago, so close tho...).

Using a debugger, we can then patch the decrypted context into memory, let the binary decrypt the file for us and call it a day.


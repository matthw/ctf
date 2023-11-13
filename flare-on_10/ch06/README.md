This was one of my favorite challenge this year

## 1. WIN32

Upon loading you face something that looks like a malformed PE.

After giving it a bit of love, the truth reveals itself.

It calculates the hash of some 16 bytes memory region and if it is equal to `0x31d9f5ff` it will do some crypto magic, decrypt some data and display a popup.
BUT the key is zero'd, so we need to find it.



```python

undefined8 entry(undefined8 param_1,undefined2 param_2)

{
    byte *input_key;
    undefined8 data_size;
    byte *enc_data;
    longlong crypto_data;
    longlong winning;
    uint hash;
    longlong lVar1;
    short local_48 [8];
    short local_38 [8];
    short *local_28;
    short *local_20;
    undefined8 local_18;
    undefined8 local_10;
    byte *ptr_input_key;

    input_key = (byte *)get_data_block(KEY);
    hash = 0;
    lVar1 = 4;
    ptr_input_key = input_key + 2;
    do {
        hash = hash ^ (hash << 7 | hash >> 0x19) + (uint)ptr_input_key[-2];
        hash = hash ^ (hash << 7 | hash >> 0x19) + (uint)ptr_input_key[-1];
        hash = hash ^ (hash << 7 | hash >> 0x19) + (uint)*ptr_input_key;
        hash = hash ^ (hash << 7 | hash >> 0x19) + (uint)ptr_input_key[1];
        lVar1 = lVar1 + -1;
        ptr_input_key = ptr_input_key + 4;
    } while (lVar1 != 0);
    if (hash == 0x31d9f5ff) {
        data_size = get_enc_data_size();
        enc_data = (byte *)get_data_block(ENC_DATA);
        decrypt((uint *)input_key,enc_data,(uint)data_size);
        crypto_data = get_data_block(ENC_DATA);
        winning = get_data_block(Winning);
        FUN_00409600(local_38,winning);
        FUN_00409600(local_48,crypto_data);
        local_28 = local_48;
        local_18 = 0x30;
        local_20 = local_38;
        local_10 = 0xffffffff;
        FUN_00409993(0x50000018,4);
    }
    return 0;
}
```

After playing with Z3 to generate valid inputs, noticing there's just too many of them, trying some random constrains and deciding it was too random, i got so only sane possible idea and dwelve back into the binary.

## 2. DOSBOX and fancy music

The massive DOS stub of the binary hosts an entirely different program.

If you run the binary in DOSBOX, you get a fancy Simon Says game promising endless hours of nostalgic fun.

After an exciting reversing session, it appears that if you win this game, it will re-write itself, filling the 16 zero'd bytes we found earlier.

Also in order to get a deterministic value, you have to enter the konami cheat code.


## 3. TL;DR

- [patch](patch.py) bin so it autoplays (i have a bad memory, i can't beat this game :p)
- run with dosbox
- input konami code to set the seed
- let it play (speed up the emulator or go grab a coffee)
- run under windows to get flag

everything was perfect about this challenge

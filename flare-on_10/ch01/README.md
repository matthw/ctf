## 1. Window Reverse Engineer

It's a windows application, i heard windows people like to use the mouse.

Since it's a 2 digits lock, it's faster to bruteforce it with your mouse than figure it's a DotNET app and open it

## 2. Certified Forensic Analyst

It turned out the FLARE team actually made a typical CTF forensic challenge: just run strings on it and get the flag.

```
% strings -e l X.dll | grep flare
 glorified_captcha@flare-on.com
```

But since it's a 500 points hard forensic challenge, you actually have to give `strings` the correct parameter to show widestrings (it also proves your boss your 10k cert was worth it).

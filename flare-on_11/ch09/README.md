## 9. Serpentine

Supporting code and data for the [full writeup](https://matth.dmz42.org/posts/2024/flare-on_11_9_serpentine/)


- For the emulator, you need unicorn 2.0.1 - there's a caching issue with 2.1.0+
- For Triton, you need python 3.11

if you use [anaconda](https://www.anaconda.com/), this should quickly get you sorted:
```
conda create -n "fl311" python=3.11.10
conda activate fl311
pip install -r requirements.txt
``` 

TL;DR: run this to get flag:
```
mkdir stages
python ../emu_v7.py
cat stages/* > stages/full.bin
python ../triton_solver.py
```

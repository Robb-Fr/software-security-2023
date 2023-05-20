# Thing Doer

By observing the file in Ghidra, we see a miss of lower bound check that allows us to jump eventually to show the flag. See [sploit.py](sploit.py) for more details. Basically you just brute force to find the exact value to which you should jump.

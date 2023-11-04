# I'm lost

With ghidra, we observe that there is this line that leads to showing the flag:

```C
(param_1 ^ param_2) == 0xd064
```

We just xor the given parameter with 0xd064 to obtain the 0 and going inside the condition.

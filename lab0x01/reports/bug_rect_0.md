# BUG-15

## Category

Stack buffer overflow/underflow

## Description

The stack is accessed to unallocated memory through the `argv` variable. This looks like a typo: we check `argc` is
equal to 8, and access `argv[8]` which is not allocated if `argc==8`. This can provoke an undefined behaviour.

## Affected Lines in the original program

In `rect.c:34` and `rect.c:35`

## Expected vs Observed

We expect the program to put a rectangle in the correct place of the image, but a memory space not reserved for `argv`
is accessed and tried to be converted to an long integer in base 16. This leads to an undefined behaviour and can, for
example, result in a segfault.

## Steps to Reproduce

### Command

```bash
./rect test_imgs/summer.png out.png 10 10 20 20 ffffff
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We solve this bug by replacing the `8` index accessed by a `7` index.

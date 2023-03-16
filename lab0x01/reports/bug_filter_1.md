# BUG-10

## Category

Stack buffer overflow/underflow

## Description

The input in fourth position provided by the user is copied to a local variable with an unsafe copy function (`strcopy`)
without any length check. This allows to perform a buffer overflow with this variable allocated on the stack.

## Affected Lines in the original program

In `filter.c:228`

## Expected vs Observed

We expect that the fourth argument (given in case of the blur filter call for example) is safely copied to a local
variable in order to provide access to the desired radius of the filter. However, the usage of the `strcopy` function
results in a buffer overflow when the given input is too long. This buffer overflow yields an undefined behaviour. In
my case, it triggers a segfault.

## Steps to Reproduce

### Command

```bash
./filter test_imgs/summer.png out.png blur 111000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

The usage of `strncpy(arg, argv[4], ARG_SIZE)` instead of `strcpy(arg, argv[4])` should make sure that the copy of the
argument to the arg variable will not try to write below the ARG_SIZE allocated characters on the stack.

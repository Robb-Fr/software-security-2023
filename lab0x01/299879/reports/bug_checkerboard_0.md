# BUG-1

## Category

Temporal safety violation

## Description

In case the `px` array of the `image` struct cannot be allocated by malloc and therefore, contains a null pointer, the
`img` struct is freed twice (once on line 91 and a second time, on line 147 after the `goto error_img`).

## Affected Lines in the original program

In `checkerboard.c:91` and `checkerboard.c:147`

## Expected vs Observed

We expect that the command given below generates correctly a checkerboard with the given specifications, or properly
crashes. However, the fail in memory allocation for the pixels array results in a double free undefined
situation, in my case detected via the following error

```bash
free(): double free detected in tcache 2
Aborted (core dumped) potentially
```

but potentially leading to modification of unexpected memory locations.

## Steps to Reproduce

### Command

```bash
./checkerboard pocBig.png 65534 65534 10 111111 999999
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/pocBig.png`

## Suggested Fix Description

As `error_img` takes care of freeing the `img` pointer, it is not necessary to add the `free(img)` line 91. Just
removing this line ensures that we do not free the pointer twice in the given circumstances, and that the pointer is
indeed freed exactly once.

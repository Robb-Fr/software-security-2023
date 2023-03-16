# BUG-8

## Category

Arithmetic overflow/underflow

## Description

It is possible that an arithmetic overflow provokes an error in the computation of the size of the scaled up logo,
leading to an inaccurate and badly drawn logo.

## Affected Lines in the original program

In `epfl.c:76` (with the modification from bug_epfl_0), `epfl.c:80` and `epfl.c:87`

## Expected vs Observed

We expect that the program adapts its drawing to the size factor and draws a logo scaled up by the given factor.
However, when giving a logo size greater than 2^32/5, the logo drawn becomes way smaller than expected (it actually
fits the output picture although this one is only a few hundred pixels height).

## Steps to Reproduce

### Command

```bash
./epfl test_imgs/summer.png out.png 0 0 858993461 ff0000
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

When decoding the size factor input by the user, we should exit the program if an overflow is detected.
For example with:

```C
// Overflow checking
if (logo_width > INT32_MAX / size || logo_height > INT32_MAX / size) {
free(img->px);
free(img);
return 1;
}
```

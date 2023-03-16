# BUG-7

## Category

Heap overflow/underflow

## Description

When we ask the program to draw a logo with a too high size factor, there is no bound check that ensures we are drawing
withing the limit of the image, enabling a potential attacker to write outside of the allocated memory dedicated for
the image pixels.

## Affected Lines in the original program

In `epfl.c:90`

## Expected vs Observed

We expect that the program adapts its drawing to the size factor and, under too big logo, either crash or partially
write the pixels, but not allow writing the logo pixel values outside of the bounds of the image. This may happen even
in the case where the modification made in lines `epfl.ch:80 to 83` were triggered: the logo moved on the top may still
be too big and we would dereference and write to locations not allocated for `image_data` on lines 96 to 99.

## Steps to Reproduce

### Command

```bash
./epfl test_imgs/summer.png out.png 0 0 190 ff0000
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We should replace the drawing condition `if (epfl[j_logo] & (16 >> i_logo / size))` by
`if (epfl[j_logo] & (16 >> i_logo / size) && i + i_logo < height)` to take into account that we may have a scaled up
logo and therefore memory location beyond `height` could be accessed with `i+i_logo`.

# BUG-4

## Category

Heap overflow/underflow

## Description

The modification of the original image's pixels is not bound checked and can lead to write outside of the allocated
memory for the image. The pixels being allocated on the Heap, this results in a Heap over/underflow situation when we
dereference the pixel array at unallocated coordinates (which we do on the detailed affected lines).

## Affected Lines in the original program

In `circle.c:55 to 67` and `circle.c:79 to 90`

## Expected vs Observed

We expect the program to be able to partially draw a circle if the specified position should go out of bound, but
without accessing or modifying memory location outside the memory allocated to store the image pixels. However, the
program does not check this and memory space is modified leading to an undefined behaviour, for example a segfault.

## Steps to Reproduce

### Command

```bash
./circle test_imgs/summer.png out.png 0 0 50 ff00aa
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We can add `if` condition before writing the new pixels to make sure that the memory index suggested by the solution of
the circle equation are valid for our picture.

```C
if (x >= 0 && y >= 0 && x < width && y < height)
```

such check before any access to the `image_data` value by dereferencing should prevent such illegal access.

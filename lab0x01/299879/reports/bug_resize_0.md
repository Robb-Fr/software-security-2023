# BUG-18

## Category

Heap overflow/underflow or Wrong operators/variables

## Description

The allocated memory size for the pixel array is `n_pixels + sizeof(struct pixel)`, while the following for loop
dereferences until a memory location `n_pixels * sizeof(struct pixel)` further the first position of the pointer. This
allows an access to memory locations on the heap and writing the pixels of the input image into it.

## Affected Lines in the original program

In `resize.c:69`

## Expected vs Observed

We expect that the program just take the input image to resize it in another output image. However, the program has an
undefined behaviour due to access to non allocated memory for the pointer. This for example can results in a
segmentation fault.

## Steps to Reproduce

### Command

```bash
./resize test_imgs/summer.png out.png 10
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

To solve this bug only, we prevent access to memory location if it's dereferenced at an index further
`[n_pixels + sizeof(struct pixel)]`. However, this would prevent the program from fulfilling its main goal: it would
output a broken image. Therefore, we will solve this bug by allocating enough memory to prevent this bad behaviour while
allowing correct functioning of the program.
Using `malloc(n_pixels * sizeof(struct pixel))` instead of `malloc(n_pixels * sizeof(struct pixel))` allocates the
correct amount of memory for the pixels of the new array to be written. If not that much memory can be allocated, the
program can properly crash and no undesired write is performed.

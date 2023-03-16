# BUG-22

## Category

Temporal safety violation

## Description

On the error treatment on line 73, the program goes to `error_mem` bloc which does not free the pointer `palette`
although this one was allocated earlier. This leaves the pointer unfreed and the memory allocated at the end of the
program.

## Affected Lines in the original program

In `solid:75`

## Expected vs Observed

We expect that all the memory allocated in the main function is freed before returning. However it is not the case for
the pointer `palette`.

## Steps to Reproduce

### Command

This bug is actually triggered on successful runs of the program and runs where there is not enough memory to allocate
memory for an image (the malloc in `solid:75` fails).

For example with such a program run:

```bash
./solid out.png 65000 65000 ffffff
```

### Proof-of-Concept Input (if needed)

Not needed

## Suggested Fix Description

Instead of going to the `error_mem` block, the program should go a block where the `palette` pointer is correctly freed.
We also should free it when we free the `img->px` and `img` pointers. Therefore, we add `goto error_palette;` on line 75
and a block on line 150:

```C
error_palette:
  free(palette);
```

Finally, we add `free(palette);` on line 109 for freeing the palette upon successful runs.

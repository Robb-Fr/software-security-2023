# BUG-13

## Category

Iteration error

## Description

The for loop iterating over all pixels goes 1 element beyond the last allocated element of the `px` array due to the
end loop condition being `i <= img->size_y`. This can provoke dereferencing a location on the heap that was not
allocated for `image_data` on line 121, causing an undefined behaviour.

## Affected Lines in the original program

In `filter.c:118` and `filter.c:119`

## Expected vs Observed

We expect the program to change the pixels values for all the pixels of the given image and only these. However, an out
of bound access on line 143 that causes an undefined behaviour, for example a segfault in my case.

## Steps to Reproduce

### Command

Any normal run with the negative filter triggers this memory leak.

```bash
./filter test_imgs/summer.png out.png negative
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We should replace the `i <= img->size_y` and `j <= img->size_x` by `i < img->size_y` and `j < img->size_x`.

# BUG-2

## Category

Type error

## Description

The type of `__endptr` attribute when calling the function `strtol` is not of the correct type. The expected input type
is `char **` but only `end_ptr` of type `char*` is given.

## Affected Lines in the original program

In `circle.c:29`

## Expected vs Observed

We expect that the command given below adds a circle in the original image. However an illegal dereferencing happens on
line 30: as the end_ptr is not initialized and its value not correctly passed to the function (the value of the pointer
instead of its address), we are trying to dereference what lies inside the value pointed to by end_ptr, leading to an
undefined behaviour. For example, it can cause segmentation fault.

## Steps to Reproduce

### Command

```bash
./circle test_imgs/summer.png out.png 200 200 50 ff00aa
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

Instead of calling `strtol(argv[6], end_ptr, 16)` we should call `strtol(argv[6], &end_ptr, 16)` (note the & operator).

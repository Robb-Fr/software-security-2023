# BUG-17

## Category

Unchecked return code from system call

## Description

The function `store_png` is called without any check for its return code. The program successfully terminates regardless
of the status code given by this function. It is therefore possible that, in the case `store_png` returns 1, our program
would still return 0 as if it successfully executed the program.

## Affected Lines in the original program

In `rect.c:86`

## Expected vs Observed

We expect the program to fail if the generated image cannot be stored successfully. However, the return code form the
`store_png` function is not checked: we expect to see an error if the image cannot be stored, but here the program
returns 0 even if no image is stored.

## Steps to Reproduce

### Command

```bash
./rect test_imgs/summer.png "" 0 0 200 200 ffffff
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We can fix this by storing the return code and using it to return an adequate code depending the result for storing the
picture. For example:

```C
int return_code = store_png(output, img, NULL, 0);
free(img->px);
free(img);
return return_code;
```

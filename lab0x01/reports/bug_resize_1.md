# BUG-19

## Category

Arithmetic overflow/underflow

## Description

When computing the size of the final image, there is no check for overflow although there is a multiplication made upon
user input double value. The product between the unsigned short and the double is casted to an unsigned int and an
unsigned short. This can lead to an overflow and therefore, leading to bad final image size.

## Affected Lines in the original program

In `resize.c:33` and `resize.c:34`

## Expected vs Observed

We expect that the program outputs an image scaled up by 110 (notably, going from a width of 600 to a width of 66000).
However, the output image has a width of 464 pixels due to the arithmetic overflow.

## Steps to Reproduce

### Command

```bash
./resize test_imgs/summer.png out.png 110
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`
The `summer.png` image, having a width of 600, when scaled up by 110, should have a width of 66000 for example.

## Suggested Fix Description

To solve this bug, we must use a safe check for the overflow for multiplication that define the size of the new image:

```C
if (width > USHRT_MAX / factor || height > USHRT_MAX / factor) {
    goto error_memory;
  }
```

and

```C
if (new_height > SIZE_MAX / new_width || new_height <= 0 || new_width <= 0) {
    goto error_memory;
  }
```

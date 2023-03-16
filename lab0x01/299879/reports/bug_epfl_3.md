# BUG-9

## Category

Logic error

## Description

The comments specify that any invalid value of top_left_x and top_left_y will be converted to 0, although any negative
value is not and gets casted to an unsigned integer on line 72 and 74, yielding unexpected behaviour.

## Affected Lines in the original program

In `epfl.c:25` and `epfl.c:26`

## Expected vs Observed

When giving a top_left_x values that is negative, we expect it either is considered invalid, and therefore is considered
as 0, or it's considering a virtual negative side of the coordinates axis and draws a logo that is shifted on the left.
However, what happens is that the logo does not appear on the image (in fact, it is tried to be drawn at the x
coordinates the top_left_x would be if its bit were interpreted as unsigned). If we had an image that is at least 2^32
pixels wide, we would see the logo being drawn at the extreme right of the picture, which is not at all what we can
expect from this program.

## Steps to Reproduce

### Command

```bash
./epfl test_imgs/summer.png out.png -1 0 12 ff0000
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

In order to enforce the contract described in the comments, we should make sure that negative values are mapped to 0,
for example with:

```C
/* Decode the top left of the EPFL logo. Invalid values are decoded as 0 */
int top_left_x = atoi(argv[3]);
top_left_x = top_left_x < 0 ? 0 : top_left_x; 
int top_left_y = atoi(argv[4]);
top_left_y = top_left_y < 0 ? 0 : top_left_y;
  ```

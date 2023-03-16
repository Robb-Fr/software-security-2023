# BUG-16

## Category

Iteration errors

## Description

The iteration through the image pixels deviates from the intended iteration. The comments clearly describe iterating
through all the image's pixels and modifying only those inside the rectangle bound. However, the current iteration
increases both x and y axis coordinates at the same pace, allowing to only iterate through the main diagonal from top
left to bottom right.

## Affected Lines in the original program

In `rect.c:79`

## Expected vs Observed

We expect the program to put a rectangle in the correct place of the image, but only a straight line following a
diagonal in the picture can be drawn. For example with the given input, we expect to have a 200 by 200 white rectangle
on the top left of the picture, but only a diagonal from 0,0 to 200,200 of 1px wide appears.

## Steps to Reproduce

### Command

```bash
./rect test_imgs/summer.png out.png 0 0 200 200 ffffff
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We can change the iteration from

```C
  unsigned i = 0;
  unsigned j = 0;
  while (i < height) {
    while (j < width) {
      // Check if the pixel is in the rectangle
        ...
      i++;
      j++;
    }
  }
```

to

```C
  unsigned i = 0;
  unsigned j = 0;
  while (i < height) {
    while (j < width) {
      // Check if the pixel is in the rectangle
        ...
      j++;
    }
    i++;
    j = 0;
  }
```

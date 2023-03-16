# BUG-6

## Category

Wrong operators/variables

## Description

In case we ask the program to draw a logo with a scaled up size, only 15 columns of the logo are drawn. The horizontal
size is not adapted because the scaling factor is not taken into account in the ending condition for drawing the logo.
Indeed, the scale factor is not taken into account when defining the zone to draw the logo on.

## Affected Lines in the original program

In `epfl.c:76`

## Expected vs Observed

We expect that the program adapts the size of the logo according to the size argument passed to the program and that a
full logo with all letters is drawn whenever this one should fully fit in the picture's canvas. However, we observe that
at most 15 columns are drawn, cropping the logo horizontally.

## Steps to Reproduce

### Command

```bash
./epfl test_imgs/summer.png out.png 0 0 10 ff0000
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We should replace the drawing condition `if (j >= top_left_x && j < top_left_x + logo_width)` by
`if (j >= top_left_x && j < top_left_x + logo_width * size)` to take into account that we may have a scaled up logo
and therefore more than `logo_width` columns should be drawn.

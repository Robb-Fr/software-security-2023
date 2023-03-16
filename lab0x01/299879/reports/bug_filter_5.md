# BUG-14

## Category

Logic error

## Description

The filter should average the neighbouring pixels as described, and therefore divide the accumulated color value of
each channel by the correct amount of pixels considered. However, independently of how many pixels are neighbouring, we
divide by `(2 * radius + 1) * (2 * radius + 1)` which is potentially incorrect for the edge and corner pixels.

## Affected Lines in the original program

In `filter.c:86`

## Expected vs Observed

We expect that the filter correctly averages every pixels to the value of its neighbours. However, we are dividing by
a too high factor for the corner and edge pixels (given that there are less neighbouring pixels for these). The computed
color is therefore too dark.

## Steps to Reproduce

### Command

The test case `test.c:blur_functionality` perfectly outlies the given issue.

### Proof-of-Concept Input (if needed)

Not needed

## Suggested Fix Description

To fix this, before iterating through the neighbouring pixels, we create a `num_pixels` variable that will hold the
count of pixels taken into account in the computation. Therefore, by the end of the loop, we'll know the exact number
of neighbouring pixels and we can therefore divide by this value as it was already done. To make sure we do not have a weird edge case, we can cap this value to 1 to make sure we do not divide by 0.

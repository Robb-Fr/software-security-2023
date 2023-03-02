# BUG-0
## Category
Uninitialized local variables

## Description

The loop iteration counters, `i` and `j`, are not initialized and the behavior
of the loop is thus undefined.

## Affected Lines in the original program
In `filter.c:22` and `filter.c:23`

## Expected vs Observed
We expect that the loops process over all the pixels in the image by iterating
over every row, and every pixel in that row, starting from index 0. The loop
counters are not initialized and are thus not guaranteed to start at 0. This
makes the behavior of the grayscale filter undefined.

## Steps to Reproduce

### Command

```
./filter poc.png out.png grayscale
```
### Proof-of-Concept Input (if needed)
(attached: poc.png)

## Suggested Fix Description
Initialize the `i` and `j` counters to 0 in the loop setup. This allows the loop
to iterate over all the image pixels to apply the grayscale filter.

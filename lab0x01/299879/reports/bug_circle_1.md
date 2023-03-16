# BUG-3

## Category

Wrong operators/variables

## Description

The comparison operator is used instead of the assignation operator. This prevents the correct assignation of the y and
x variables and the second solution to the equation can therefore not be drawn in the picture matrix.

## Affected Lines in the original program

In `circle.c:61` and `circle.c:84`

## Expected vs Observed

We expect that the program correctly draws a full circle at the desired position. However, the given command misses many
pixels on the top left quadrant of the circle.

## Steps to Reproduce

### Command

```bash
./circle test_imgs/summer.png out.png 200 200 50 ff00aa
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We can replace `y == round(center_y - sqrt(radius * radius - (x - center_x) * (x - center_x)));` and
`x == round(center_x - sqrt(radius * radius - (y - center_y) * (y - center_y)));` by
`y = round(center_y - sqrt(radius * radius - (x - center_x) * (x - center_x)));` and
`x = round(center_x - sqrt(radius * radius - (y - center_y) * (y - center_y)));` respectively to ensure that the
assignation is performed and we do not just have an unused comparaison.

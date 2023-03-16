# BUG-12

## Category

Local persisting pointers

## Description

The `get_pixel` function creates a new local variable on the stack and then returns a pointer to this variable. This
function is then called in `filter.c:122` and uses the pointer although it outlives the variable that was on the
stack and is de-allocated when `get_pixel` returns. This can provoke undefined behaviour.

## Affected Lines in the original program

In `filter.c:109` and `filter.c:121`

## Expected vs Observed

We expect the program to output an image that inverted the color channels of the input image. However, the output
behaviour is undefined and can lead to a segfault notably.

## Steps to Reproduce

### Command

```bash
./filter test_imgs/summer.png out.png negative
```

### Proof-of-Concept Input (if needed)

`src/test_imgs/summer.png`

## Suggested Fix Description

We replace the local stack variable initialization by a pointer allocation on the heap. We therefore replace

```C
struct pixel px;
return &px;
```

by

```C
struct pixel *px = malloc(sizeof(struct pixel));
return px;
```

To properly deal with this new pointer, we must not forget to free it when it gets out of scope. We can add `free(neg);`
on line 131.

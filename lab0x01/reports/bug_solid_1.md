# BUG-21

## Category

Unchecked return code from system call

## Description

The `allocate_palette` calls `malloc` but does not check if the returned pointer is non null (meaning the memory is
successfully allocated). As palette is dereferenced on lines 95 to 97, this, in the case that the palette could not have
been allocated, dereferencing of null pointer.

## Affected Lines in the original program

In `solid.c:16`

## Expected vs Observed

We expect that, if the program cannot allocate enough memory to store the palette, it properly crashes. However it does
not and it uses a potentially null pointer that is dereferenced later. This could lead to an undefined behaviour when
the pointer `palette` is used afterward. For example, if not enough memory is available, the memory allocation would
return a null pointer, and this pointer being dereferenced in `solid.c:16`, leading to an undefined behaviour or a
crash.

## Steps to Reproduce

### Command

This error would be triggered if not enough memory is available, therefore it highly depends on the circumstances of
execution. In a context where too few bytes of memory are available, the program would probably crash under a normal
execution.

### Proof-of-Concept Input (if needed)

Not needed

## Suggested Fix Description

This issue can be solved by checking the return value of the `allocate_palette` function, and properly finish with an
error the program, using the error block `error_mem` for example:

```C
if (!palette) {
    goto error_mem;
  }
```

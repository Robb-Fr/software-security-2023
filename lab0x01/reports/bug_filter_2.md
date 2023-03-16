# BUG-11

## Category

String Vulnerability

## Description

The filename input is used in the unsafe `printf` function without using a format string. This allows an attacker to use
a format string notably to read values from the stack (as done in the next steps).

## Affected Lines in the original program

In `filter.c:233`

## Expected vs Observed

We expect that in case of failing to load a png file, the program safely exits and potentially informs the user about
the filename that produced the failure and no more, notably not allowing an attacker to read from the stack. However,
the unsanitized string given by the user can use the format string capabilities to read from the stack.

## Steps to Reproduce

### Command

```bash
./filter "Hey %s%s%s%s%s%s" out.png blur 10
```

### Proof-of-Concept Input (if needed)

Not needed

## Suggested Fix Description

The usage of `printf("%s", input)` instead of `printf(input)` should make sure that the format string is neutralized
and cannot be used to read from the stack.

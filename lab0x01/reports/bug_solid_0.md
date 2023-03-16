# BUG-20

## Category

Command injection

## Description

The filename input by the user is used to call a command from the OS with the `system` function. This allows a user to
launch arbitrary command, for example a shell session by using the `solid` program only.

## Affected Lines in the original program

In `solid.c:125`

## Expected vs Observed

We expect that the program only displays the final file's size and does nothing else. Notably, we do not expect it gives
any capability to an attacker for exploiting the machine the program runs on. However, we observe that this feature
allows an attacker to launch any command from the machine the `solid` program is running on, notably a shell session
(the example that is given in the next part).

## Steps to Reproduce

### Command

```bash
./solid ";sh" 9999 9999 ffffff
```

### Proof-of-Concept Input (if needed)

Not needed

## Suggested Fix Description

In order to avoid calling a function supplied by the user, we can replace this with a call to a C built-in function that
allows to read a file, only the filename for the file the user previously created can then be used to read this same
file. We replaced

```C
strcat(command, "stat -c %s ");
strncat(command, output_name, OUTPUT_NAME_SIZE);
system(command);
```

```C
FILE *fp = fopen(output_name, "r");
if (fp) {
fseek(fp, 0L, SEEK_END);
printf("%ld", ftell(fp));
free(fp);
} else {
printf("Could not read the size");
}
```

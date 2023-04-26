# Answers

This document contains the answers for the AFL++ part of the lab

## Why did you need to change is_png_chunk_valid?

This function checks for some specific checksum value in the header of the file. This value is **not easily guessable by random mutations** and, as the function is called quite soon in the parsing of the png file, not being able to produce an input that passes it would be a **coverage killer for our fuzzer**. It would take a long time until a random mutation is able to pass this check although we are not really interested by its functionality: the **function is quite small with few risky memory allocation**.

## Why did you have to use afl-clang to compile the source (and not e.g. ordinary clang)?

For this experience, we wanted to use a **coverage guided fuzzer**. With a standard clang compiled file, the afl-fuzzer program would not be able to easily get information about the coverage some input allowed to perform. afl-clang uses **instrumentation** to add extra code that **helps afl-fuzzer to understand how a certain input reached some parts of the code**, and perform **more efficient mutation** with this information.

## How long did you fuzz? How many crashes in total did AFL++ produce? How many unique crashes?

I made 2 runs of fuzzing to finish this experiment. Both run lasted around 40 minutes, the first one produced around 30k crashes, saving 16 unique, while the second run (with the first 2 bugs fixed) produced around 14 crashes, with 2 unique saved.

## Why are hangs counted as bugs in AFL++? Which type of attack can they be used for?

**Hangs are not to be expected** on this library that should proceed the input and either fail or succeed to read the png. Therefore, a hang would allow an attacker to perform an unexpected **denial of service** on the machine running the program that would prevent other inputs to be proceeded.

## Which interface of libpngparser remains untested by AFL++ (take a look at pngparser.h)?

In pngparser.h, we see 2 functions, `load_png`, used by the `size` program and `store_png` that is exposed as well but totally untested through the `size` program (as this driver is not using the `store_png` function at all).

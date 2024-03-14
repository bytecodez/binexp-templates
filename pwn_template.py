#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("targ", checksec=True)
libc = elf.libc
context.log_level = "debug"
#context.log_level = "critical"  # quiet mode

gs = """
continue
"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
      remote("1.1.1.1", 5555) 
    else:
        return process(elf.path)


io = start()

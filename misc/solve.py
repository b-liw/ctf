#!/usr/bin/env python2
from pwn import *
# import monkeyhex
# import struct
# import binascii
# import pyshark
# import angr
# import claripy

HOST = ""
PORT = 1337

file_path = os.path.join(os.getcwd(), "./binary_name")

libc_path = os.path.join(os.getcwd(), "./libc.so.6")

#gcc -shared -fPIC -o inject.so inject.c
preload_lib = os.path.join(os.getcwd(), "./inject.so")

program_args = []

breakpoints_addr = []

gdb_commands = ['c']

gdb_script = []
gdb_script += ["break *" + hex(x) for x in breakpoints_addr]
gdb_script += gdb_commands
gdb_script = '\n'.join(gdb_script)


gdb_env = {'LD_PRELOAD': libc_path}

context.binary = file_path
context.log_level = 'info'
context.terminal = ['konsole', '-e']

elf = ELF(file_path)
libc = ELF(libc_path)

# proc = process(argv = [file_path] + program_args)
# proc = remote(HOST, PORT)
# proc = gdb.debug(args = [file_path] + program_args, gdbscript = gdb_script)

# proc.interactive()

#!/usr/bin/env python2
from pwn import *
from ctypes import *
import monkeyhex
import time as t

HOST = 'chal1.swampctf.com'
PORT = 1313

context.log_level = 'info'

possible_keys = dict()

for time in xrange(2**16):
    key = ((((time & 0xFFC) << 16) - 0x14C437BE) ^ ((time & 0xF0) << 8) | ((time & 0xFFC) << 8) |  ((time >> 8) << 24) |  time & 0xFC)
    key = c_uint32(key).value
    if key in possible_keys:
        possible_keys[key].append(time)
    else:
        possible_keys[key] = [time]

#for x in possible_keys:
#    proc = process(['gdb', '-ex', 'py ecx=' + str(x)', '-x', './gdb.py'])
#    if "Program received" not in proc.recvall(0.5):
#        print "FOUND: ", hex(x), str(x)
#        break
#    proc.close()

valid_key = 0xff4fdc56
print possible_keys[valid_key]

serverTimeOffset = 5

while True:
    sleep(0.5)
    timeSec = int(t.time())
    x = (timeSec + serverTimeOffset) & 0xFFFF
    print x
    if (x in possible_keys[valid_key]):
        proc = remote(HOST, PORT)
        print proc.recvall(12)


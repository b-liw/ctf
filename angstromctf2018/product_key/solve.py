#!/usr/bin/env python
import angr
import claripy
import sys

path_to_binary = "./activate"
project = angr.Project(path_to_binary)
start_addr = 0x400932

name_s = 'Artemis Tosini'
email_s = 'artemis.tosini@example.com'

name = claripy.BVS('name', 8 * (14 + 1))
email = claripy.BVS('email', 8 * (26 + 1))
product_key = claripy.BVS('product_key', 8*(29+1))

state = project.factory.blank_state(addr = start_addr)

for i in range(14):
	byte = name.get_byte(i)
	constraint = byte == name_s[i]
	state.add_constraints(constraint)

state.add_constraints(name.get_byte(14) == 0)

for i in range(26):
    byte = email.get_byte(i)
    constraint = byte == email_s[i]
    state.add_constraints(constraint)

state.add_constraints(email.get_byte(26) == 0)

for i in range(29):
    byte = product_key.get_byte(i)
    if i in [4, 9, 14, 19, 24]: # indexes of '-'
        constraint = byte == '-'
    else:
        constraint = claripy.And(byte >= '0', byte <= '9')
    state.add_constraints(constraint)

state.add_constraints(product_key.get_byte(29) == 0)

# print state.solver.eval(name, cast_to=str)
# print state.solver.eval(email, cast_to=str)
# print state.solver.eval(product_key, cast_to=str)

simulation = project.factory.simgr(state, threads = 4)

fake_heap_address0 = 0x6444444
state.regs.rdi = state.solver.BVV(fake_heap_address0, 64) # name
fake_heap_address1 = 0x6445555
state.regs.rsi = state.solver.BVV(fake_heap_address1, 64) # email
fake_heap_address2 = 0x6446666
state.regs.rdx = state.solver.BVV(fake_heap_address2, 64) # key

state.memory.store(fake_heap_address0, name)
state.memory.store(fake_heap_address1, email)
state.memory.store(fake_heap_address2, product_key)

succ = [0x400FD3]
fail = [0x4009D9, 0x400FBC]

print('Launching exploration')
simulation.explore(find=succ, avoid=fail)
print('Explored')

if simulation.found:
	solution_state = simulation.found[0]
	solution0 = solution_state.se.eval(product_key, cast_to=str)
	print solution0
else:
	raise Exception('No solutions!')

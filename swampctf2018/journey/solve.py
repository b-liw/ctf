#!/usr/bin/env python2
import angr
import claripy
import sys

path_to_binary = "./journey"

BUF_LEN = 17 + 1 # null byte

succ = [0x8048989]
fail = [0x80489B8]

class ReplacementScanf(angr.SimProcedure):
	def run(self, format_string, param0):
		scanf0 = claripy.BVS('scanf0', 8*(BUF_LEN))
		for i in xrange(BUF_LEN - 1):
			symbol = scanf0.get_byte(i)
			self.state.solver.add(self.state.solver.And(symbol >= ' ', symbol <= '~'))
		self.state.solver.add(scanf0.get_byte(BUF_LEN - 1) == 0)
		self.state.memory.store(param0, scanf0)
		self.state.globals['solutions'] = [scanf0]


def main():
	project = angr.Project(path_to_binary)
	sh = project.analyses.StaticHooker("libc.so.6")
	state = project.factory.entry_state(add_options=angr.options.unicorn)
	simulation = project.factory.simgr(state, threads = 4)

	project.hook_symbol('__isoc99_scanf', ReplacementScanf())

	print('Launching exploration')
	simulation.explore(find=succ, avoid=fail)
	print('Explored')

	if simulation.found:
		solution_state = simulation.found[0]
		solutions = solution_state.globals['solutions']
		print ' '.join([solution_state.se.eval(solution, cast_to=str) for solution in solutions])
	else:
		raise Exception('No solutions!')

if __name__ == '__main__':
    main()

import gdb

file_path = './os_patched_new'
libc_path = './libc.so.6'

gdb.execute('file ' + file_path)
#gdb.execute("set environment LD_PRELOAD " + libc_path)
gdb.execute('break *0x0000000000400AA5')
gdb.execute('r')
gdb.execute('set $ecx=' + str(ecx))
gdb.execute('continue')
gdb.execute('quit')


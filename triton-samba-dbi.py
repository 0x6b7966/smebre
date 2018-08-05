#! /usr/bin/env python

import os
# import syscallmap32

from triton import *
from pintool import *
from sets import Set

logfile = "tritonlog.log"
#os.remove(logfile)
f = open(logfile, 'w')
readbuf = None
stdset = Set([])

def getMemoryBytearr(addr, size):
	index = 0
	a = bytearray(b'')
	while getCurrentMemoryValue(addr+index):
		a.append(getCurrentMemoryValue(addr+index))
		index += 1
	return a

def syscallEntry(threadId, std):
	global readbuf, stdset
	# if (threadId, std) not in stdset:
	# 	stdset.add((threadId, std))
	# 	print "[+] (%d %d) created" % (threadId, std)
	print "syscall %d called" % getSyscallNumber(std)

	"""
	# Check if the syscall is read()
	if getSyscallNumber(std) == SYSCALL32.READ:
		fd = getSyscallArgument(std, 0)
		buf_base = getSyscallArgument(std, 1)
		size = getSyscallArgument(std, 2)
		print "READ() | fd: %d, buf_base : 0x%x, %d" % (fd, buf_base, size)
		#readbuf = {'fd': fd, 'buf_base': buf_base, 'size': size}
	"""


def syscallExit(threadId, std):
	global readbuf
	# (Under construction) Clear previous tainted area. We do care only messages per read()

	if readbuf is not None:
		fd = readbuf['fd']
		buf_base = readbuf['buf_base']
		size = readbuf['size']
		buf_data = getMemoryBytearr(buf_base, size)
		f.write("[+] syscall read(%x, 0x%x, %d)\nData:%s\n" % (fd, buf_base, size, buf_data))
		readbuf = None

		# (Under construction) Taint memory read via specific IP source

if __name__ == '__main__':

	# startAnalysisFromSymbol('main')
	startAnalysisFromEntry()

	getTritonContext().setArchitecture(ARCH.X86_64)

	# Perform symbolic execution only on tainted instructions
	# getTritonContext().enableMode(MODE.ONLY_ON_TAINTED, True)

	#insertCall(syscallEntry, INSERT_POINT.SYSCALL_ENTRY)
	#insertCall(syscallExit, INSERT_POINT.SYSCALL_EXIT)

	# (Under construction) If the instruction refers to the tainted memory, mark as the range of bytes symbolic
	#insertCall(cb_ir,       INSERT_POINT.BEFORE_SYMPROC)

	# (Under construction) Print all the branches that encountered

	runProgram()

f.close()
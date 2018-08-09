#! /usr/bin/env python

import os, sys, traceback
# import syscallmap32

import numpy as np
from triton import *
from pintool import *
from sets import Set
from hexdump import *

GREEN = "\033[92m"
ENDC  = "\033[0m"
SSIZE_MAX = 32767
logfile = "tritonlog_"
logext = ".log"
#os.remove(logfile)
readbuf = None
routineAddr = None
instructionAddr = None
inst_write_flag = False
lastRoutineString = ""
stdset = Set([])
ctx = getTritonContext()

def printExecInfo(f=None, verbose=True):
	global logfile, logext
	if f is not None: # close previous fd
		f.close()
	f = open(logfile+str(getPid())+logext, 'a+')
	exc_type, exc_value, exc_traceback = sys.exc_info()
	if verbose is False:
		# Print error type only 
		f.write("[-] syscallExit(), Error type in line %d: %s\n" %
			(exc_traceback.tb_lineno, exc_type) )
	else:
		tblist = traceback.format_exception(exc_type, exc_value, exc_traceback)
		f.write("[-] syscallExit(), Error details:\n")
		for tbstr in tblist:
			f.write("%s"%tbstr)
	f.close()


def getMemoryBytearr(addr, size):
	a = bytearray()
	for index in range(0, size):
		val = getCurrentMemoryValue(addr+index)
		a.append(val)
	return a

def syscallEntry(threadId, std):
	global readbuf, stdset
	# if (threadId, std) not in stdset:
	# 	stdset.add((threadId, std))
	# 	print "[+] (%d %d) created" % (threadId, std)
	# f.write("[+] syscall %d called\n" % getSyscallNumber(std))
	# print "syscall %d called" % getSyscallNumber(std)

	
	# Check if the syscall is read()
	if getSyscallNumber(std) == SYSCALL64.READ:
		fd = getSyscallArgument(std, 0)
		if fd < 0x20:
			return
		buf_base = getSyscallArgument(std, 1)
		size = getSyscallArgument(std, 2)
		# print "READ() | fd: %d, buf_base : 0x%x, %d" % (fd, buf_base, size)
		readbuf = {'fd': fd, 'buf_base': buf_base, 'size': size, 'arch': 64}

	elif getSyscallNumber(std) == SYSCALL32.READ:
		fd = getSyscallArgument(std, 0)
		if fd < 0x20:
			return
		buf_base = getSyscallArgument(std, 1)
		size = getSyscallArgument(std, 2)
		# print "READ() | fd: %d, buf_base : 0x%x, %d" % (fd, buf_base, size)
		readbuf = {'fd': fd, 'buf_base': buf_base, 'size': size, 'arch': 32}


def syscallExit(threadId, std):
	global readbuf, instructionAddr, ctx, inst_write_flag

	if readbuf is not None and getSyscallReturn(std) > 0:
		fd = readbuf['fd']
		buf_base = readbuf['buf_base']
		size = readbuf['size']
		if size >= SSIZE_MAX:
			readbuf = None
			return
		arch = readbuf['arch']
		# routineName = getRoutineName(instructionAddr)
		f = None
		try:
			buf_data = getMemoryBytearr(buf_base, size)
			f = open(logfile+str(getPid())+logext, 'a+')
			# f.write("[+] PID/RTN/ADDR : %d/%s/%x\nsyscall%d read(%x, 0x%x, %d)\n%s\n" % 
			# 	(getPid(), routineName, instructionAddr, arch, fd, buf_base, size, 
			# 	hexdump(bytes(buf_data), result='return')[0:1216])) #76 bytes per line (16 bytes shown x 16 lines)

			f.write("[+] PID(%d): syscall%d read(%x, 0x%x, %d)\n%s\n" % 
				(getPid(), arch, fd, buf_base, size, 
				hexdump(bytes(buf_data), result='return')[0:1216])) #76 bytes per line (16 bytes shown x 16 lines)

			inst_write_flag = True
			
			if ctx.isTaintEngineEnabled() is False:
				ctx.enableTaintEngine(True)
				f.write("[DEBUG] taintEngineEnabled\n")
			# ctx.setTaintMemory(MemoryAccess(buf_base, size), True)

			# Iterate for each byte of memory (size in memoryaccess is just CPU.SIZE!)
			offset = 0
			while offset != size:
			    ctx.taintMemory(buf_base + offset)
			    concreteValue = getCurrentMemoryValue(buf_base + offset)
			    ctx.setConcreteMemoryValue(buf_base + offset, concreteValue)
			    ctx.convertMemoryToSymbolicVariable(MemoryAccess(buf_base + offset, CPUSIZE.BYTE))
			    offset += 1
			f.write("[+] %d bytes tainted from the memory 0x%x\n" % (offset, buf_base))

			f.close()
			# (Under development) Check if the message is 

		# except Exception:
		# 	# f.write("[+] PID/RTN/ADDR : %d/%s/%x\nsyscall%d read(%x, 0x%x, %d) (Over SSIZE_MAX or Protected)\n" %
		# 	# 	(getPid(), routineName, instructionAddr, arch, fd, buf_base, size))
		# 	# f.write("[+] syscall%d read(%x, 0x%x, %d) (Protected)\n" % 
		# 	# 	(arch, fd, buf_base, size))
		# 	pass
		except TypeError:
			pass
		except:
			printExecInfo(f=f)
		finally:
			readbuf = None

		# (Under construction) Taint memory read via specific IP source

def image(imagePath, imageBase, imageSize):
	f = open(logfile+str(getPid())+logext, 'a+')
	f.write('IMGLoad----------\n')
	f.write('Image path: '+imagePath+'\n')
	f.write('Image base: %s\n'% hex(imageBase))
	f.write('Image size: %d\n'% imageSize)
	f.close()


def before(instruction):
	global lastRoutineString, routineAddr, instructionAddr
	instructionAddr = instruction.getAddress()

	# Show AST Representation (symbolic execution) if it has tainted REG or MEM
	# if instruction.isSymbolized():
	# 	f = open(logfile+str(getPid())+logext, 'a+')
	# 	f.write('SymEx----------\n')
	# 	for expr in instruction.getSymbolicExpressions():
	# 		f.write("\t%s\n" % expr)
	# 	f.close()

	"""
	if instruction.getType() == OPCODE.CALL:
		routineAddr = getCurrentRegisterValue(getTritonContext().registers.rdi)
		print type(routineAddr)
	"""

def after(instruction):
	global ctx, instructionAddr, GREEN, ENDC, inst_write_flag
	# if inst_write_flag is True:
	# 	f = open(logfile+str(getPid())+logext, 'a+')
	# 	f.write("\t%x: %s\n" %(instructionAddr, instruction))
	# 	f.close()
	# Show instruction if it has tainted REG or MEM
	f = None
	try:
		if ctx.isTaintEngineEnabled():
			f = open(logfile+str(getPid())+logext, 'a+')
			if instruction.isBranch() is True:
				f.write("[B]")
			if instruction.isTainted() is True:
				f.write("[T]\t%#x: %s\n" %(instruction.getAddress(),instruction.getDisassembly()))
			else:
				f.write("\t%#x: %s\n" %(instruction.getAddress(), instruction.getDisassembly()))
			f.close()
	except:
		printExecInfo(f=f)

	

if __name__ == '__main__':

	# ctx.setArchitecture(ARCH.X86_64)
	ctx.enableSymbolicEngine(False)
	ctx.enableTaintEngine(False)
	ctx.enableMode(MODE.ALIGNED_MEMORY, True)
	#ctx.enableMode(MODE.ONLY_ON_TAINTED, True) # Perform symbolic execution only on tainted instructions

	# SET TRITON ANALYSIS STARTING POINT
	# startAnalysisFromEntry()
	startAnalysisFromSymbol('__read')

	# INSERT CALLS ON PIN
	# insertCall(before, INSERT_POINT.BEFORE)
	# insertCall(image, INSERT_POINT.IMAGE_LOAD)
	insertCall(syscallEntry, INSERT_POINT.SYSCALL_ENTRY)
	insertCall(syscallExit, INSERT_POINT.SYSCALL_EXIT)
	insertCall(after, INSERT_POINT.AFTER)
	

	# (Under construction) If the instruction refers to the tainted memory, mark as the range of bytes symbolic
	#insertCall(cb_ir,       INSERT_POINT.BEFORE_SYMPROC)

	# (Under construction) Print all the branches that encountered

	runProgram()

f.close()
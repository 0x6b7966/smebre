#! /usr/bin/env python

import os, sys, traceback, time
# import syscallmap32

import numpy as np
from triton import *
from pintool import *
from sets import Set
from hexdump import *

# GREEN = "\033[92m"
# ENDC  = "\033[0m"
SSIZE_MAX = 32767
logfile = "tritonlog_"
logext = ".log"
readbuf = None
inst_write_flag = False
ctx = getTritonContext()
astCtxt = ctx.getAstContext()
f = None
branch_cnt = 0
branch_sat_cnt = 0
branch_unsat_cnt = 0

def printExecInfo(verbose=True):
	global f, logfile, logext
	if f is None:
		f = open(logfile+str(getPid())+logext, 'a+')
	exc_type, exc_value, exc_traceback = sys.exc_info()
	if verbose is False:
		# Print error type only 
		f.write("[-] Error type in line %d: %s\n" %
			(exc_traceback.tb_lineno, exc_type) )
	else:
		tblist = traceback.format_exception(exc_type, exc_value, exc_traceback)
		f.write("[-] Error details:\n")
		for tbstr in tblist:
			f.write("%s"%tbstr)

def getMemoryBytearr(addr, size):
	a = bytearray()
	for index in range(0, size):
		val = getCurrentMemoryValue(addr+index)
		a.append(val)
	return a

def syscallEntry(threadId, std):
	global readbuf, stdset

	# Check if the syscall is read()
	if getSyscallNumber(std) == SYSCALL64.READ:
		fd = getSyscallArgument(std, 0)
		buf_base = getSyscallArgument(std, 1)
		size = getSyscallArgument(std, 2)
		if fd < 0x20 or size < 0x10:
			return
		# print "READ() | fd: %d, buf_base : 0x%x, %d" % (fd, buf_base, size)
		readbuf = {'fd': fd, 'buf_base': buf_base, 'size': size, 'arch': 64}

	elif getSyscallNumber(std) == SYSCALL32.READ:
		fd = getSyscallArgument(std, 0)
		buf_base = getSyscallArgument(std, 1)
		size = getSyscallArgument(std, 2)
		if fd < 0x20 or size < 0x10:
			return
		# print "READ() | fd: %d, buf_base : 0x%x, %d" % (fd, buf_base, size)
		readbuf = {'fd': fd, 'buf_base': buf_base, 'size': size, 'arch': 32}


def syscallExit(threadId, std):
	global f, readbuf, instructionAddr, ctx, inst_write_flag, branch_unsat_cnt, branch_sat_cnt

	if readbuf is not None and getSyscallReturn(std) > 0:
		fd = readbuf['fd']
		buf_base = readbuf['buf_base']
		size = readbuf['size']
		if size >= SSIZE_MAX:
			readbuf = None
			return
		arch = readbuf['arch']
		
		try:
			buf_data = getMemoryBytearr(buf_base, size)
			if f is None:
				f = open(logfile+str(getPid())+logext, 'a+')

			f.write("[+] PID(%d): syscall%d read(%x, 0x%x, %d)\n%s\n" % 
				(getPid(), arch, fd, buf_base, size, 
				hexdump(bytes(buf_data), result='return')[0:1216])) #76 bytes per line (16 bytes shown x 16 lines)

			inst_write_flag = True
			
			if ctx.isTaintEngineEnabled() is False:
				ctx.enableTaintEngine(True)
				f.write("[DEBUG] taintEngineEnabled\n")
			if ctx.isSymbolicEngineEnabled() is False:
				ctx.enableSymbolicEngine(True)
				f.write("[DEBUG] sylbolicEngineEnabled\n")

			ctx.clearPathConstraints()
			ctx.concretizeAllMemory()

			# Iterate for each byte of memory (size in memoryaccess is just CPU.SIZE!)
			offset = 0
			while offset != size:
			    ctx.taintMemory(buf_base + offset)
			    concreteValue = getCurrentMemoryValue(buf_base + offset)
			    ctx.setConcreteMemoryValue(buf_base + offset, concreteValue)
			    ctx.convertMemoryToSymbolicVariable(MemoryAccess(buf_base + offset, CPUSIZE.BYTE))
			    offset += 1
			f.write("[+] %d bytes tainted from the memory 0x%x\n" % (offset, buf_base))

		# except Exception:
		# routineName = getRoutineName(instructionAddr)
	 	# f.write("[+] PID/RTN/ADDR : %d/%s/%x\nsyscall%d read(%x, 0x%x, %d) (Over SSIZE_MAX or Protected)\n" %
	 	# 	(getPid(), routineName, instructionAddr, arch, fd, buf_base, size))
	 	# f.write("[+] syscall%d read(%x, 0x%x, %d) (Protected)\n" % 
	 	# 	(arch, fd, buf_base, size))
		# 	pass
		except TypeError:
			pass
		except:
			printExecInfo()
		finally:
			readbuf = None
			branch_unsat_cnt = 0
			branch_sat_cnt = 0

		# (Under construction) Taint memory read via specific IP source

def image(imagePath, imageBase, imageSize):
	f = open(logfile+str(getPid())+logext, 'a+')
	f.write('IMGLoad----------\n')
	f.write('Image path: '+imagePath+'\n')
	f.write('Image base: %s\n'% hex(imageBase))
	f.write('Image size: %d\n'% imageSize)
	f.close()

def path_constraints():
	global ctx
	pco = ctx.getPathConstraints()

	# List of symbolic values solved. list_brch_smvs[branch_idx][path_idx] 
	list_brch_smvs = []
	# if len(pco) < 15:
	# 	return list_brch_smvs
	for pc in pco:
		if pc.isMultipleBranches():
			p0   =  pc.getBranchConstraints()[0]['constraint']
			p1   =  pc.getBranchConstraints()[1]['constraint']
			p0_smvs = list()
			p1_smvs = list()

			# Branch 1
			models  = ctx.getModel(p0)
			if len(models) == 0:
			for k, v in models.items():
				p0_smvs.append(str(v))

			# Branch 2
			models  = ctx.getModel(p1)
			if len(models) == 0:
			for k, v in models.items():
				p1_smvs.append(str(v))

			list_brch_smvs.append(p0_smvs)
			list_brch_smvs.append(p1_smvs)

	# ctx.clearPathConstraints()
	return list_brch_smvs

def before(instruction):
	global f, lastRoutineString, routineAddr, instructionAddr, branch_sat_cnt, branch_unsat_cnt
	instructionAddr = instruction.getAddress()

	try:
		if ctx.isTaintEngineEnabled():
			if instruction.isTainted() is True:
				# f = open(logfile+str(getPid())+logext, 'a+')
				if instruction.isBranch() is True:
					st = time.time()
					list_brch_smvs = path_constraints()
					for brch_smvs in list_brch_smvs:
						if len(brch_smvs[0]) == 0 or len(brch_smvs[1]) == 0:
							branch_unsat_cnt += 1
							f.write('[-] Unsat branches no. : %d' % branch_unsat_cnt)
						else:
							branch_sat_cnt += 1
							f.write("[+] Sat branches no. : %d" % branch_sat_cnt)
							et = time.time() - st
							f.write('\t(Time elapsed : %.3f)\n' % et)
							f.write('B1 - %s\n' % ('|'.join(brch_smvs[0])))
							f.write('B2 - %s\n' % ('|'.join(brch_smvs[1])))
						f.write("B")
						f.write("\t%#x: %s\n" %(instruction.getAddress(), instruction.getDisassembly()))
				else:
					f.write("\t%#x: %s\n" %(instruction.getAddress(), instruction.getDisassembly()))
			# if instruction.getType() == OPCODE.CALL:
					# f.write("\t%#x: %s\n" %(instruction.getAddress(), instruction.getDisassembly()))

	except:
		printExecInfo()

	# Show AST Representation (symbolic execution) if it has tainted REG or MEM
	# if instruction.isSymbolized():
	# 	f = open(logfile+str(getPid())+logext, 'a+')
	# 	f.write('SymEx----------\n')
	# 	for expr in instruction.getSymbolicExpressions():
	# 		f.write("\t%s\n" % expr)
	# 	f.close()
	

def after(instruction):
	pass

if __name__ == '__main__':

	# ctx.setArchitecture(ARCH.X86_64)
	ctx.enableSymbolicEngine(False)
	ctx.enableTaintEngine(False)
	ctx.enableMode(MODE.ALIGNED_MEMORY, True)
	ctx.enableMode(MODE.ONLY_ON_TAINTED, True) # Perform symbolic execution only on tainted instructions

	# SET TRITON ANALYSIS STARTING POINT
	startAnalysisFromEntry()
	# startAnalysisFromSymbol('__read')

	setupImageWhitelist(['smbd'])

	# INSERT CALLS ON PIN
	insertCall(before, INSERT_POINT.BEFORE)
	# insertCall(image, INSERT_POINT.IMAGE_LOAD)
	insertCall(syscallEntry, INSERT_POINT.SYSCALL_ENTRY)
	insertCall(syscallExit, INSERT_POINT.SYSCALL_EXIT)
	# insertCall(after, INSERT_POINT.AFTER)

	# (Under construction) If the instruction refers to the tainted memory, mark as the range of bytes symbolic
	#insertCall(cb_ir,       INSERT_POINT.BEFORE_SYMPROC)
	runProgram()
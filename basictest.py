#! /usr/bin/env python
# Testing script targeting a simple binary


#! /usr/bin/env python

import os, sys, traceback
from triton import *
from pintool import *
from hexdump import *
ctx = None
checkflag = False
IMM = Immediate(1, 1)

def printExecInfo(verbose=True):
	exc_type, exc_value, exc_traceback = sys.exc_info()
	if verbose is False:
		# Print error type only 
		print "[-] Error type in line %d: %s" %	(exc_traceback.tb_lineno, exc_type)
	else:
		tblist = traceback.format_exception(exc_type, exc_value, exc_traceback)
		print "[-] Error details:"
		for tbstr in tblist:
			print "%s" % tbstr

def getMemoryBytearr(addr, size):
	a = bytearray()
	for index in range(0, size):
		val = getCurrentMemoryValue(addr+index)
		a.append(val)
	return a

# def syscallEntry(threadId, std):

# def syscallExit(threadId, std):

# def image(imagePath, imageBase, imageSize):

def path_constraints():
	global ctx
	pco = ctx.getPathConstraints()
	
	list_brch_smvs = [] # list_brch_smvs[branch_idx][path_idx] 
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
	global checkflag
	rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
	if instruction.getAddress() == 0x400597:
		print "rip : 0x%x (before)" % rip
	if instruction.getAddress() == 0x400599:
		checkflag = True
		print "gotit! rip : 0x%x (before)" % rip


def after(instruction):
	global ctx, checkflag
	if checkflag == True:
		checkflag = False
		print instruction
	try:
		if instruction.getAddress() == 0x400599:
			print "gotit! (after)"

		rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
		if instruction.isBranch() is True and instruction.getType() != 0x10a :
			# 1. Get two branches
			# (1) Next address
			
			o_next_addr = instruction.getNextAddress()
			# (2) Branch instruction operand
			# If the operand is from memory (skip it)
		
			# if not isinstance(instruction.getOperands()[0], type(IMM)):
			# 	print type(instruction.getOperands()[0])
			# 	j_next_addr = instruction.getOperands()[0]
		

			# # If the operand is from immedidate
			# j_next_addr = instruction.getOperands()[0].getValue()

			# f_next_addr = None

			# 2. Force to take the other path
			print "[B] %s (rip: 0x%x) -> 0x%x" % (instruction, rip, rip)
			if rip == o_next_addr:
				pass
				# print "\t(X) o_next_addr (rip) - 0x%x" % rip
				# f_next_addr = j_next_addr
				# print "\t(O) f_next_addr (negated) - 0x%x" % f_next_addr  
			else:
				print "===BINGO==="
				# print "\t(X) j_next_addr (rip) - 0x%x" % rip
				# f_next_addr = o_next_addr
				# print "\t(O) f_next_addr (negated) - 0x%x" % f_next_addr  

		else:
			print "[ ] %s (rip: 0x%x)" % (instruction, rip)

	except:
		printExecInfo()
		# present_inst = instruction.getAddress()
		# dissasm = instruction.getDisassembly()
		# rip = ctx.getConcreteRegisterValue(ctx.registers.rip)
		# print "[ ] 0x%x : %s" % (present_inst, dissasm)
		# print "\t0x%x -> 0x%x (B1) or 0x%x (B2)" % (present_inst, o_next_addr, opr_next_inst)
		

		##### Take snapshot(not yet) and peek another branch #####
		# ip = ctx.getConcreteRegisterValue(ctx.registers.rip)
		# f.write("[!] JMP from %x to %x\n" % (instructionAddr, ip))
		# f.write("\t%#x: %s\n" %(instruction.getAddress(), instruction.getDisassembly()))

		
if __name__ == '__main__':

	ctx = getTritonContext()
	# astCtxt = ctx.getAstContext()

	# ctx.setArchitecture(ARCH.X86_64)
	ctx.enableSymbolicEngine(False)
	ctx.enableTaintEngine(False)
	# ctx.enableMode(MODE.ALIGNED_MEMORY, True)
	# ctx.enableMode(MODE.ONLY_ON_TAINTED, True) # Perform symbolic execution only on tainted instructions

	setupImageWhitelist(['crackme_xor'])

	startAnalysisFromEntry()

	# insertCall(xxx, INSERT_POINT.BEFORE_SYMPROC)
	insertCall(before, INSERT_POINT.BEFORE)
	# insertCall(image, INSERT_POINT.IMAGE_LOAD)
	# insertCall(syscallEntry, INSERT_POINT.SYSCALL_ENTRY)
	# insertCall(syscallExit, INSERT_POINT.SYSCALL_EXIT)
	insertCall(after, INSERT_POINT.AFTER)

	runProgram()
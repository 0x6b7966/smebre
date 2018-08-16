#! /usr/bin/env python

import sys, os
path_file1 = sys.argv[1]
path_file2 = sys.argv[2]

def cmpline(l1, l2):
	idx1 = l1.find(':') + 2
	idx2 = l2.find(':') + 2
	fc1 = l1[idx1:idx1+1]
	fc2 = l2[idx2:idx2+1]
	if l1[idx1:] != l2[idx2:]:
		if fc1 == 'j' and fc2 == 'j':
			return 1
		if fc1 == 'c' and fc2 == 'c':
			return 1
		return -1
	return 1

f1 = open(path_file1, 'r')
f2 = open(path_file2, 'r')

# Read a line one by one from each file
lines1 = (x.rstrip('\n') for x in f1)
lines2 = (x.rstrip('\n') for x in f2)

linecount = 1
for l1, l2 in zip(lines1, lines2):
	if cmpline(l1, l2) < 0:
		print "[!] different inst found"
		print "[!] line no. %d" % linecount
		print "[!] line 1. %s" % l1
		print "[!] line 2. %s" % l2
		if linecount > 100000:
			sys.exit()
	linecount += 1

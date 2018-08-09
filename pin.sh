#!/bin/bash
# Run this command in the root of PIN directory.
# The location of Triton tracer (pintool) and our analysis script is just for instance.
# No need to use -follow_execv. The PIN automatically attaches libpintool.so and its corresponding script to each subprocess.

# Normal PIN with Triton pintool (x86_64).
LD_BIND_NOW=1 ./intel64/bin/pinbin -t source/tools/Triton/build/src/tracer/pin/libpintool.so -script ~/smebre/triton-samba-dbi.py -- /usr/sbin/smbd

# PIN attach with Triton Pintool
#LD_BIND_NOW=1 ./intel64/bin/pinbin -pid [process id] -t ./source/tools/Triton/build/src/tracer/pin/libpintool.so -script ~/smebre/triton-samba-dbi.py 

#!/bin/bash

# Normal PIN with Triton pintool
LD_BIND_NOW=1 /usr/src/pin/pin -follow_execv -ifeellucky -t /usr/src/pin/source/tools/Triton/build/src/tracer/pin/libpintool.so -script ~/smebre/triton-samba-dbi.py -- /usr/sbin/smbd

# PIN attach with Triton Pintool
#LD_BIND_NOW=1 ./pin -pid $1 -follow_execv -t ./source/tools/Triton/build/src/tracer/pin/libpintool.so -script ~/smebre/triton-samba-dbi.py 

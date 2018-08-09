#!/usr/bin/env python
# Demo for MASM syntax of Capstone Python bindings
# By Nguyen Anh Quynnh
 
from __future__ import print_function
from capstone import *
 
X86_CODE32 = b"\xba\xcd\xab\x00\x00\x8d\x4c\x32\x08\x81\xc6\x34\x12\x00\x00"
 
md = Cs(CS_ARCH_X86, CS_MODE_32)
 
print(">> Intel syntax:")
for insn in md.disasm(X86_CODE32, 0x1000):
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))
print()
 
# switch to MASM syntax
md.syntax = CS_OPT_SYNTAX_NASM
print(">> NASM syntax:")
for insn in md.disasm(X86_CODE32, 0x1000):
    print("0x%x:\t%s\t%s" % (insn.address, insn.mnemonic, insn.op_str))


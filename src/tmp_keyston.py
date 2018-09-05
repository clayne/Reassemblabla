#!/usr/bin/python
#-*- coding: utf-8 -*-

from keystone import *

def KEYSTONE_asm(CODE): # disasm_capstone 에서 또 틀린게뭐있나 확인해보기위해서 쓰는것
    try:
        # Initialize engine in X86-32bit mode
        ks = Ks(KS_ARCH_X86, KS_MODE_32)
        ks.syntax = KS_OPT_SYNTAX_ATT # ATT신텍스
        encoding, count = ks.asm(CODE)
    except KsError as e:
        encoding = []
    RET = ""
    for C in encoding:
        _c = hex(C)[2:]
        if len(_c) == 1:
            _c = '0'+ _c
        RET += _c
    return RET


#CODE = " bound.d8 %esp, 0x20(%ebp)"
CODE = " bound (%esp), %ebp"
print KEYSTONE_asm(CODE)

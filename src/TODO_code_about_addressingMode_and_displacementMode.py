#!/usr/bin/python
#-*- coding: utf-8 -*-
from capstone import *
from intelhex import IntelHex
from elftools.elf.elffile import ELFFile
import sys 
import os
import subprocess
import re
from optparse import OptionParser
import binascii 

import itertools # TODO!
#from __future__ import absolute_import

import argparse
import sys

from pwn import *
from pwnlib.commandline import common

from etc import *
from binary2dic import *

'''
aa = parseline(' 73c:   01 1b                   add    %ebx,(%ebx)','data')
print aa
'''
# TODO: prefix 가지는 어셈블리에 대해서도 핸들링 해줘야 함. 예를들어 punpckldq 의 modr/m바이트를 핸들링할수 있음. 하지만 punpckldq 앞에 prefix가 붙는 인스트럭션들은 아직 핸들링루틴이 구현되지않았음. 그 부분에 대해서도 해줄것
'''
# prefix 체크하는 법 : https://stackoverflow.com/questions/924303/how-to-write-a-disassembler/924336

1. Check if the current byte is an instruction prefix byte (F3, F2, or F0); if so, then you've got a REP/REPE/REPNE/LOCK prefix. Advance to the next byte.
2. Check to see if the current byte is an address size byte (67). If so, decode addresses in the rest of the instruction in 16-bit mode if currently in 32-bit mode, or decode addresses in 32-bit mode if currently in 16-bit mode
3. Check to see if the current byte is an operand size byte (66). If so, decode immediate operands in 16-bit mode if currently in 32-bit mode, or decode immediate operands in 32-bit mode if currently in 16-bit mode
4. Check to see if the current byte is a segment override byte (2E, 36, 3E, 26, 64, or 65). If so, use the corresponding segment register for decoding addresses instead of the default segment register.
5. The next byte is the opcode. If the opcode is 0F, then it is an extended opcode, and read the next byte as the extended opcode.
6. Depending on the particular opcode, read in and decode a Mod R/M byte, a Scale Index Base (SIB) byte, a displacement (0, 1, 2, or 4 bytes), and/or an immediate value (0, 1, 2, or 4 bytes). The sizes of these fields depend on the opcode , address size override, and operand size overrides previously decoded.
'''

#filename = './ex_dir/ex_relro'
resdic = binarycode2dic('/bin/dash')

mandatory_prefix = {'66':'???', 'F2':'???', 'F3':'???'}

# jmp : instruction itself contains address length information
# rel32 가 아니면 다 디폴트로는 rel8로 어셈블되니까
# 따로 rel8에 대해서 핸들링 안해줘도 될듯
jmp_rel32 = {'0x0f 0x83':['jae', 'jnb', 'jnc'],'0x0f 0x82':['jb', 'jc', 'jnae'],'0x0f 0x81':['jno'],'0x0f 0x80':['jo'],'0x0f 0x87':['ja', 'jnbe'],'0x0f 0x86':['jbe', 'jna'],'0x0f 0x85':['jne', 'jnz'],'0x0f 0x84':['je', 'jz'],'0x0f 0x89':['jns'],'0x0f 0x88':['js'],'0x0f 0x8a':['jp', 'jpe'],'0x0f 0x8c':['jl', 'jnge'],'0x0f 0x8b':['jnp', 'jpo'],'0xe9 0xcd':['jmp'],'0x0f 0x8f':['jg', 'jnle'],'0x0f 0x8e':['jle', 'jng'],'0x0f 0x8d':['jge', 'jnl']}

#TODO: 디폴트가 d8이 아닌 경우가 있어서 jmp_rel8 도 만들어줘야할듯
jmp_rel32 = {}

# 근데 코드사이 간격이 더 벌어져버려가지고 displacement 간격이 늘어나버려가지고 d8 이 d32 로 바껴버리면 어떡하지?
# 1. 우선 d8 로 내가 강제한 경우인데 displacement 가 1바이트가 넘어가져버리면 자동으로 d32 로 변환되나?
# 2. ==> 사실 이건 노상관일것같은게 애초에 아래가 문제가되는경우가 "데이터를 잘못 디스어셈블했을때"임


# modR/M byte : instruction that has modR/M byte which indecates for displacement length information
has_modrm_as_slash_r = {'0x66 0x0f 0x62':['punpckldq'], '0x0f 0xc7':['cmpxchg8b'], '0x0f 0xc4':['pinsrw'], '0x0f 0xc5':['pextrw'], '0x0f 0xc2':['cmpps'], '0x0f 0xc3':['movnti'], '0xf3 0x0f 0xc2':['cmpss'], '0xf2 0x0f 0x58':['addsd'], '0x66 0x0f 0xd4':['paddq'], '0x66 0x0f 0x7e':['movd'], '0x66 0x0f 0x68':['punpckhbw'], '0x66 0x0f 0xd7':['pmovmskb'], '0x66 0x0f 0xd0':['addsubpd'], '0x66 0x0f 0xd1':['psrlw'], '0x66 0x0f 0xd2':['psrld'], '0x66 0x0f 0xd3':['psrlq'], '0x28':['sub'], '0x29':['sub'], '0x22':['and'], '0x23':['and'], '0x20':['and'], '0x66 0x0f 0x7f':['movdqa'], '0x0f 0x76':['pcmpeqd'], '0x0f 0x74':['pcmpeqb'], '0x0f 0x75':['pcmpeqw'], '0xf3 0x0f 0x70':['pshufhw'], '0x66 0x0f 0xeb':['por'], '0x66 0x0f 0x6b':['packssdw'], '0x66 0x0f 0x6c':['punpcklqdq'], '0x66 0x0f 0x6a':['punpckhdq'], '0x66 0x0f 0x6f':['movdqa'], '0x66 0x0f 0x6d':['punpckhqdq'], '0x66 0x0f 0x6e':['movd'], '0x66 0x0f 0xdd':['paddusw'], '0xf2 0x0f 0x5f':['maxsd'], '0xf2 0x0f 0x5e':['divsd'], '0xf2 0x0f 0x5d':['minsd'], '0xf2 0x0f 0x5c':['subsd'], '0x66 0x0f 0xda':['pminub'], '0xf2 0x0f 0x5a':['cvtsd2ss'], '0x66 0x0f 0xdc':['paddusb'], '0x66 0x0f 0xee':['pmaxsw'], '0x0f 0xc6':['shufps'], '0xf3 0x0f 0x7f':['movdqu'], '0x66 0x0f 0x63':['packsswb'], '0x66 0x0f 0x60':['punpcklbw'], '0x66 0x0f 0x61':['punpcklwd'], '0x2b':['sub'], '0x66 0x0f 0xd8':['psubusb'], '0x2a':['sub'], '0x0f 0x7f':['movq'], '0x0f 0x7e':['movd'], '0x0f 0xc0':['xadd'], '0x0f 0xfa':['psubd'], '0x0f 0xfc':['paddb'], '0x0f 0xc1':['xadd'], '0x0f 0xfe':['paddd'], '0x0f 0xfd':['paddw'], '0x66 0x0f 0xdf':['pandn'], '0x66 0x0f 0xd5':['pmullw'], '0xf2 0x0f 0x59':['mulsd'], '0x0f 0x50':['movmskps'], '0x0f 0x51':['sqrtps'], '0x0f 0x52':['rsqrtps'], '0x0f 0x53':['rcpps'], '0x0f 0x54':['andps'], '0x0f 0x55':['andnps'], '0x0f 0x56':['orps'], '0x0f 0x57':['xorps'], '0xf3 0x0f 0x12':['movsldup'], '0x0f 0x59':['mulps'], '0xf3 0x0f 0x10':['movss'], '0xf3 0x0f 0x11':['movss'], '0xf3 0x0f 0x16':['movshdup'], '0xf2 0x0f 0x51':['sqrtsd'], '0xf2 0x0f 0x7c':['haddps'], '0x66 0x0f 0xe7':['movntdq'], '0x0f 0xf9':['psubw'], '0x0f 0xf8':['psubb'], '0x0f 0xf1':['psllw'], '0x0f 0xae':['stmxcsr', 'clflush', 'fxrstor', 'fxsave', 'ldmxcsr', 'lfence', 'mfence', 'sfence'], '0x0f 0xaf':['imul'], '0x0f 0x58':['addps'], '0x0f 0xf5':['pmaddwd'], '0x0f 0xf4':['pmuludq'], '0x0f 0xf7':['maskmovq'], '0x0f 0xf6':['psadbw'], '0x66 0x0f 0xc5':['pextrw'], '0x66 0x0f 0xc4':['pinsrw'], '0x66 0x0f 0xc6':['shufpd'], '0x66 0x0f 0xc2':['cmppd'], '0x0f 0x5a':['cvtps2pd'], '0x0f 0x5b':['cvtdq2ps'], '0x0f 0x5c':['subps'], '0x0f 0x5d':['minps'], '0x0f 0x5e':['divps'], '0x0f 0x5f':['maxps'], '0x0f 0x73':['psrlq', 'psllq'], '0x0f 0x70':['pshufw'], '0xf2 0x0f 0x7d':['hsubps'], '0x0f 0x71':['psrlw', 'psllw', 'psraw'], '0x0f 0xdf':['pandn'], '0x66 0x0f 0x69':['punpckhwd'], '0x0f 0xdd':['paddusw'], '0x0f 0xdc':['paddusb'], '0x0f 0xdb':['pand'], '0x0f 0xda':['pminub'], '0xf2 0x0f 0x12':['movddup'], '0xf2 0x0f 0x11':['movsd'], '0xf2 0x0f 0x10':['movsd'], '0x69':['imul'], '0x62':['bound'], '0x63':['arpl'], '0x0f 0xf2':['pslld'], '0x6b':['imul'], '0x0f 0xd9':['psubusw'], '0x0f 0xd8':['psubusb'], '0x0f 0xd7':['pmovmskb'], '0x0f 0xd5':['pmullw'], '0x0f 0xd4':['paddq'], '0x0f 0xd3':['psrlq'], '0x0f 0xd2':['psrld'], '0x0f 0xd1':['psrlw'], '0x9b 0xd9':['fstenv', 'fstcw'], '0xf2 0x0f 0xd0':['addsubps'], '0x66 0x0f 0x66':['pcmpgtd'], '0x0f 0xbe':['movsx'], '0x0f 0xbf':['movsx'], '0x0f 0xba':['bts', 'bt', 'btc', 'btr'], '0x0f 0x18':['prefetchh'], '0x0f 0x14':['unpcklps'], '0x0f 0x15':['unpckhps'], '0x0f 0x16':['movhps', 'movlhps'], '0x0f 0x17':['movhps'], '0x66 0x0f 0x67':['packuswb'], '0x0f 0x11':['movups'], '0x0f 0x12':['movhlps', 'movlps'], '0x0f 0x13':['movlps'], '0xd0':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd1':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd2':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd3':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd8':['fsubr', 'fadd', 'fcom', 'fcomp', 'fdiv', 'fdivr', 'fmul', 'fsub'], '0x0f 0x10':['movups'], '0x84':['test'], '0x85':['test'], '0x86':['xchg'], '0x87':['xchg'], '0x80':['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub'], '0x81':['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub'], '0x66 0x0f 0xde':['pmaxub'], '0x0f 0x6a':['punpckhdq'], '0x66 0x0f 0x64':['pcmpgtb'], '0x0f 0x6b':['packssdw'], '0x88':['mov'], '0x1b':['sbb'], '0x1a':['sbb'], '0x0f 0x6f':['movq'], '0xf2 0x0f 0xf0':['lddqu'], '0x66 0x0f 0xd9':['psubusw'], '0x0f 0xb5':['lgs'], '0x66 0x0f 0x16':['movhpd'], '0x66 0x0f 0x15':['unpckhpd'], '0x66 0x0f 0x14':['unpcklpd'], '0x66 0x0f 0x13':['movlpd'], '0x0f 0xb0':['cmpxchg'], '0x66 0x0f 0x11':['movupd'], '0x66 0x0f 0x10':['movupd'], '0x66 0x0f 0x65':['pcmpgtw'], '0x66 0x0f 0xf6':['psadbw'], '0x66 0x0f 0xf7':['maskmovdqu'], '0x0f 0x69':['punpckhwd'], '0x0f 0x68':['punpckhbw'], '0x8f':['pop'], '0x8a':['mov'], '0x19':['sbb'], '0x18':['sbb'], '0x0f 0x61':['punpcklwd'], '0x0f 0x60':['punpcklbw'], '0x0f 0x63':['packsswb'], '0x0f 0x62':['punpckldq'], '0x0f 0x65':['pcmpgtw'], '0x0f 0x64':['pcmpgtb'], '0x0f 0x67':['packuswb'], '0x0f 0x66':['pcmpgtd'], '0xda':['fisubr', 'fiadd', 'fidiv', 'fidivr', 'ficom', 'ficomp', 'fimul', 'fisub'], '0xdb':['fstp', 'fild', 'fist', 'fistp', 'fisttp', 'fld'], '0x66 0x0f 0xe8':['psubsb'], '0xdd':['fnstsw', 'fisttp', 'fld', 'frstor', 'fnsave', 'fst', 'fstp'], '0xde':['fisubr', 'fiadd', 'fidiv', 'fidivr', 'ficom', 'ficomp', 'fimul', 'fisub'], '0xdf':['fisttp', 'fbld', 'fbstp', 'fild', 'fist', 'fistp'], '0xd9':['fnstenv', 'fld', 'fldcw', 'fldenv', 'fst', 'fstp', 'fnstcw'], '0x31':['xor'], '0x66 0x0f 0xe9':['psubsw'], '0x11':['adc'], '0x30':['xor'], '0x66 0x0f 0x7c':['haddpd'], '0x3a':['cmp'], '0x66 0x0f 0x7d':['hsubpd'], '0x3b':['cmp'], '0x66 0x0f 0xec':['paddsb'], '0xf2 0x0f 0x2c':['cvttsd2si'], '0x66 0x0f 0xea':['pminsw'], '0xf2 0x0f 0x2a':['cvtsi2sd'], '0x66 0x0f 0xef':['pxor'], '0xf2 0x0f 0x2d':['cvtsd2si'], '0x66 0x0f 0xed':['paddsw'], '0x0f 0xb4':['lfs'], '0xf6':['test', 'div', 'idiv', 'imul', 'mul', 'neg', 'not'], '0xf7':['test', 'div', 'idiv', 'imul', 'mul', 'neg', 'not'], '0xf3 0x0f 0x6f':['movdqu'], '0x0f 0xde':['pmaxub'], '0x8b':['mov'], '0x32':['xor'], '0x83':['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub'], '0x66 0x0f 0x71':['psrlw', 'psllw', 'psraw'], '0x66 0x0f 0x70':['pshufd'], '0x66 0x0f 0x73':['psrlq', 'pslldq', 'psllq', 'psrldq'], '0x66 0x0f 0x72':['psrld', 'pslld', 'psrad'], '0x66 0x0f 0x75':['pcmpeqw'], '0x66 0x0f 0x74':['pcmpeqb'], '0x33':['xor'], '0x66 0x0f 0x76':['pcmpeqd'], '0x66 0x0f 0xe3':['pavgw'], '0x66 0x0f 0xe2':['psrad'], '0x66 0x0f 0xe1':['psraw'], '0x66 0x0f 0xe0':['pavgb'], '0x39':['cmp'], '0x38':['cmp'], '0x66 0x0f 0xe5':['pmulhw'], '0x66 0x0f 0xe4':['pmulhuw'], '0x0f 0x6e':['movd'], '0x89':['mov'], '0x0f 0x72':['psrld', 'pslld', 'psrad'], '0xff':['push', 'call', 'dec', 'inc', 'jmp'], '0xfe':['inc', 'dec'], '0x66 0x0f 0x5c':['subpd'], '0x66 0x0f 0x5b':['cvtps2dq'], '0x66 0x0f 0x5a':['cvtpd2ps'], '0x66 0x0f 0x5f':['maxpd'], '0x66 0x0f 0x5e':['divpd'], '0x66 0x0f 0x5d':['minpd'], '0x0f 0x2e':['ucomiss'], '0x0f 0x2d':['cvtps2pi'], '0x0f 0x2f':['comiss'], '0x0f 0x2a':['cvtpi2ps'], '0x0f 0x2c':['cvttps2pi'], '0x0f 0x2b':['movntps'], '0x9b 0xdd':['fstsw', 'fsave'], '0x0f 0xb7':['movzx'], '0x66 0x0f 0x59':['mulpd'], '0x66 0x0f 0x58':['addpd'], '0x66 0x0f 0x51':['sqrtpd'], '0x66 0x0f 0x50':['movmskpd'], '0x66 0x0f 0x57':['xorpd'], '0x66 0x0f 0x56':['orpd'], '0x66 0x0f 0x55':['andnpd'], '0x66 0x0f 0x54':['andpd'], '0x0f 0xf3':['psllq'], '0x66 0x0f 0x17':['movhpd'], '0x0f 0x21':['mov'], '0x0f 0x20':['mov'], '0x0f 0x23':['mov'], '0x0f 0x22':['mov'], '0x0f 0x29':['movaps'], '0x0f 0x28':['movaps'], '0x0f 0xb6':['movzx'], '0x0f 0xb1':['cmpxchg'], '0x66 0x0f 0x12':['movlpd'], '0x0f 0xb2':['lss'], '0x21':['and'], '0x66 0x0f 0x28':['movapd'], '0x66 0x0f 0x29':['movapd'], '0xf3 0x0f 0x2c':['cvttss2si'], '0xf3 0x0f 0x2a':['cvtsi2ss'], '0xf3 0x0f 0x2d':['cvtss2si'], '0x09':['or'], '0x66 0x0f 0xdb':['pand'], '0x8d':['lea'], '0x0f 0xfb':['psubq'], '0x8e':['mov'], '0x66 0x0f 0x2f':['comisd'], '0x66 0x0f 0x2d':['cvtpd2pi'], '0x66 0x0f 0x2e':['ucomisd'], '0x66 0x0f 0x2b':['movntpd'], '0x66 0x0f 0x2c':['cvttpd2pi'], '0x66 0x0f 0x2a':['cvtpi2pd'], '0x0f 0x03':['lsl'], '0x0f 0x02':['lar'], '0x0f 0x01':['smsw', 'invlpg', 'lgdt', 'lidt', 'lmsw', 'sgdt', 'sidt'], '0x0f 0x00':['verw', 'lldt', 'ltr', 'sldt', 'str', 'verr'], '0xc5':['lds'], '0xc4':['les'], '0xc7':['mov'], '0xc6':['mov'], '0xc1':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xc0':['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0x8c':['mov'], '0x13':['adc'], '0x12':['adc'], '0x0f 0xe0':['pavgb'], '0x0f 0xe1':['psraw'], '0x0f 0xe2':['psrad'], '0x0f 0xe3':['pavgw'], '0x0f 0xe4':['pmulhuw'], '0x0f 0xe5':['pmulhw'], '0x0f 0xe7':['movntq'], '0x0f 0xe8':['psubsb'], '0x0f 0xe9':['psubsw'], '0x10':['adc'], '0x66 0x0f 0xf2':['pslld'], '0x66 0x0f 0xf3':['psllq'], '0x66 0x0f 0xf1':['psllw'], '0x08':['or'], '0xf2 0x0f 0x70':['pshuflw'], '0x66 0x0f 0xf4':['pmuludq'], '0x66 0x0f 0xf5':['pmaddwd'], '0x66 0x0f 0xf8':['psubb'], '0x66 0x0f 0xf9':['psubw'], '0x00':['add'], '0x01':['add'], '0x02':['add'], '0x03':['add'], '0xdc':['fsubr', 'fadd', 'fcom', 'fcomp', 'fdiv', 'fdivr', 'fmul', 'fsub'], '0xf3 0x0f 0x52':['rsqrtss'], '0xf3 0x0f 0x53':['rcpss'], '0xf3 0x0f 0x51':['sqrtss'], '0xf3 0x0f 0x58':['addss'], '0xf3 0x0f 0x59':['mulss'], '0x0f 0xea':['pminsw'], '0x0f 0xeb':['por'], '0x0f 0xec':['paddsb'], '0x0f 0xed':['paddsw'], '0x0f 0xee':['pmaxsw'], '0x0f 0xef':['pxor'], '0xf2 0x0f 0xc2':['cmpsd'], '0xf3 0x0f 0x5f':['maxss'], '0xf3 0x0f 0x5d':['minss'], '0xf3 0x0f 0x5e':['divss'], '0xf3 0x0f 0x5b':['cvttps2dq'], '0xf3 0x0f 0x5c':['subss'], '0xf3 0x0f 0x5a':['cvtss2sd'], '0x66 0x0f 0xfb':['psubq'], '0x66 0x0f 0xfc':['paddb'], '0x66 0x0f 0xfa':['psubd'], '0x66 0x0f 0xfd':['paddw'], '0x66 0x0f 0xfe':['paddd'], '0x0a':['or'], '0x0b':['or']}



# modr/m 바이트가 /digit 으로 표현되는 인스트럭션들은
# 같은 기계어코드인데 --> 다른 디스어셈블리를 가질수가 있음 (D0 /4는 SAL, D0 /2는 RCL)
# 왜냐면 /digit 을 뭘로 셋팅하느냐에 따라서 다른인스트럭션으로 해석되게끔. 효율성을 추구했기 때문임. 
has_modrm_as_slash_digit = {'0x8f': ['pop'], '0xd8': ['fsubr', 'fadd', 'fcom', 'fcomp', 'fdiv', 'fdivr', 'fmul', 'fsub'], '0x0f 0xba': ['bts', 'bt', 'btc', 'btr'], '0xd9': ['fnstenv', 'fld', 'fldcw', 'fldenv', 'fst', 'fstp', 'fnstcw'], '0x83': ['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub'], '0xc7': ['mov'], '0x66 0x0f 0x71': ['psrlw', 'psllw', 'psraw'], '0x0f 0xc7': ['cmpxchg8b'], '0x66 0x0f 0x73': ['psrlq', 'pslldq', 'psllq', 'psrldq'], '0x66 0x0f 0x72': ['psrld', 'pslld', 'psrad'], '0x0f 0x18': ['prefetchh'], '0x0f 0xae': ['stmxcsr', 'clflush', 'fxrstor', 'fxsave', 'ldmxcsr', 'lfence', 'mfence', 'sfence'], '0x0f 0x01': ['smsw', 'invlpg', 'lgdt', 'lidt', 'lmsw', 'sgdt', 'sidt'], '0x0f 0x00': ['verw', 'lldt', 'ltr', 'sldt', 'str', 'verr'], '0xd0': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd1': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xd2': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xc6': ['mov'], '0xc1': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xc0': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0x9b 0xd9': ['fstenv', 'fstcw'], '0x0f 0x72': ['psrld', 'pslld', 'psrad'], '0x0f 0x73': ['psrlq', 'psllq'], '0x0f 0x71': ['psrlw', 'psllw', 'psraw'], '0xd3': ['shr', 'rcl', 'rcr', 'rol', 'ror', 'sal', 'sar', 'shl'], '0xf6': ['test', 'div', 'idiv', 'imul', 'mul', 'neg', 'not'], '0xdb': ['fstp', 'fild', 'fist', 'fistp', 'fisttp', 'fld'], '0xdc': ['fsubr', 'fadd', 'fcom', 'fcomp', 'fdiv', 'fdivr', 'fmul', 'fsub'], '0xdd': ['fnstsw', 'fisttp', 'fld', 'frstor', 'fnsave', 'fst', 'fstp'], '0xde': ['fisubr', 'fiadd', 'fidiv', 'fidivr', 'ficom', 'ficomp', 'fimul', 'fisub'], '0xdf': ['fisttp', 'fbld', 'fbstp', 'fild', 'fist', 'fistp'], '0xf7': ['test', 'div', 'idiv', 'imul', 'mul', 'neg', 'not'], '0xff': ['push', 'call', 'dec', 'inc', 'jmp'], '0x80': ['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub'], '0x9b 0xdd': ['fstsw', 'fsave'], '0xfe': ['inc', 'dec'], '0xda': ['fisubr', 'fiadd', 'fidiv', 'fidivr', 'ficom', 'ficomp', 'fimul', 'fisub'], '0x81': ['xor', 'adc', 'add', 'and', 'cmp', 'or', 'sbb', 'sub']}

'''
for i in xrange(len(z)):
	# line = '[\'' + z[i][0].lower() + '\'' + ', ' + '\'' + z[i][1].lower() + '\'' + '], '
	#sys.stdout.write(line)

	key   = z[i][0]
	value = z[i][1]
	if key not in has_modrm_as_slash_digit.keys():
		has_modrm_as_slash_digit.update({key:['']})
	
	if value not in has_modrm_as_slash_digit[key]: # has_modrm_as_slash_digit[key]배열중 하나가 아니라면
		has_modrm_as_slash_digit[key].append(value)
		print "{} : {}".format(key, value)
		print "{} : {}".format(key, has_modrm_as_slash_digit[key])
		print "{} added!".format(value)
		print ""
print has_modrm_as_slash_digit
'''

# TODO: Also handle instruction using ".s" directive.
def check_displacement_bit(one_byte):
	one_byte =  int(one_byte,16)
	if   one_byte / 0b11000000 is 1:
		return ''
	elif one_byte / 0b10000000 is 1:
		return '.d32'
	elif one_byte / 0b01000000 is 1:
		return '.d8'
	else:
		return ''


for sectionName in resdic.keys():
	sortedkeylist = sorted(resdic[sectionName])
	for addr in sortedkeylist:
		machinecode = resdic[sectionName][addr][2].split(' ')[1:]
		disasemcode = resdic[sectionName][addr][1].split(' ')[1:]
		machinecode_line = resdic[sectionName][addr][2][4:-1] # '#=>' 와 ' '를 잘라낸다
		#print len(machinecode_line)
		#print machinecode_line
		#print ""
		if len(disasemcode) >= 1:
			if disasemcode[0] in jmp_rel32.keys() : # 인스트럭션이 점프인데
				if machinecode[0] in jmp_rel32.values(): # 머신코드가 jmp_rel32 에 정의된거일경우
					disasemcode[0] = disasemcode[0] + '.d32'
					resdic[sectionName][addr][1] = '' # 초기화
					for i in xrange(len(disasemcode)):
						resdic[sectionName][addr][1] +=  ' ' + disasemcode[i]
			
			elif disasemcode[0] in list(itertools.chain(*has_modrm_as_slash_r.values())): # python flat list
				for modrm_key in has_modrm_as_slash_r.keys(): 
					if disasemcode[0] in has_modrm_as_slash_r[modrm_key] and machinecode_line.find(modrm_key) == 0: # 머신코드가 인덱스0에서부터 일치하는지 확인
						modrmbyte = machinecode_line[len(modrm_key)+1:len(modrm_key)+5]
						d32_or_d8 = check_displacement_bit(modrmbyte)
						disasemcode[0] = disasemcode[0] + d32_or_d8
						resdic[sectionName][addr][1] = '' # 초기화
						for i in xrange(len(disasemcode)):
							resdic[sectionName][addr][1] +=  ' ' + disasemcode[i]

			elif disasemcode[0] in list(itertools.chain(*has_modrm_as_slash_digit.values())): # 우선은 체크만하고 
				for modrm_key in has_modrm_as_slash_digit.keys(): # 모든 키들에 대해서 
					if disasemcode[0] in has_modrm_as_slash_digit[modrm_key] and machinecode_line.find(modrm_key) == 0: # 키 찾았당 
						modrmbyte = machinecode_line[len(modrm_key)+1:len(modrm_key)+5]
						d32_or_d8 = check_displacement_bit(modrmbyte)
						disasemcode[0] = disasemcode[0] + d32_or_d8
						resdic[sectionName][addr][1] = '' # 초기화
						for i in xrange(len(disasemcode)):
							resdic[sectionName][addr][1] +=  ' ' + disasemcode[i]
			
gen_assemblyfile(resdic, '/bin/dash')



















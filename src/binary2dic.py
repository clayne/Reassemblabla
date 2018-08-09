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

from etc import *


# TODO: 예외처리 다 해줬나?
def disasm_capstone(_scontents, _sbaseaddr, _ssize):
	cs = Cs(CS_ARCH_X86, CS_MODE_32)
	cs.detail = True   
	cs.syntax = CS_OPT_SYNTAX_ATT # CS_OPT_SYNTAX_NASM, CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT
	dics_of_text = {} 
	_offset = 0
	
	_sendaddr = _sbaseaddr + _ssize
	while _sbaseaddr + _offset < _sendaddr: # 베이스어드레스도 바뀌고 오프셋도 바뀜
		_errorcode = 'default' # errorcode init
		
		DISASM = cs.disasm(_scontents, _sbaseaddr)
		for i in DISASM: 
			# MODR/M BIT HANDLING
			if   i.modrm / 0b11000000:
				_displacement = ''
			elif i.modrm / 0b10000000:
				_displacement = '.d32'
			elif i.modrm / 0b01000000:
				_displacement = '.d8'
			else:
				_displacement = ''
			
			
			# PREFIX HANDLING
			'''
			prefix[0] : 2. String manipulation instruction prefixes(REP(F3), REPE(F3), REPNE(F2)) + LOCK (F0)
			prefix[1] : 3. Segment override prefix (CS(0x2e) SS(0x36) DS(0x3e) ES(0x26) FS(0x64) GS(0x65))
			prefix[2] : 4. Operand override, 66h ( decode immediate operands in 16-bit mode if currently in 32-bit mode, or decode immediate operands in 32-bit mode if currently in 16-bit mode)
			prefix[3] : 5. Address override, 67h (decode addresses in the rest of the instruction in 16-bit mode if currently in 32-bit mode, or decode addresses in 32-bit mode if currently in 16-bit mode)
			'''
			
			# [01] CAPSTONE 'repz' IGNORING ISSUE HANDLING
			if binascii.hexlify(i.bytes).startswith('f3') or binascii.hexlify(i.bytes).startswith('f2') : # REP/REPE, REPNE
				if not i.mnemonic.startswith('rep'): # BUG!
					#print "OFFSET(REP) : {}".format(_offset)
					_byte = binascii.hexlify(_scontents[_offset:_offset+1])
					if _byte =='f3' : _rep = 'rep'
					else : _rep = 'repne'
					
					dics_of_text[i.address] =   [
												'', 
												_rep, 
												'#=> ' + _byte
												]
					_offset = _offset + 1 # 다음인스트럭션의 오프셋은 1 커졌다
					_scontents  = _scontents[_offset:] 
					_sbaseaddr  = _sbaseaddr + _offset 
					_offset = 0 
					_errorcode = 'rep handling'
					break       # restart "cs.disasm"
					
					
			# [02] CAPSTONE 0x66, 0x90 TO 'nop' ISSUE HANDLING 
			if binascii.hexlify(i.bytes) == '6690':
				#print "OFFSET(NOP ERROR) : {}".format(_offset)
				_errorcode = 'goto data' # 데이터처리 부분으로 보내버리기 
				
			
			# DEFAULT
			if _errorcode == 'default' :
				#print "OFFSET(DEFAULT) : {}".format(_offset)			
				dics_of_text[i.address] =   [
											'', 
											str(' ' + i.mnemonic + _displacement + ' ' + i.op_str), 
											'#=> ' + binascii.hexlify(i.bytes)
											]
				
				_offset = _offset + i.size # 다음 오프셋을 설정 
			

		
		
		# DEFAULT EXCAPTION: DATA INTERLEAVED INSIDE CODE SECTION
		if (_errorcode == 'default' or _errorcode == 'goto data') and _sbaseaddr + _offset < _sendaddr : 
			#print "OFFSET(DATA) : {}".format(_offset)
			_saddress = _sbaseaddr + _offset
			dics_of_text[_saddress] = 	[
										'', 
										' .byte 0x' + binascii.hexlify(_scontents[_offset:_offset+1]), 
										'#=> ' + binascii.hexlify(_scontents[_offset:_offset+1])
										]
			
			_offset    = _offset + 1 # 다음 오프셋을 설정
			_scontents = _scontents[_offset:]
			_sbaseaddr  = _sbaseaddr + _offset
			_offset = 0 # 오프셋 업데이트
	
	
	return dics_of_text

def binarydata2dic(filename):
	'''
	ex)
		extract {'section name', ***dic***}
			***dic*** =   {('40123941':['디렉티브자리','pop %eax']),
						   ('40123944':['디렉티브자리','pop %ebx'])
														...	  }
	'''
	datadic = {}
	retdic = {}
	
	bin = ELFFile(open(filename,'rb'))
	f = open(filename,'r')
	binfile = f.read()
	
	data_section = ['.data','.rodata'] 
	for i in xrange(len(data_section)):
		s_start = bin.get_section_by_name(data_section[i]).header.sh_addr
		s_offset = bin.get_section_by_name(data_section[i]).header.sh_offset
		s_size = bin.get_section_by_name(data_section[i]).header.sh_size
		s_contents = binfile[s_offset:s_offset+s_size]
		datadic = {} # initialize
		for j in xrange(s_size):
			addr = s_start + j
			offset = s_offset + j
			_byte = binascii.b2a_hex(binfile[offset])
			datadic[addr] = ['', " .byte 0x" + _byte, '#=> 0x'+_byte]
		retdic[data_section[i]] = datadic
	# zero-fill-on-demand
	zeroinit_section = ['.bss']
	s_start = bin.get_section_by_name('.bss').header.sh_addr
	s_offset = bin.get_section_by_name('.bss').header.sh_offset
	s_size = bin.get_section_by_name('.bss').header.sh_size
	datadic = {} # initialize 0x00 from sh_addr to sh_addr+sh_size
	for j in xrange(s_size):
		addr = s_start + j
		datadic[addr] = ['', " .byte 0x00",'#=> 0x00']
	retdic['.bss'] = datadic
	
	return retdic

# objdump 버전
'''
def binarycode2dic(filename): 
	cmd = 'objdump -D '+filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	mydic = {} # initialize
	Scontents = {} # section contents
	Sname = "" 	   # section name
	record_start = 0
	record_end = 0
	section_list = ['.text','.plt.got','.init'] 
	for i in range(0,len(lines)):
		if len(lines[i]) > 1: # ignore '\n', '\r' line
			if lines[i].startswith('Disassembly of section'):
				if record_start is 1:
					record_end = 1 # 레코딩 중이였다면, 레코딩을 끝냄 
				if record_start is 1 and record_end is 1:
					mydic[Sname] = Scontents
					record_start = 0
					record_end = 0
					Scontents = {}
					
				Sname = lines[i].replace('Disassembly of section ','',1)[:-1] # 마지막 ':' 제거
				if Sname in section_list:
					record_start = 1 # 레코딩을 시작한다
					print "recording stsrt!!! section:{}... ".format(Sname)
			elif record_start is 1 and record_end is 0: # 레코딩 활성화상태
				if lines[i][-1] != ':': # ignore dummy line(ex. '08048340 <_start>:')
					line = parseline(lines[i], "text") # line 은 엔트리 1개짜리 딕셔너리
					Scontents.update(line)
				
	return mydic			
'''

# capstone 버전
def binarycode2dic(filename, SHTABLE): 
	f = open(filename, 'rb')
	fread = f.read()
	
	SectionName = ['.text','.plt.got','.init','.plt'] 
	#SectionName = ['.text', '.dynstr']
	resdic = {}
	
	for _sname in SectionName:
		if _sname in SHTABLE.keys():
			#print("{} exist!".format(_sname))
			_soffset   = SHTABLE[_sname]['sh_offset']
			_ssize     = SHTABLE[_sname]['sh_size']
			_scontents = fread[_soffset:_soffset+_ssize]
			_sbaseaddr  = SHTABLE[_sname]['sh_addr']
			
			#print("hey! {} section region is {} ~~~ {}".format(_sname,hex(_sbaseaddr), hex(_sbaseaddr+_ssize)))
			resdic[_sname] = disasm_capstone(_scontents, _sbaseaddr, _ssize) 
		else:
			"no.."
	return resdic


def get_dynsymtab(filename):
	'''
	- usage)
		input : binary name
		output : dict {address:symbolname, ...}
	'''
	print "get_dynsymtab"
	cmd = 'objdump -T '+filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	symtab = {}
	for i in range(0,len(lines)):
		line = re.sub('\s+',' ',lines[i]).strip() # duplicate space, tab --> single space
		l = line.split(' ')
		if len(l) > 5:
			if not l[0].startswith("00000000"):	
				if l[3] == '.bss': 
					# ['08051198', 'g', 'DO', '.bss', '00000004', 'GLIBC_2.0', 'stdout']
					symtab[int('0x'+l[0], 16)] = l[6]
	return symtab

def get_reldyn(filename):
	'''
	# input : 파일이름
	# output : reldyn 섹션의 dictionary 를 리턴함 {[08049ff4:'printf']} 어쩌구... <- 참고로 Full_Relro 에서만 사용됨. 
	'''
	'''
	Relocation section '.rel.dyn' at offset 0x2a0 contains 3 entries:
	Offset     Info    Type            Sym.Value  Sym. Name
	08049ff4  00000206 R_386_GLOB_DAT    00000000   printf@GLIBC_2.0
	08049ff8  00000106 R_386_GLOB_DAT    00000000   __gmon_start__
	08049ffc  00000406 R_386_GLOB_DAT    00000000   __libc_start_main@GLIBC_2.0
	
	The decoding of unwind sections for machine type Intel 80386 is not currently supported.
	'''
	cmd = 'readelf -a ' + filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	for i in xrange(len(lines)):
		if 'Relocation section \'.rel.dyn\'' in lines[i]:
			start = i + 2 # line 0 (Relocation section '.rel.dyn' 어쩌구..), line 1 (Offset Info Type 어쩌구..) 제외
			for j in xrange(start, len(lines)):
				if len(lines[j]) is 0: # '.rel.dyn' 이 끝나면
					end = j
					break
			break
	lines = lines[start:end]
	reldyn = {}

	for i in xrange(len(lines)):
		lines[i] = re.sub('\s+',' ',lines[i]).strip() # duplicate space, tab --> single space
		l_split = lines[i].split(' ')
		if len(l_split) >= 5 : # 쓸모없는 엔트리 3개짜리 라인들을 제외 ("0002b0fc  00000008 R_386_RELATIVE")
			offset = l_split[0] 
			name   = l_split[4]
			offset = int('0x'+offset,16)
			if '@' in name: # "getpwnam@GLIBC_2.0" 에서 이름만 파싱
				name = name[:name.index('@')]
				reldyn.update({offset:name})
	
	return reldyn
	
def get_relplt(filename):
	cmd = 'readelf -a ' + filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	for i in xrange(len(lines)):
		if 'Relocation section \'.rel.plt\'' in lines[i]:
			start = i + 2 # line 0 (Relocation section '.rel.dyn' 어쩌구..), line 1 (Offset Info Type 어쩌구..) 제외
			for j in xrange(start, len(lines)):
				if len(lines[j]) is 0: # '.rel.dyn' 이 끝나면
					end = j
					break
			break
	lines = lines[start:end] 
	reldyn = {}

	for i in xrange(len(lines)):
		lines[i] = re.sub('\s+',' ',lines[i]).strip() # duplicate space, tab --> single space
		l_split = lines[i].split(' ')
		if len(l_split) >= 5 : # 쓸모없는 엔트리 3개짜리 라인들을 제외 ("0002b0fc  00000008 R_386_RELATIVE")
			offset = l_split[0] 
			name   = l_split[4]
			offset = int('0x'+offset,16)
			if '@' in name: # "getpwnam@GLIBC_2.0" 에서 이름만 파싱
				name = name[:name.index('@')]
				reldyn.update({offset:name})
	
	return reldyn




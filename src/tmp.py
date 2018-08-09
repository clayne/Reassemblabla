#!/usr/bin/python
#-*- coding: utf-8 -*-
#from __future__ import print_function
import sys 
import os
import pwn
import binascii
from capstone import *
from elftools.elf.elffile import ELFFile
from pwnlib import *
from pwn import *
from elftools import *
from etc import *
from linkerhandling import *

#from linkerhandling import *

# CHECK: capstone을 쓰면 단일디스어셈블리의 의미를 오목조목 다 살펴볼수있어서 좋지만
# 바이너리전체를 디스어셈블하기에는 비적절. 왜냐면 리컬시브 트레버설방식을 못쓰기때문임
# 그러면 캡스톤을 이용해서 제작한 디스어셈블러를 가져다가 
# 1. CS_OPT_SYNTAX_NASM 으로 디스어셈블하게끔 하기
# 2. d32, d8 이런거 붙여주고 frefix도 내가 준 프리픽스대로 잘 처리되서 어셈블되도록 하기

def get_shtable(filename): # 섹션들에 대한 정보들을 가지고있는 테이블
	SHTABLE = {}
	f = open(filename,'rb')
	elffile = ELFFile(f)
	for nsec, section in enumerate(elffile.iter_sections()):
		entry = {} # initializaion
		entry['sh_type']      = section['sh_type']
		entry['sh_addr']      = section['sh_addr']
		entry['sh_offset']    = section['sh_offset']
		entry['sh_size']      = section['sh_size']
		entry['sh_entsize']   = section['sh_entsize']
		entry['sh_flags']     = section['sh_flags']
		entry['sh_link']      = section['sh_link']
		entry['sh_info']      = section['sh_info']
		entry['sh_addralign'] = section['sh_addralign']
		SHTABLE[section.name]  = entry
	f.close()
	return SHTABLE

# The manual says LOCK only supports ADD, ADC, AND, BTC, BTR, BTS, CMPXCHG, CMPXCH8B, DEC, INC, NEG, NOT, OR, SBB, SUB, XOR, XADD, and XCHG. 


# {주소 : ['', '디스어셈블리', '#=> 바이트코드'], 주소 : ['', '디스어셈블리', '#=> 바이트코드']} 이렇게주면됨 
def disasm_capstone(_scontents, _sbaseaddr, _ssize):
	cs = Cs(CS_ARCH_X86, CS_MODE_32)
	cs.detail = True   
	cs.syntax = CS_OPT_SYNTAX_INTEL # CS_OPT_SYNTAX_NASM, CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT
	dics_of_text = {} 
	_offset = 0
	
	_sendaddr = _sbaseaddr + _ssize
	while _sbaseaddr + _offset < _sendaddr: # 베이스어드레스도 바뀌고 오프셋도 바뀜
		print "===restart while at {}!!!".format(_sbaseaddr)
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
					print "OFFSET(REP) : {}".format(_offset)
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
				print "OFFSET(NOP ERROR) : {}".format(_offset)
				_errorcode = 'goto data' # 데이터처리 부분으로 보내버리기 
				
			
			# DEFAULT
			if _errorcode == 'default' :
				print "OFFSET(DEFAULT) : {}".format(_offset)			
				dics_of_text[i.address] =   [
											'', 
											str(' ' + i.mnemonic + _displacement + ' ' + i.op_str), 
											'#=> ' + binascii.hexlify(i.bytes)
											]
				
				_offset = _offset + i.size # 다음 오프셋을 설정 
			

		
		
		# DEFAULT EXCAPTION: DATA INTERLEAVED INSIDE CODE SECTION
		if (_errorcode == 'default' or _errorcode == 'goto data') and _sbaseaddr + _offset < _sendaddr : 
			print "OFFSET(DATA) : {}".format(_offset)
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
	
	
			# print "DETAILS..."
			# print "mnemonic     : {}".format(i.mnemonic)   
			# print "op_str       : {}".format(i.op_str)   
			# 
			# print "groups       : {}".format(i.groups)    
			# print "regs_read    : {}".format(i.regs_read)   
			# print "regs_write   : {}".format(i.regs_write)
			# 
			# print "inst ID      : {}".format(i.id)   # instruction ID 
			# print "size         : {}".format(i.size) # length of instruction
			# print "prefix       : {}".format(i.prefix)
			# print "opcode       : {}".format(i.opcode)
			# print "addr_size    : {}".format(i.addr_size)
			# print "modrm        : {}".format(i.modrm)
			# print "disp         : {}".format(i.disp)
			# print "sib          : {}".format(i.sib)
			# print "instruction  : {}".format(binascii.hexlify(i.bytes)) # real byte of instruction
			# print ""

			
	'''
		print("prefix       : {}".format(i.prefix))
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
		print("instruction  : {}".format(binascii.hexlify(i.bytes))) # real byte of instruction
		print("")
		
		if i.prefix[0]+i.prefix[1]+i.prefix[2]+i.prefix[3] == 0:
			"nono.."
		else:
			# 뭐가 Repeat/lock 프리픽스를 담냐?
			# prefix[0] 은 2. String manipulation instruction prefixes(REP(F3), REPE(F3), REPNE(F2)) 다른데서보니까 LOCK (F0)도 이 범주에 속한다고함. 캡스톤이 얘를 디스어셈블 못한다는게 문제지만...
			# prefix[1] 은 3. Segment override prefix(CS(0x2e) SS(0x36) DS(0x3e) ES(0x26) FS(0x64) GS(0x65))
			# prefix[2] 은 4. Operand override, 66h ( decode immediate operands in 16-bit mode if currently in 32-bit mode, or decode immediate operands in 32-bit mode if currently in 16-bit mode)
			# prefix[3] 은 5. Address override, 67h (decode addresses in the rest of the instruction in 16-bit mode if currently in 32-bit mode, or decode addresses in 32-bit mode if currently in 16-bit mode)
			prefix = i.prefix[3]
			bytes = binascii.hexlify(i.bytes)
			

			if prefix != 0:
				if prefix==0x67:
					"no"
				else:
					print("prefix       : {}".format(prefix))
					print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
					print("instruction  : {}".format(bytes)) # real byte of instruction
					print("")
	'''
		
	'''
hahahahaha
		
		disassembled_line = i.mnemonic + _d + ' '+ i.op_str
		
		try: # jmp, call, je, 이런 분기문에 대해서는 어셈블을 못했음. 왜냐면 어셈블이 안되서 비교를 못했기때문임
			pwn.asm(disassembled_line)
			success = 1
		except:
			success = 0
		if success is 1:
			if binascii.hexlify(pwn.asm(disassembled_line)) != binascii.hexlify(i.bytes):
				f.write(disassembled_line)
				f.write('\n')
				f.write(binascii.hexlify(pwn.asm(disassembled_line)))
				f.write('\n')
				f.write(binascii.hexlify(i.bytes))
				f.write('\n\n')
				print "\n\n\n\n\nOOOHHHHhhHHHH!!!!!!\n\n\n\n\n"
	'''
		
		
		
		
def binarycode2dic(filename, SHTABLE): 
	f = open(filename, 'rb')
	fread = f.read()
	
	#SectionName = ['.text','.plt.got','.init'] 
	SectionName = ['.text', '.dynstr']
	resdic = {}
	
	for _sname in SectionName:
		if _sname in SHTABLE.keys():
			print("{} exist!".format(_sname))
			_soffset   = SHTABLE[_sname]['sh_offset']
			_ssize     = SHTABLE[_sname]['sh_size']
			_scontents = fread[_soffset:_soffset+_ssize]
			_sbaseaddr  = SHTABLE[_sname]['sh_addr']
			
			print("hey! {} section region is {} ~~~ {}".format(_sname,hex(_sbaseaddr), hex(_sbaseaddr+_ssize)))
			resdic[_sname] = disasm_capstone(_scontents, _sbaseaddr, _ssize) 
		else:
			print("{} no...".format(_sname))
	return resdic

	
	


	
	
	
	

	
	
	
if __name__=="__main__":
	filename = 'test'
	SHTABLE = get_shtable(filename)
	
	resdic = binarycode2dic(filename, SHTABLE)
	resdic_data = binarydata2dic(filename)
	resdic.update(resdic_data)
	
	entrypointaddr = findenytypoint(filename)
	resdic['.text'][entrypointaddr][0] = "_start:"
	
	# checksec 돌린다 (pie, packed, relro 등등 사용가능)
	checksec_gogo = pwnlib.elf.elf.ELF(filename, False)
	
	if checksec_gogo.relro == 'Full': # if full_relro라면
		print "full relro!"
		reldyn = get_reldyn(filename)
		lfunc_revoc_linking_fullrelro(resdic, reldyn)

	else: 
		print "partial relro!"
		resdic['.text'] = lfunc_revoc_linking(resdic['.text']) # 링킹풀어줌
		resdic['.init'] = lfunc_revoc_linking(resdic['.init']) # 링킹풀어줌
	
	# BSS dynamic symbol handling
	symtab = get_dynsymtab(filename) 
	global_symbolize_bss(resdic['.bss'], symtab)
	
	# 심볼라이즈 전에 brackets를 다 제거해야징
	remove_brackets(resdic['.text']) 
	remove_brackets(resdic['.init']) 

	# data, text 섹션들 심볼라이즈
	lfunc_symbolize_textsection(resdic)
	lfunc_symbolize_datasection(resdic)
	
	# 남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다 
	lfunc_remove_callweirdaddress(resdic['.text'])
	lfunc_remove_callweirdaddress(resdic['.init']) # 이게이상함. 중복된 MYSYM_17 을 만듦
	

	# BSS dynamic symbol 을 없애버린다. 
	not_global_symbolize_bss(resdic['.bss'], symtab)
	
	if options.align is True: 
		if '.text' in resdic.keys():
			resdic['.text'] = align_text(resdic['.text'])
		if '.rodata' in resdic.keys():
			resdic['.rodata'] = align_data(resdic['.rodata'])
		if '.data' in resdic.keys():
			resdic['.data'] = align_data(resdic['.data'])
		if '.bss' in resdic.keys():
			resdic['.bss'] = align_data(resdic['.bss'])
		
	if options.datainsert is True:
		for i in range(0, len(resdic['.rodata'])):
			if len(resdic['.rodata'].values()[i][0]) != 0: # 만약에 심볼이있다면 데이터처음부분에 INSRTED DATA 를넣자
				resdic['.rodata'].values()[i][1] = " .byte 0x49, 0x4e, 0x53, 0x45, 0x52, 0x54, 0x45, 0x44, 0x5f\n" + resdic['.rodata'].values()[i][1]
				# print resdic['.rodata'].values()[i][1]
	
	gen_assemblyfile(resdic, filename)
	gen_compilescript(filename)
	gen_assemblescript(filename)
	
	onlyfilename = filename.split('/')[-1]
	
	
	
	
	
	
	
	
	
	
	
	
	resdic = binarycode2dic(filename,SHTABLE)
	resdic_data = binarydata2dic(filename)
	resdic.update(resdic_data)
	
	entrypointaddr = findenytypoint(filename)
	resdic['.text'][entrypointaddr][0] = "_start:"
	
	# checksec 돌린다 (pie, packed, relro 등등 사용가능)
	checksec_gogo = pwnlib.elf.elf.ELF(filename, False)
	
	if checksec_gogo.relro == 'Full': # if full_relro라면
		print "full relro!"
		reldyn = get_reldyn(filename)
		lfunc_revoc_linking_fullrelro(resdic, reldyn)

	else: 
		print "partial relro!"
		# .text 섹션이 없을리가 없겠지만
		if '.text' in resdic.keys(): resdic['.text'] = lfunc_revoc_linking(resdic['.text']) # 링킹풀어줌
		if '.init' in resdic.keys(): resdic['.init'] = lfunc_revoc_linking(resdic['.init']) # 링킹풀어줌
	
	# BSS dynamic symbol handling
	###symtab = get_dynsymtab(filename) 
	###global_symbolize_bss(resdic['.bss'], symtab)
	
	# 심볼라이즈 전에 brackets를 다 제거해야징
	remove_brackets(resdic['.text']) 
	remove_brackets(resdic['.init']) 

	# data, text 섹션들 심볼라이즈
	lfunc_symbolize_textsection(resdic)
	lfunc_symbolize_datasection(resdic)
	
	# 남은것들 (symbolization 이 안된 것들) 을 일괄적으로 처리한다 
	lfunc_remove_callweirdaddress(resdic['.text'])
	lfunc_remove_callweirdaddress(resdic['.init']) 
	

	# BSS dynamic symbol 을 없애버린다. 
	###not_global_symbolize_bss(resdic['.bss'], symtab)
	
	if options.align is True: 
		if '.text' in resdic.keys():
			resdic['.text'] = align_text(resdic['.text'])
		if '.rodata' in resdic.keys():
			resdic['.rodata'] = align_data(resdic['.rodata'])
		if '.data' in resdic.keys():
			resdic['.data'] = align_data(resdic['.data'])
		if '.bss' in resdic.keys():
			resdic['.bss'] = align_data(resdic['.bss'])

	
	gen_assemblyfile(resdic, filename)
	gen_compilescript(filename)
	gen_assemblescript(filename)
	
	onlyfilename = filename.split('/')[-1]









	'''
	print "{} : {}",format(key, resdic['.text'][key][1])
	print "{}",format(resdic['.text'][key][2])
	'''
# resdic['.text'] = lfunc_revoc_linking(resdic['.text']) # TODO: 이것도 새로이 만들어진 딕셔너리를 대상으로 링킹을풀어주도록 하기 
# remove_brackets(resdic['.text']) 
# lfunc_symbolize_textsection(resdic)
# lfunc_remove_callweirdaddress(resdic['.text'])
# gen_assemblyfile(resdic, filename)

'''
res = binarycode2dic(filename, SHTABLE)
resdic_data = binarydata2dic(filename)
resdic.update(resdic_data)
gen_assemblyfile(resdic, filename)
'''


# 디스어셈블을 할때 원샷에 끝내버리면 좋은데, 더 어떤정보가 필요할지 아직 모르니까
# 디스어셈블 결과의 딕셔너리에 {address:['','디스어셈블 코드','머신코드 바이트들']} 이랬다면
#                    {address:['','딕셔너리'] 이렇게 바꾸자.
'''
#MACHINECODE = asm('mov eax, DWORD PTR[eax] + 0x12')
MACHINECODE = "\x8d\x4c\x32\x08\x01\xd8\x81\xc6\x34\x12\x00\x00\x05\x23\x01\x00\x00\x36\x8b\x84\x91\x23\x01\x00\x00\x41\x8d\x84\x39\x89\x67\x00\x00\x8d\x87\x89\x67\x00\x00\xb4\xc6\xe9\xea\xbe\xad\xde\xff\xa0\x23\x01\x00\x00\xe8\xdf\xbe\xad\xde\x74\xff"
cs = Cs(CS_ARCH_X86, CS_MODE_32)
cs.detail = True # It producing details costs more memory
cs.syntax = CS_OPT_SYNTAX_ATT # ATT 형식으로 출력되게 해준다

for i in cs.disasm(MACHINECODE, 0x1000):
	if i.modrm != 0:
		print("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
		print "inst ID      : {}".format(i.id)   # instruction ID 
		print "size         : {}".format(i.size) # length of instruction
		print "type         : {}".format(i.type)
		print "operands     : {}".format(i.operands)
		print "prefix       : {}".format(i.prefix)
		print "opcode       : {}".format(i.opcode)
		print "rex          : {}".format(i.rex)
		print "addr_size    : {}".format(i.addr_size)
		print "modrm        : {}".format(i.modrm)
		print "modrm_offset : {}".format(i.modrm_offset)
		print "disp         : {}".format(i.disp)
		print "disp_offset  : {}".format(i.disp_offset)
		print "disp_size    : {}".format(i.disp_size)
		print "sib          : {}".format(i.sib)
		print "instruction  : {}".format(binascii.hexlify(i.bytes)) # real byte of instruction
		print ""
'''

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
import pwn
from etc import *
from keystone import *
from global_variables import *



def extract_OPCODE_and_OPCODEinModRM(hexified_i_byte):
	prefix = ['f3', 'f2', 'f0', '2e', '36', '3e', '26', '64', '65', '66', '67']

	i = 0
	found_opcode = 0

	while i < len(hexified_i_byte)/2:
		_B = hexified_i_byte[i*2:i*2+2]
		if _B in prefix:
			"pass...no prefix allowed..."
		elif found_opcode == 0:
			found_opcode = 1
			OPCODE = _B
		else: # found opcode already!
			ModRM = _B
			break
		i += 1

	ModRM = int('0x'+ModRM, 16)
	ModRM = "{0:b}".format(ModRM)
	ModRM = str(ModRM)

	OPCODE_inside_ModRM_byte = ModRM[2:5]
	return OPCODE, int(OPCODE_inside_ModRM_byte,2)

def BUG_B_HANDLING(OPCODE, OPCODE_inside_ModRM_byte):
	digit = OPCODE_inside_ModRM_byte

	MY_mnemoonic = ''
	if OPCODE == '80':
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'add'
		elif digit == 1: MY_mnemoonic = 'or'
		elif digit == 2: MY_mnemoonic = 'adc'
		elif digit == 3: MY_mnemoonic = 'sbb'
		elif digit == 4: MY_mnemoonic = 'and'
		elif digit == 5: MY_mnemoonic = 'sub'
		elif digit == 6: MY_mnemoonic = 'xor'
		elif digit == 7: MY_mnemoonic = 'cmp'

	elif OPCODE == '81':		
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'and'
		elif digit == 1: MY_mnemoonic = 'or'
		elif digit == 2: MY_mnemoonic = 'adc'
		elif digit == 3: MY_mnemoonic = 'sbb'
		elif digit == 4: MY_mnemoonic = 'and'
		elif digit == 5: MY_mnemoonic = 'sub'
		elif digit == 6: MY_mnemoonic = 'xor'
		elif digit == 7: MY_mnemoonic = 'cmp'

	elif OPCODE == '83':
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'add'
		elif digit == 1: MY_mnemoonic = 'or'
		elif digit == 2: MY_mnemoonic = 'adc'
		elif digit == 3: MY_mnemoonic = 'sbb'
		elif digit == 4: MY_mnemoonic = 'and'
		elif digit == 5: MY_mnemoonic = 'sub'
		elif digit == 6: MY_mnemoonic = 'xor'
		elif digit == 7: MY_mnemoonic = 'cmp'

	elif OPCODE == '71':
		if 0: "Nothing"
		elif digit == 2: MY_mnemoonic = 'PSRLW'
		elif digit == 4: MY_mnemoonic = 'PSRAW'
		elif digit == 6: MY_mnemoonic = 'PSLLW'

	elif OPCODE == '72':
		if 0: "Nothing"
		elif digit == 2: MY_mnemoonic = 'PSRLD'
		elif digit == 4: MY_mnemoonic = 'PSRAD'
		elif digit == 6: MY_mnemoonic = 'PSLLD'

	elif OPCODE == '73':
		if 0: "Nothing"
		elif digit == 2: MY_mnemoonic = 'PSRLQ'
		elif digit == 3: MY_mnemoonic = 'PSRLDQ'
		elif digit == 6: MY_mnemoonic = 'PSLLQ'
		elif digit == 7: MY_mnemoonic = 'PSLLDQ'

	elif OPCODE == 'c0':
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'rol'
		elif digit == 1: MY_mnemoonic = 'ror'
		elif digit == 2: MY_mnemoonic = 'rcl'
		elif digit == 3: MY_mnemoonic = 'rcr'
		elif digit == 4: MY_mnemoonic = 'shl'
		elif digit == 6: MY_mnemoonic = 'shr'
		elif digit == 7: MY_mnemoonic = 'sar'

	elif OPCODE == 'c1':
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'rol'
		elif digit == 1: MY_mnemoonic = 'ror'
		elif digit == 2: MY_mnemoonic = 'rcl'
		elif digit == 3: MY_mnemoonic = 'rcr'
		elif digit == 4: MY_mnemoonic = 'shl'
		elif digit == 6: MY_mnemoonic = 'shr'
		elif digit == 7: MY_mnemoonic = 'sar'

	elif OPCODE == 'ba':
		if 0: "Nothing"
		elif digit == 4: MY_mnemoonic = 'bt'
		elif digit == 5: MY_mnemoonic = 'bts'
		elif digit == 6: MY_mnemoonic = 'btr'
		elif digit == 7: MY_mnemoonic = 'btc'

	elif OPCODE == 'c6':
		if 0: "Nothing"
		elif digit == 0: MY_mnemoonic = 'mov'

	elif OPCODE == 'c7':
		if digit == 0: MY_mnemoonic = 'mov'

	elif OPCODE == 'f6':
		if digit == 0: MY_mnemoonic = 'test'

	elif OPCODE == 'f7':
		if digit == 0: MY_mnemoonic = 'test'

	return MY_mnemoonic



def bugB(i_op_str):
	digit = i_op_str.split(', ')[0] # $0xf0
	digit = digit[1:]               # 0xf0
	digit = int(digit, 16)
	if digit / 0b10000000 == 1:     # 음수라면 
		NEW_op_str = i_op_str.replace("$0x", "$0xffffff")
	else:
		NEW_op_str = i_op_str
	return NEW_op_str




def KEYSTONE_asm(CODE):	
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

def disasm_capstone(_scontents, _sbaseaddr, _ssize):
	print "disasm_capstone"
	cs = Cs(CS_ARCH_X86, CS_MODE_32)
	cs.detail = True   
	cs.syntax = CS_OPT_SYNTAX_ATT # CS_OPT_SYNTAX_NASM, CS_OPT_SYNTAX_INTEL, CS_OPT_SYNTAX_ATT
	dics_of_text = {} 
	_offset = 0
	MY_op_str = ''
	MY_mnemoonic = ''
	DISASSEMBLY_for_reassemble = ''


	_sendaddr = _sbaseaddr + _ssize
	while _sbaseaddr + _offset < _sendaddr: # 베이스어드레스도 바뀌고 오프셋도 바뀜
		_errorcode = 'default' # errorcode init
		
		DISASM = cs.disasm(_scontents, _sbaseaddr)




		for i in DISASM: 
			#[DISP-A] MODR/M BIT HANDLING
			if   i.modrm / 0b11000000:
				_displacement = ''
			elif i.modrm / 0b10000000:
				_displacement = '.d32'
			elif i.modrm / 0b01000000:
				_displacement = '.d8'
			else:
				_displacement = ''
				
			
			#[DISP-B] RELATIVE8/RELATIVE16 HANDLING FOR JMP
			JMP_REL32 = {'0f83':['jae', 'jnb', 'jnc'],'0f82':['jb', 'jc', 'jnae'],'0f81':['jno'],'0f80':['jo'],'0f87':['ja', 'jnbe'],'0f86':['jbe', 'jna'],'0f85':['jne', 'jnz'],'0f84':['je', 'jz'],'0f89':['jns'],'0f88':['js'],'0f8a':['jp', 'jpe'],'0f8c':['jl', 'jnge'],'0f8b':['jnp', 'jpo'],'e9':['jmp'],'0f8f':['jg', 'jnle'],'0f8e':['jle', 'jng'],'0f8d':['jge', 'jnl']}
			
			# TODO: REL8 테이블 만들기 
			JMP_REL8 = {'TODO':'TODO'}
			if i.mnemonic.startswith('j'):
				_OPCODE = ''
				for _O in i.opcode: # OPCODE 를 스트링으로 변환하는 작업
					if _O is 0 : break
					_OPCODE += format(_O, '02x') 
				
				if _OPCODE in JMP_REL32.keys():
					_displacement = '.d32'
				elif _OPCODE in JMP_REL8.keys():
					_displacement = '.d8'
			
			#[DISP-C] SWAP DIRECTIVE(.s) handling		
			'''
			SKIP 함
			- .d32와 .s를 중복해서 못쓴다. 
				* 중요도는 .d32가 큼. 왜냐하면 코드의 length에 직결되기 때문이다
				* 그리고 .s 구현하려면 [??? r/m32 r32] and [??? r32 r/m32] 를 모두 가지는 인스트럭션(ex. mov)를 모두 구해야하는데 파싱해와서 할수있겠지만 귀찮음. 
				* 따라서 .s를 희생하자 
			'''
			
			
			'''
			prefix[0] : 2. String manipulation instruction prefixes(REP(F3), REPE(F3), REPNE(F2)) + LOCK (F0)
			prefix[1] : 3. Segment override prefix (CS(0x2e) SS(0x36) DS(0x3e) ES(0x26) FS(0x64) GS(0x65))
			prefix[2] : 4. Operand override, 66h ( decode immediate operands in 16-bit mode if currently in 32-bit mode, or decode immediate operands in 32-bit mode if currently in 16-bit mode)
			prefix[3] : 5. Address override, 67h (decode addresses in the rest of the instruction in 16-bit mode if currently in 32-bit mode, or decode addresses in 32-bit mode if currently in 16-bit mode)
			'''
			
			#[BUG-A] CAPSTONE 'repz' IGNORING ISSUE HANDLING
			if binascii.hexlify(i.bytes).startswith('f3') or binascii.hexlify(i.bytes).startswith('f2') : # REP/REPE, REPNE
				if not i.mnemonic.startswith('rep'): # BUG!
					_byte = binascii.hexlify(_scontents[_offset:_offset+1])
					if _byte =='f3' : _rep = 'rep'
					else : _rep = 'repne'
					dics_of_text[int(i.address)] =  [
												'', 
												_rep, 
												'#=> ' + 'ADDR:' + str(hex(i.address)) + ' BYTE:' + _byte,
												'',
												''
												]
					_offset = _offset + 1 # 다음인스트럭션의 오프셋은 1 커졌다
					_scontents  = _scontents[_offset:] 
					_sbaseaddr  = _sbaseaddr + _offset 
					_offset = 0 
					_errorcode = 'rep handling'
					break       # restart "cs.disasm"
			
			#[X] NON-ISSUE: Capstone 에서 Opcode inside ModR/M byte를 처리해주지 않는 문제 (https://github.com/aquynh/capstone/issues/1238)
			'''
			if i.mnemonic == 'xorl': 
				#OPCODE, digit = extract_OPCODE_and_OPCODEinModRM(binascii.hexlify(i.bytes))
				#MY_mnemoonic = BUG_B_HANDLING(OPCODE, digit)
				_errorcode = 'default'
			'''

			# [BUG-B] cmp esi, -1 이것을 cmp esi, 0xff 으로 잘못 디스어셈블.. https://github.com/aquynh/capstone/issues/1237
			# 83 /7 ib	CMP r/m32,imm8
			if binascii.hexlify(i.bytes).startswith('83'):
				if i.mnemonic.startswith('cmp'):
					MY_op_str = bugB(i.op_str)
					_errorcode = 'default'


			#[BUG-C] CAPSTONE machinecode'testb %cl, %dl' --> disassembly'testb %dl, %cl' ISSUE HANDLING
			if (i.mnemonic == 'testb') or (i.mnemonic == 'testw'):
				# 두개의 operand 모두 register 일때에만 이런 이슈가 발생함. 
				if binascii.hexlify(i.bytes).startswith('84') or binascii.hexlify(i.bytes).startswith('85'): # 84(TEST r/m8,r8), 85(TEST r/m16,r16)
					DISASSEMBLY_for_reassemble   = i.mnemonic + _displacement + ' ' + i.op_str
					ORIG_ASSEMBLY = str(binascii.hexlify(i.bytes))
					REEE_ASSEMBLY = str(KEYSTONE_asm(DISASSEMBLY_for_reassemble))
					if ORIG_ASSEMBLY != REEE_ASSEMBLY: # testb %cl, %dl 에서와 마찬가지로 레지스터 위치가 swich되어 나온 예
						P = i.op_str.split(', ')
						MY_op_str = P[1] + ', ' + P[0]
				DISASSEMBLY_for_reassemble = '' # init
				_errorcode = 'default'
			
			#[BUG-C] CAPSTONE 0x66, 0x90 TO 'nop' ISSUE HANDLING 
			if binascii.hexlify(i.bytes) == '6690':
				_errorcode = 'goto data' # 데이터처리 부분으로 보내버리기 
				break # restart "cs.disasm"
			
			#[BUG-D] wrong mov suffix when source register is segment register... https://github.com/aquynh/capstone/issues/1240
			if i.mnemonic.startswith('mov'):
				SegmentRegister = ['%cs','%ds','%ss','%es','%gs','%fs']
				Reg = i.op_str.split(', ')[0]
				if Reg in SegmentRegister:
					MY_mnemoonic = 'movw'
					_errorcode = 'default'

			#[BUG-E] Capstone disassembles [ff 15 00 00 00 00] to 	[calll *]... https://github.com/aquynh/capstone/issues/1241
			if i.mnemonic.startswith('call'):
				if i.op_str == '*':
					MY_op_str = '*0x00'
				_errorcode = 'default'

			#[BUG-F] SRC and DEST location changed! on bound instruction... https://github.com/aquynh/capstone/issues/1242 
			# (버그있는)as에게 주기위해서 MY_op_str를 설정해주지만, 위대하신 keystone-capstone 은 올바른 disassembly를 입력받길원하시므로 
			if i.mnemonic.startswith('bound'):
				BOUNDinst = i.op_str.split(', ')
				MY_op_str = BOUNDinst[1] + ', ' + BOUNDinst[0]
				DISASSEMBLY_for_reassemble = i.mnemonic + _displacement + i.op_str
				_errorcode = 'default'


			# [ADDITIONAL FEATURE] undocumented instruction salc handling
			if i.mnemonic == 'salc': 
				_errorcode = 'goto data'
				break
			
			#[DEFAULT-A] NORMAL DISASSEMBLE
			if _errorcode == 'default' :	
				if MY_op_str=='':
					MY_op_str = i.op_str
				else:
					"MY_op_str has already set becaust of [BUG-C]"

				if MY_mnemoonic=='':
					MY_mnemoonic = i.mnemonic
				else:
					"MY_mnemoonic has already set because of [BUG-B]"

				dics_of_text[int(i.address)] =   [
											'', 
											str(' ' + MY_mnemoonic + _displacement + ' ' + MY_op_str), 
											'#=> ' + 'ADDR:' + str(hex(i.address)) + ' BYTE:' + binascii.hexlify(i.bytes),
											'',
											''
											]
				
				_offset = _offset + i.size # 다음 오프셋을 설정 
			
				# TODO: 디스어셈블리와 리어셈블리가 다른경우가 있는지 확인하기 위해 추가함. 나중에 삭제고고
				if DISASSEMBLY_for_reassemble == '':
					DISASSEMBLY_for_reassemble = MY_mnemoonic + _displacement + ' ' + MY_op_str
				else:
					"위의 어디에선가 설정해줬을것이므로 그걸 그대로 써라. "

				ORIG_ASSEMBLY = str(binascii.hexlify(i.bytes))
				RE___ASSEMBLY = str(KEYSTONE_asm(DISASSEMBLY_for_reassemble))
				if (_displacement == '.d32') or (_displacement == '.d8'):
					"DEFFERENT because KEYSTONE can't handle .d32 or .d8 prefix."
				elif i.mnemonic.startswith('j') or i.mnemonic .startswith('call'):
					"DEFFERENT pretty because call/jmp object address is werid"
				elif i.mnemonic.endswith('l'):
					"DEFFERENT because capstone cannot understans 'long' suffix... "
				else:
					if ORIG_ASSEMBLY != RE___ASSEMBLY:
						print "-----[LOG] DIFFERENT BETWEEN BINARY AND RE-ASSEMBLY-----"
						print "* DISASM   : " + DISASSEMBLY_for_reassemble
						print "* ORIG     : " + ORIG_ASSEMBLY
						print "* KEYSTONE : " + RE___ASSEMBLY
						print "-------------------------------------------------------"
				DISASSEMBLY_for_reassemble = '' # init
				MY_op_str = ''   # init
				MY_mnemoonic = '' # init

				# print "============================================="
				# print "mnemonic     : {}".format(i.mnemonic)   
				# print "op_str       : {}".format(i.op_str)   
				# print 
				# print "groups       : {}".format(i.groups)    
				# print "regs_read    : {}".format(i.regs_read)   
				# print "regs_write   : {}".format(i.regs_write)
				# print 
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
				
				
				
		#[DEFAULT-B] EXCAPTION: DATA INTERLEAVED INSIDE CODE SECTION ... Suddenly fallen into Undergroud world, Mt.Avot (DATA HANDLING PART)
		if _errorcode == 'default' or _errorcode == 'goto data':
			if _sbaseaddr + _offset < _sendaddr : # 현재지점이 end address 지점을 넘어가부리면 안댐
				_saddress = _sbaseaddr + _offset
				dics_of_text[_saddress] = 	[
											'', 
											' .byte 0x' + binascii.hexlify(_scontents[_offset:_offset+1]), 
											'#=> ' + 'ADDR:' + str(hex(_saddress)) + ' BYTE:' + binascii.hexlify(_scontents[_offset:_offset+1]),
											'',
											''
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
	
	data_section = DataSections_IN_resdic
	data_section.remove('.bss') # bss섹션은 zero fill on demend 로 채워줄 것이기 때문임

	for SECTIONNAME in data_section:
		if bin.get_section_by_name(SECTIONNAME) != None: # 섹션이 있는지 검사

			s_start = bin.get_section_by_name(SECTIONNAME).header.sh_addr
			s_offset = bin.get_section_by_name(SECTIONNAME).header.sh_offset
			s_size = bin.get_section_by_name(SECTIONNAME).header.sh_size
			s_contents = binfile[s_offset:s_offset+s_size]
			datadic = {} # initialize
			for j in xrange(s_size):
				addr   = s_start + j
				offset = s_offset + j
				_byte  = binascii.b2a_hex(binfile[offset])
				datadic[addr] = [
								'', 
								" .byte 0x" + _byte, 
								'#=> ' + 'ADDR:' + str(hex(addr)) + ' BYTE:' +_byte, 
								'',
								''
								]
			retdic[SECTIONNAME] = datadic

	# zero-fill-on-demand
	zeroinit_section = ['.bss']
	s_start = bin.get_section_by_name('.bss').header.sh_addr
	s_offset = bin.get_section_by_name('.bss').header.sh_offset
	s_size = bin.get_section_by_name('.bss').header.sh_size
	datadic = {} # initialize 0x00 from sh_addr to sh_addr+sh_size
	for j in xrange(s_size):
		addr = s_start + j
		datadic[addr] = [
						'', 
						" .byte 0x00",
						'#=> ' + 'ADDR:' + str(hex(addr)) + ' BYTE:' + '00', 
						'',
						''
						]
	retdic['.bss'] = datadic
	
	return retdic

# capstone 버전
def binarycode2dic(filename, SHTABLE): 
	f = open(filename, 'rb')
	fread = f.read()
	
	SectionName = CodeSections_IN_resdic
	resdic = {}
	
	for _sname in SectionName:
		if _sname in SHTABLE.keys():
			_soffset   = SHTABLE[_sname]['sh_offset']
			_ssize     = SHTABLE[_sname]['sh_size']
			_scontents = fread[_soffset:_soffset+_ssize]
			_sbaseaddr  = SHTABLE[_sname]['sh_addr']
			
			resdic[_sname] = disasm_capstone(_scontents, _sbaseaddr, _ssize) 
		else:
			"no.."
	resdic['.dummy'] = {} # dummy section for PIE
	return resdic

# TODO: bss 뿐만이 아니라 .text, .fini, .init, emdemddp 등등에 대한 심볼들도 만들어주기 
def get_dynsymtab(filename): # 이게 제대로 동작을 안함? 아니 하는데.... 그니까 suppressint 참조코드가 잘 생기지... 
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
			if 'g' in l[1]: # global symbol 만 취급합니더,,,ㅋㅋ
				'''	
				if l[3] == '.bss': # ['08051198' : 'g', 'DO', '.bss', '00000004', 'GLIBC_2.0', 'stdout'] 이런형식
					symtab[int('0x'+l[0], 16)] = l[6]
				'''	
				if l[3] not in symtab.keys(): symtab[l[3]] = {} # init

				symtab[l[3]][int('0x'+l[0], 16)] = l[6]


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
	LN_start = 0
	LN_end   = 0
	cmd = 'readelf -a ' + filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	for i in xrange(len(lines)):
		if 'Relocation section \'.rel.dyn\'' in lines[i]:
			LN_start = i + 2 # line 0 (Relocation section '.rel.dyn' 어쩌구..), line 1 (Offset Info Type 어쩌구..) 제외
			for j in xrange(LN_start, len(lines)):
				if len(lines[j]) is 0: # '.rel.dyn' 이 끝나면
					LN_end = j
					break
			break
	lines = lines[LN_start:LN_end]
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
	LN_start = 0
	LN_end   = 0
	
	cmd = 'readelf -a ' + filename
	res = subprocess.check_output(cmd, shell=True)
	lines = res.splitlines() 
	for i in xrange(len(lines)):
		if 'Relocation section \'.rel.plt\'' in lines[i]:
			LN_start = i + 2 # line 0 (Relocation section '.rel.dyn' 어쩌구..), line 1 (Offset Info Type 어쩌구..) 제외
			for j in xrange(LN_start, len(lines)):
				if len(lines[j]) is 0: # '.rel.dyn' 이 끝나면
					LN_end = j
					break
			break
	lines = lines[LN_start:LN_end] 
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




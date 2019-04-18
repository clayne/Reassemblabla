#!/usr/bin/python
#-*- coding: utf-8 -*-
from capstone import *
import binascii 
from keystone import * 
from elftools.elf.relocation import RelocationSection
from elftools.elf.sections import SymbolTableSection

from etc import * 



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
		ks = Ks(KS_ARCH_X86, KS_MODE_32) 	# Initialize engine in X86-32bit mode
		ks.syntax = KS_OPT_SYNTAX_ATT 		# ATT신텍스
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
			JMP_REL8 = {'TODO':'TODO'} # TODO: REL8 테이블 만들기
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
			SKIP. 그 이유는
			- .d32와 .s를 중복해서 못쓴다. 
				* 중요도는 .d32가 큼. 왜냐하면 코드의 length에 직결되기 때문이다
				* 그리고 .s 구현하려면 [??? r/m32 r32] and [??? r32 r/m32] 를 모두 가지는 인스트럭션(ex. mov)를 모두 구해야하는데 파싱해와서 할수있겠지만 귀찮음. 
				* 따라서 .s를 희생하자 
				* TODO: 문제발생시 언젠가 핸들링 추가하기.
			'''
			
			'''
			prefix[0] : 2. String manipulation instruction prefixes(REP(F3), REPE(F3), REPNE(F2)) + LOCK (F0)
			prefix[1] : 3. Segment override prefix (CS(0x2e) SS(0x36) DS(0x3e) ES(0x26) FS(0x64) GS(0x65))
			prefix[2] : 4. Operand override, 66h ( decode immediate operands in 16-bit mode if currently in 32-bit mode, or decode immediate operands in 32-bit mode if currently in 16-bit mode)
			prefix[3] : 5. Address override, 67h (decode addresses in the rest of the instruction in 16-bit mode if currently in 32-bit mode, or decode addresses in 32-bit mode if currently in 16-bit mode)
			'''
			
			#[BUG-A] 캡스톤에서 'repz' 프리픽스를 무시한 채로 디스어셈블하는 이슈. 캡스톤측에서는 이슈 아니라고 주장하지만, 리어셈블시 바이트패턴이 바뀔 수 있음. 
			if binascii.hexlify(i.bytes).startswith('f3') or binascii.hexlify(i.bytes).startswith('f2') : # REP/REPE, REPNE
				if not i.mnemonic.startswith('rep'): # BUG!
					_byte = binascii.hexlify(_scontents[_offset:_offset+1])
					if _byte =='f3' : _rep = 'rep'
					else : _rep = 'repne'
					dics_of_text[int(i.address)] =  [
												'', 
												[_rep], 
												'                              #=> ' + 'ADDR:' + str(hex(i.address)) + ' BYTE:' + _byte,
												'',
												''
												]
					_offset = _offset + 1 # 다음인스트럭션의 오프셋은 1 커졌다
					_scontents  = _scontents[_offset:] 
					_sbaseaddr  = _sbaseaddr + _offset 
					_offset = 0 
					_errorcode = 'rep handling'
					break       # restart "cs.disasm"

			# [BUG-B] cmp esi, -1 이것을 cmp esi, 0xff 으로 잘못 디스어셈블함 (https://github.com/aquynh/capstone/issues/1237)
			if binascii.hexlify(i.bytes).startswith('83'):
				if i.mnemonic.startswith('cmp'):
					MY_op_str = bugB(i.op_str)
					_errorcode = 'default'


			#[BUG-C] 캡스톤에서 'testb %cl, %dl'을 'testb %dl, %cl'으로 디스어셈블하는 이슈.
			if (i.mnemonic == 'testb') or (i.mnemonic == 'testw'):
				if binascii.hexlify(i.bytes).startswith('84') or binascii.hexlify(i.bytes).startswith('85'): # # 두개의 operand 모두 register 일때에만 이런 이슈가 발생함. .ex) 84(TEST r/m8,r8), 85(TEST r/m16,r16)
					DISASSEMBLY_for_reassemble   = i.mnemonic + _displacement + ' ' + i.op_str
					ORIG_ASSEMBLY = str(binascii.hexlify(i.bytes))
					REEE_ASSEMBLY = str(KEYSTONE_asm(DISASSEMBLY_for_reassemble))
					if ORIG_ASSEMBLY != REEE_ASSEMBLY: # testb %cl, %dl 에서와 마찬가지로 레지스터 위치가 swich되어 나온 예
						P = i.op_str.split(', ')
						MY_op_str = P[1] + ', ' + P[0]
				DISASSEMBLY_for_reassemble = '' # init
				_errorcode = 'default'
			

			#[BUG-D] 캡스톤에서 0x66, 0x90 (2-byte nop)을 'nop'으로 디스어셈블하는 이슈.
			if binascii.hexlify(i.bytes) == '6690':
				_errorcode = 'goto data' # 데이터처리 부분으로 보내버리기 
				break # restart "cs.disasm"
			

			#[BUG-E] wrong mov suffix when source register is segment register... https://github.com/aquynh/capstone/issues/1240
			if i.mnemonic.startswith('mov'):
				SegmentRegister = ['%cs','%ds','%ss','%es','%gs','%fs']
				Reg = i.op_str.split(', ')[0]
				if Reg in SegmentRegister:
					MY_mnemoonic = 'movw'
					_errorcode = 'default'


			#[BUG-F] Capstone disassembles [ff 15 00 00 00 00] to 	[calll *]... https://github.com/aquynh/capstone/issues/1241
			if i.mnemonic.startswith('call'):
				if i.op_str == '*':
					MY_op_str = '*0x00'
				_errorcode = 'default'


			#[BUG-G] bound 인스트럭션에서 SRC 와 DEST 가 바뀐다. https://github.com/aquynh/capstone/issues/1242 
			#        이건 캡스톤 버그가 아니라 ATT 디자인 버그였음! https://stackoverflow.com/questions/52158999/is-this-assembler-bug-bound-instruction
			if i.mnemonic.startswith('bound'):
				BOUNDinst = i.op_str.split(', ')
				MY_op_str = BOUNDinst[1] + ', ' + BOUNDinst[0]
				DISASSEMBLY_for_reassemble = i.mnemonic + _displacement + i.op_str
				_errorcode = 'default'

			# TODO: 추후에 다시 올바르게 디자인해준 후 활성화할 것. 
			# (이거 왜 비활성화해줬냐면..멀쩡한 7바이트 인스트럭션인 lea 0x804fd20(,%eax,4),%ebx 이것도 바이트패턴으로 디스어셈블해서 심볼화해야할 0x804fd20 심볼화를 못하게 됨...) 
			'''
			# [BUG-EVICTED FROM BUG LIST] lea 0x0(%edi,%eiz,1),%edi 의 7 byte nop을  lea  0x0(%edi),%edi 으로 디스어셈블함 ㅠ 
			if i.mnemonic.startswith('lea') and  i.size is 7:
				MY_bytes = binascii.hexlify(i.bytes)
				for k in xrange(len(binascii.hexlify(i.bytes))):
					j = len(binascii.hexlify(i.bytes)) -1 - k
					if j % 2 is 0 : # 짝수인덱스는 곧 홀수번째 요소를 의미하므로. 홀수번째 요소 앞에 ', 0x'가 들어가야함. 
						MY_bytes = MY_bytes[:j] + ', 0x' + MY_bytes[j:]
				MY_bytes = MY_bytes[2:] # 처음의 ', '를 빼준다

				# MY_mnemoonic, _displacement, MY_op_str 를 모두 새값으로 설정해주자.
				MY_mnemoonic = '.byte'
				_displacement = ''
				MY_op_str = MY_bytes

				_errorcode = 'default' # 8dbc2700000000
			'''

			# [BUG-F] undocumented instruction salc handling
			if i.mnemonic == 'salc': 
				_errorcode = 'goto data'
				break

			#[DEFAULT-A] NORMAL DISASSEMBLE
			if _errorcode == 'default' :	
				if MY_op_str=='':
					MY_op_str = i.op_str
				if MY_mnemoonic=='':
					MY_mnemoonic = i.mnemonic

				dics_of_text[int(i.address)] =   [
											'', 
											[str(' ' + MY_mnemoonic + _displacement + ' ' + MY_op_str)], 
											'                              #=> ' + 'ADDR:' + str(hex(i.address)) + ' BYTE:' + binascii.hexlify(i.bytes),
											'',
											''
											]
				
				_offset = _offset + i.size # 다음 오프셋을 설정 
			
				if DISASSEMBLY_for_reassemble == '':
					DISASSEMBLY_for_reassemble = MY_mnemoonic + _displacement + ' ' + MY_op_str
				else:
					'위의 어디에선가 설정해줬을것이므로 그걸 그대로 써라.'

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
						'This function is Temroparlly disabled'
						'''
						print "-----[LOG] DIFFERENT BETWEEN BINARY AND RE-ASSEMBLY-----"
						print "* DISASM   : " + DISASSEMBLY_for_reassemble
						print "* ORIG     : " + ORIG_ASSEMBLY
						print "* KEYSTONE : " + RE___ASSEMBLY
						print "--------------------------------------------------------"
						'''
				DISASSEMBLY_for_reassemble = '' # init
				MY_op_str = ''   				# init
				MY_mnemoonic = '' 				# init
				
				 
		#[DEFAULT-B] 코드섹션 안에 있는 데이터의 경우 바이트로 때려박아버린다.
		if _errorcode == 'default' or _errorcode == 'goto data':
			if _sbaseaddr + _offset < _sendaddr : # 현재지점이 end address 지점을 넘어가버리는 경우 중단
				_saddress = _sbaseaddr + _offset
				dics_of_text[_saddress] = 	[
											'', 
											[' .byte 0x' + binascii.hexlify(_scontents[_offset:_offset+1])], 
											'                              #=> ' + 'ADDR:' + str(hex(_saddress)) + ' BYTE:' + binascii.hexlify(_scontents[_offset:_offset+1]),
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
	dics_of_data = {}
	resdic = {}
	
	bin = ELFFile(open(filename,'rb'))
	f = open(filename,'r')
	binfile = f.read()
	
	for SectionName in DataSections_WRITE:
		if SectionName == '.bss': # bss 는 초기화되면서 0으로 채워질것이기 때문에 데이터를 굳이 때려박지 않아도 됨.
			continue
		if bin.get_section_by_name(SectionName) != None: # 섹션이 있는지 검사

			s_start = bin.get_section_by_name(SectionName).header.sh_addr
			s_offset = bin.get_section_by_name(SectionName).header.sh_offset
			s_size = bin.get_section_by_name(SectionName).header.sh_size
			s_contents = binfile[s_offset:s_offset+s_size]
			dics_of_data = {} # initialize
			for j in xrange(s_size):
				addr   = s_start + j
				offset = s_offset + j
				_byte  = binascii.b2a_hex(binfile[offset])
				dics_of_data[addr] = [
								'', 
								[' .byte 0x' + _byte], 
								'                              #=> ' + 'ADDR:' + str(hex(addr)) + ' BYTE:' +_byte, 
								'',
								''
								]
			resdic[SectionName] = dics_of_data

	# zero-fill-on-demand 섹션의 경우 0의 갯수로 size를 지정한다. 
	s_start  = bin.get_section_by_name('.bss').header.sh_addr
	s_offset = bin.get_section_by_name('.bss').header.sh_offset
	s_size   = bin.get_section_by_name('.bss').header.sh_size
	dics_of_data = {}
	for j in xrange(s_size):
		addr = s_start + j
		dics_of_data[addr] = [
						'', 
						[' .byte 0x00'],
						'                              #=> ' + 'ADDR:' + str(hex(addr)) + ' BYTE:' + '00', 
						'',
						''
						]
	resdic['.bss'] = dics_of_data
	
	return resdic

def binarycode2dic(filename, SHTABLE): 
	f = open(filename, 'rb')
	fread = f.read()
	
	SectionName = CodeSections_WRITE
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
	return resdic



def get_SYM_LIST(filename): # BiOASAN compatibility feature : Named symbol 의 주소 파싱 후 리스트로 리턴
	bin = ELFFile(open(filename,'rb')) 
	SYM_LIST = []
	for section in bin.iter_sections():
		if not isinstance(section, SymbolTableSection):
			continue
		else:
			if section.name == '.symtab': 
				for symbol in section.iter_symbols():
					if symbol.name != '': # 실존하시는 심볼이라면
						if symbol.entry.st_value not in SYM_LIST:
							SYM_LIST.append(symbol.entry.st_value)
	return SYM_LIST



def get_DYNSYM_LIST(filename):
	DYNSYM_LIST = {}

	bin = ELFFile(open(filename,'rb')) 
	for section in bin.iter_sections():
		if not isinstance(section, SymbolTableSection):
			continue
		else:
			if section.name == '.dynsym':
				for symbol in section.iter_symbols():
					if symbol.name != '':		
						if symbol.entry.st_info['type'] == 'STT_FUNC':
							DYNSYM_LIST[str(symbol.name)] = 'STT_FUNC'
						elif symbol.entry.st_info['type'] == 'STT_OBJECT':
							DYNSYM_LIST[str(symbol.name)] = 'STT_OBJECT'
						elif symbol.entry.st_info['type'] == 'STT_NOTYPE':
							DYNSYM_LIST[str(symbol.name)] = 'STT_NOTYPE'
						# 이외에도 STT_NOTYPE, STT_OBJECT, STT_FUNC, STT_SECTION, STT_FILE, STT_COMMON, STT_LOOS, STT_HIOS, STT_LOPROC, STT_HIPROC 등 많음. 나중에 확장할때 참고. 
	return DYNSYM_LIST

def get_relocation_tables(filename):
	DYNSYM_LIST = get_DYNSYM_LIST(filename)
	#RELOSYM_LIST = {'R_386_32':{}, 'R_386_COPY':{}, 'R_386_GLOB_DAT':{}, 'R_386_JUMP_SLOT':{}} # TODO: R_386_32 는 어떻게 처리해줘야 함? 예를들어 /bin/dash 에는 이 타입의 심볼이있어서 추가는해줬는데, 이거에대한 핸들링루틴이 없음.  
	RELOSYM_LIST = {'R_386_32':{}, 'R_386_PC32':{}, 'R_386_GOT32':{}, 'R_386_PLT32':{}, 'R_386_COPY':{}, 'R_386_GLOB_DAT':{}, 'R_386_JUMP_SLOT':{}} # TODO: R_386_32 는 어떻게 처리해줘야 함? 예를들어 /bin/dash 에는 이 타입의 심볼이있어서 추가는해줬는데, 이거에대한 핸들링루틴이 없음.  
	
	RET = {'STT_FUNC':{}, 'STT_OBJECT':{}, 'STT_NOTYPE':{}}
	#TYPES = {1:'R_386_32', 5:'R_386_COPY', 6:'R_386_GLOB_DAT', 7:'R_386_JUMP_SLOT'}
	TYPES = {1:'R_386_32', 2:'R_386_PC32', 3:'R_386_GOT32', 4:'R_386_PLT32', 5:'R_386_COPY', 6:'R_386_GLOB_DAT', 7:'R_386_JUMP_SLOT'}

	bin = ELFFile(open(filename,'rb'))
	for section in bin.iter_sections():

		if not isinstance(section, RelocationSection):
			continue
		else: # RelocationSection 섹션 중에서 section['sh_link'] 섹션을 꺼내옴. 
			symtable = bin.get_section(section['sh_link']) # symtable = '.dynsym' 섹션임. sh_link 정보를가지고 어떤 섹션에 접근을 하는구나. 
			print symtable.name

			for rel in section.iter_relocations():
				_type = rel['r_info_type'] 
				symbol = symtable.get_symbol(rel['r_info_sym'])
				
				if symbol.name != '': 
					print 'type : {}, symbol name : {}'.format(_type, symbol.name) 
					RELOSYM_LIST[TYPES[_type]][rel['r_offset']] = symbol.name

	'''
	현재까지 RELOSYM_LIST 상태는 다음과 같다. 
	R_386_COPY : {}
	R_386_GLOB_DAT : {134518400 : __gmon_start__}
	R_386_32 : {}
	R_386_JUMP_SLOT : {134518416 : printf, 134518420 : __libc_start_main}
	'''

	for R_TYPE in RELOSYM_LIST.keys():
		for symaddr in RELOSYM_LIST[R_TYPE].keys():
			symname = RELOSYM_LIST[R_TYPE][symaddr]
			if symname in DYNSYM_LIST.keys(): 
				if DYNSYM_LIST[symname] is 'STT_FUNC':  		# 심볼이름이 STT_FUNC 속성에 속한다면
					RET['STT_FUNC'].update({symaddr:symname})
				elif DYNSYM_LIST[symname] is 'STT_OBJECT': 		# 심볼이름이 STT_OBJECT 속성에 속한다면 
					RET['STT_OBJECT'].update({symaddr:symname})
				elif DYNSYM_LIST[symname] is 'STT_NOTYPE': # ex) _Jv_RegisterClasses 같은것들. 이 타입의 객체는 심볼라이즈해주면 컴파일에러남. (컴파일러가 자동으로 추가해주므로, 사전에 있을시에 문제되는것들)
					RET['STT_NOTYPE'].update({symaddr:symname})

	return RET 


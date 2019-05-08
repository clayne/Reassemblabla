#!/usr/bin/python
#-*- coding: utf-8 -*-
from etc import *
from vsa import *



def dynamic_symbol_labeling(resdic, addr2name):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if addr in addr2name.keys():
				symbolname = addr2name[addr]
				if resdic[SectionName][addr][0] == '': # 심볼이 없다면, 심볼이름을 붙여준다. 심볼이 이미 있다면, 이전에 설정된 심볼을 우선적으로 선택하므로 심볼라이즈 ㄴㄴ. 
					resdic[SectionName][addr][0] = symbolname + ':'

def not_global_symbolize_ExternalLinkedSymbol(resdic):
	for SectionName in resdic.keys():
		for addr in resdic[SectionName].keys():
			if resdic[SectionName][addr][0] != '': # 심볼이 붙어있는데
				if resdic[SectionName][addr][0].startswith(SYMPREFIX[0] + 'MYSYM_') == True:
					'This is my symbol. :) PASS.'
				else:
					symbolname = resdic[SectionName][addr][0][:-1]
					if '@' in symbolname:
						symbolname = symbolname[:symbolname.index('@')] # stderr@GOT(%ebx) 의 @뒤에 떼준다
						symbolname = SYMPREFIX[0] + 'MYSYM_SPOILED_' + SectionName[1:] + '_' + symbolname 
						resdic[SectionName][addr][0] = symbolname + ':'
					elif 'MYSYM' not in symbolname:
						flag_namedsymbol = 0
						for permitted_name in MyNamedSymbol:
							if symbolname.startswith(permitted_name): # __x86.get_pc_thunk.si, __x86.get_pc_thunk.di, ...
								flag_namedsymbol = 1
								'Good. You Servived.' 
						if flag_namedsymbol is 0: # You are not permitted symbol name. ex)printf
							symbolname = SYMPREFIX[0] + 'MYSYM_SPOILED_' + SectionName[1:] + '_' + symbolname
							resdic[SectionName][addr][0] = symbolname + ':'
	return resdic		

def getpcthunk_labeling(resdic):
	pcthunk_reglist = [] # 필요할지도 모르니까, getpcthunk의 결과가 들어가는 레지스터들의 리스트들도 따로 저장해둠.
	code_sections = CodeSections_WRITE
	count = 0
	for sectionName in code_sections:
		if sectionName in resdic.keys():
			SectionDict = resdic[sectionName]
			SORTKEY = SectionDict.keys()
			SORTKEY.sort()
			for i in xrange(len(SORTKEY) - 1):
				j = 0
				while j < len(SectionDict[SORTKEY[i]][1]):
					DISASM_1 = SectionDict[SORTKEY[i]][1][j][1:]
					k = 0
					while k < len(SectionDict[SORTKEY[i+1]][1]):
						DISASM_2 = SectionDict[SORTKEY[i+1]][1][k][1:]
						if ' ' in DISASM_1 and DISASM_2.startswith('ret'): # leave, ret 같은건 취급안함
							OPCODE_1 = DISASM_1[:DISASM_1.index(' ')]
							OPRAND_1 = DISASM_1[DISASM_1.index(' ')+1:]
							if OPCODE_1.startswith('mov'): 
								if OPRAND_1.startswith('(%esp), %e') or OPRAND_1.startswith('0(%esp), %e'): # 첫번째 관문 통과 
									if '0(%esp), %e' in OPRAND_1:
										REGX = OPRAND_1[len('0(%esp), %e'):]
									elif '(%esp), %e' in OPRAND_1:
										REGX = OPRAND_1[len('(%esp), %e'):]
									SectionDict[SORTKEY[i]][0] = '__x86.get_pc_thunk.' + str(count) + '.' + REGX + ':' # symbolization
									count += 1
									pcthunk_reglist.append('e' + REGX)
						k += 1
					j += 1
	return 	list(set(pcthunk_reglist)) # 중복 제거

def symbolize_textsection(resdic, testingcrashhandler):
	symbolcount = 0	
	symbolize_count = 0

	for section_from in CodeSections_WRITE:
		for section_to in AllSections_WRITE:
			if section_from in resdic.keys() and section_to in resdic.keys():
				print '     {} -----> {}'.format(section_from, section_to)
				for ADDR in resdic[section_from].keys(): 
					orig_i_list = pickpick_idx_of_orig_disasm(resdic[section_from][ADDR][1])
					for orig_i in orig_i_list:
						DISASM = resdic[section_from][ADDR][1][orig_i]
						if testingcrashhandler is True:
							destinations = VSA_and_extract_addr(DISASM) 
						else:
							destinations = extract_hex_addr(DISASM)
						for DEST in destinations: 
							if DEST in resdic[section_to].keys(): 
								symbolize_count += 1
								# 심볼이름셋팅
								if resdic[section_to][DEST][0] != "": # if symbol already exist
									simbolname = resdic[section_to][DEST][0][:-1] # MYSYM1: --> MYSYM1
								else: # else, create my symbol name 
									simbolname = SYMPREFIX[0] + "MYSYM_" + str(symbolcount)
									symbolcount = symbolcount + 1
									resdic[section_to][DEST][0] = simbolname + ":"
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST),simbolname)     # 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST)[2:],simbolname) # 그게아니라 12 이렇게생겼을경우 12 --> MYSYM_1 치환 (그럴리는없겠지만..)
	symbolize_counter('Symbolize (textsection) : {}'.format(symbolize_count))
	return resdic

def symbolize_datasection(resdic): # datasection --> datasection 을 symbolize. 
	'''
	먼저, datasection 이 datasection 을 포인팅하는 값이 있는지 1바이트씩 슬라이딩 윈도우로 조사한다.
	있다면, 그 .byte 01 .byte 04 .byte 20 .byte 80  자리에 .byte 심볼이름 을 씀. 
    4byte align 맞춰가면서 symbolize 하기
    '''
	_from = DataSections_WRITE     
	_to   = AllSections_WRITE
	symcnt = 0
	symbolize_count = 0
	for section_from in _from:
		if _from == '.bss':# bss에는 아무것도 안들어있자나..
			continue
		for section_to in _to:
			if section_from in resdic.keys() and section_to in resdic.keys(): 
				i = 0
				sorted_keylist = sorted(resdic[section_from]) # key list sort
				while i <= len(sorted_keylist) - 4: # len-4, len-3, len-2, len-1
					key = sorted_keylist[i]
					if resdic[section_from][sorted_keylist[i+0]][1][0].startswith(' .byte'):
						if resdic[section_from][sorted_keylist[i+1]][1][0].startswith(' .byte'):
							if resdic[section_from][sorted_keylist[i+2]][1][0].startswith(' .byte'):
								if resdic[section_from][sorted_keylist[i+3]][1][0].startswith(' .byte'):
									candidate  = ""
									candidate += resdic[section_from][sorted_keylist[i+3]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+2]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+1]][1][0]
									candidate += resdic[section_from][sorted_keylist[i+0]][1][0]
									candidate = candidate.replace(' .byte 0x','')
									candidate = "0x"+candidate
									if int(candidate,16) in resdic[section_to].keys(): # to 의 대상이되는 섹션
										symbolize_count += 1
										symbolname = resdic[section_to][int(candidate,16)][0]
										if symbolname == '': 
											symbolname = SYMPREFIX[0] + "MYSYM_DATA_"+str(symcnt)+":"
										resdic[section_from].pop(sorted_keylist[i+3])
										resdic[section_from].pop(sorted_keylist[i+2])
										resdic[section_from].pop(sorted_keylist[i+1])
										resdic[section_from][    sorted_keylist[i+0]][1][0] = " .long " + symbolname[:-1] # ':' 떼기위해-1, not delete, just modify data format(.byte->.long)
										resdic[section_from][    sorted_keylist[i+0]][2] = '                              #=> ' + 'ADDR:' + str(hex(sorted_keylist[i+0])) + ' BYTE:' + candidate[2:] 
										resdic[section_to][int(candidate,16)][0]= symbolname # symbolize that loc
										i = i + 4 # because entry of dict poped
										symcnt = symcnt + 1
										continue
								else: i = i + 1 # .byte blabla .byte blabla .byte blabla .long blabla  일 경우, .long blabla 까지 쓰루하기
							else: i = i + 1 
						else: i = i + 1 
					else:
						"do nothing"
					i = i + 1 
	symbolize_counter('Symbolize (datasection) : {}'.format(symbolize_count))
	return resdic


# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면 je XXX 로 바꾼다. (오직 컴파일 에러를 막기 위한 땜빵기능임...) TODO: Crash based lazy symbolization 이 도입되면 이거 없애야 함
def lfunc_change_callweirdaddress_2_callXXX(dics_of_text): 
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call'] # ,'loop','loope','loopne' 는 loop XXX 라고해봤자 에러메시지 뿜어댐. 왠지 모르겠다. 그러니까 이거 세개는 제외시키자. lfunc_change_loop_call_jmp_and_hexvalue_instruction_to_data가 알아서 처리해줄거임
	
	for i in xrange(len(dics_of_text)):
		ADDR = dics_of_text.keys()[i]
		orig_i_list = pickpick_idx_of_orig_disasm(dics_of_text[ADDR][1])
		for orig_i in orig_i_list:
			elements = dics_of_text[ADDR][1][orig_i].split(' ')
			yes_it_is_branch_instruction = 0
			if len(elements) >= 3:
				if elements[2].startswith('0x'):
					elements[2] = elements[2][2:]
				if ishex(elements[2]): 			   			# jmp 12f2 <--here
					for b in branch_inst:
						if b in elements[1]: yes_it_is_branch_instruction = 1
					if yes_it_is_branch_instruction == 1: 	# here --> jmp 12f2
						elements[2] = 'XXX'
						line = '' # 다시 재조립
						for i in xrange(len(elements)):
							line = line + elements[i] + ' '
						dics_of_text[ADDR][1][orig_i] = line 



# lfunc_remove_callweirdaddress 보다 더 진보된 방법이다..
# je 2a0c 처럼 이상한곳으로 점프하는 (심볼리제이션이 안된 곳) 인스트럭션이 있다면, 데이터로 때려박음. (오직 컴파일 에러를 막기 위한 땜빵기능임...) TODO: Crash based lazy symbolization 이 도입되면 이거 없애야 함
def lfunc_change_callweirdaddress_2_data(dics_of_text):  
	branch_inst = ['jmp','je','jne','jg','jge','ja','jae','jl','jle','jb','jbe','jo','jno','jz','jnz','js','jns','call','loop','loope','loopne']
	
	for i in xrange(len(dics_of_text)):
		ADDR = dics_of_text.keys()[i]
		orig_i_list = pickpick_idx_of_orig_disasm(dics_of_text[ADDR][1])
		for orig_i in orig_i_list:
			elements = dics_of_text[ADDR][1][orig_i].split(' ')
			yes_it_is_branch_instruction = 0
			if len(elements) >= 3:
				if '0x' in elements[2]:
					elements[2] = elements[2].replace('0x','')
					elements[2] = elements[2].replace('*', '')
					elements[2] = elements[2].replace('$', '') 
				if ishex(elements[2]): 			          # jmp 12f2 <--here
					for INSTR in branch_inst:
						if INSTR in elements[1]:
							yes_it_is_branch_instruction = 1
					if yes_it_is_branch_instruction == 1: # here --> jmp 12f2
						bytepattern = dics_of_text[ADDR][2].split('BYTE:')[1]
						line_data = ' .byte '
						for j in xrange(len(bytepattern)/2):
							line_data += '0x' + bytepattern[j*2:j*2+2] + ', '
						line_data = line_data[:-2]
						dics_of_text[ADDR][1][orig_i] = line_data










def symbolize_textsection_pic(resdic):
	symbolcount = 0	
	symbolize_count = 0

	for section_from in CodeSections_WRITE:
		for section_to in AllSections_WRITE:
			if section_from in resdic.keys() and section_to in resdic.keys():
				print '     {} -----> {}'.format(section_from, section_to)
				for ADDR in resdic[section_from].keys(): 
					orig_i_list = pickpick_idx_of_orig_disasm(resdic[section_from][ADDR][1])
					for orig_i in orig_i_list:
						DISASM = resdic[section_from][ADDR][1][orig_i]
						instObj = InstParser(DISASM)	
					
						if not instObj.is_jmp_inst() and 'call' not in instObj.op:
							continue

						#print(DISASM)

						destinations = extract_hex_addr(DISASM)



						for DEST in destinations: 
							if DEST in resdic[section_to].keys(): 
								symbolize_count += 1
								# 심볼이름셋팅
								if resdic[section_to][DEST][0] != "": # if symbol already exist
									simbolname = resdic[section_to][DEST][0][:-1] # MYSYM1: --> MYSYM1
								else: # else, create my symbol name 
									simbolname = SYMPREFIX[0] + "MYSYM_" + str(symbolcount)
									symbolcount = symbolcount + 1
									resdic[section_to][DEST][0] = simbolname + ":"
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST),simbolname)     # 만약에 0x8048540 이렇게생겼을경우 0x8048540 --> MYSYM_1 치환
								resdic[section_from][ADDR][1][orig_i] = resdic[section_from][ADDR][1][orig_i].replace(hex(DEST)[2:],simbolname) # 그게아니라 12 이렇게생겼을경우 12 --> MYSYM_1 치환 (그럴리는없겠지만..)
								#print('symbolize!!')
	symbolize_counter('Symbolize (textsection) : {}'.format(symbolize_count))
	return resdic

def get_cfg_node_label(lineObj, addr):
	#label_set = set()
	#cfg_queue = list()

	addr, label_set = get_prev_inst(lineObj, addr)
	'''
	if len(label) > 0:
		label_set = set([label])
	else:
		label_set = set()
	'''
	cfg_queue = list()
	for label in label_set:
		cfg_queue += lineObj.get_jmp_sites(label)

	print('start backward cfg')
	while addr != None:

		import pdb
		#pdb.set_trace()


		new_label_set = travel_reverse_cfg(lineObj, addr) - label_set
		new_jmp_sites = []

		for label in new_label_set:
			new_jmp_sites += lineObj.get_jmp_sites(label)			

		cfg_queue += new_jmp_sites

		label_set |= new_label_set
		
		if len(cfg_queue) > 0:
			addr = cfg_queue.pop(0)
		else:
			addr = None

		#print(new_label_sits)
		#if addr is not None:
		#	print('\n\n%x\n\n'%(addr))

		#print(label_set)
	return label_set

def get_prev_inst(lineObj, addr):
	
	lineObj.set_line(addr)
	cur_idx, cur = lineObj.get_cur_line()
	if len(cur[0]) > 0: 
		label_set = set([cur[0][:-1]])
	else:
		label_set = set()
	
	lineObj.get_prev_line()
	prev_addr = lineObj.get_cur_addr()	

	return prev_addr, label_set

def symbolize_got_based_addressing(resdic):
	import pdb


	got_base = min(resdic['.got.plt'].keys())
	for section in ['.text','.init','.fini']:
	
		lineObj = LineObject(resdic, section)

		#find callee whoch cleans up its stack argument	
		for ret_addr in lineObj.retl_x_list:
			
			addr, size = lineObj.handle_retl_x(ret_addr)
			
			label_set = get_cfg_node_label(lineObj, addr)	
		
			#addr,size  = lineObj.pop_jmp_from_site()
			lineObj.register_retl_x_callee(label_set, size)


		print('-------------------------------------------')
		print(lineObj.label_retl_size_dict)

		print('-------------------------------------------')
		#print(lineObj.label_retl_size_dict)

		for call_site in lineObj.error_call_site:
			lineObj.set_line(call_site)
			for cnt in range(10):
				prev_idx, prev = lineObj.get_prev_line()
				instObj =  InstParser(prev[1][0])
				if instObj.op == 'pushl':
					if '$' in instObj.argv[1] and '$0' != instObj.argv[1]:
						lineObj.exit_call_site.append(call_site)
					break

		for call_site in lineObj.exit_call_site:


			exit_label_set = get_cfg_node_label(lineObj, call_site)
			retl_label_set1 = set()
			retl_label_set2 = set()

			alist1 =  [addr for addr in lineObj.retl_list if addr < call_site]
			if len(alist1) > 0:
				adjacent_ret1 = max(alist1)
				retl_label_set1 = get_cfg_node_label(lineObj, adjacent_ret1)

			alist2 = [addr for addr in lineObj.retl_list if addr > call_site]
			if len(alist2) > 0:
				adjacent_ret2 = min(alist2)
				retl_label_set2 = get_cfg_node_label(lineObj, adjacent_ret2)


			import pdb
			#pdb.set_trace()
			if len(exit_label_set & retl_label_set1) == 0 and len(exit_label_set & retl_label_set2) == 0:
				lineObj.register_exit_callee(exit_label_set)
		
			

		for start in lineObj.get_pc_thunk_call_site_list:
			print('-------------------------------------------')
			print('start addr : %x'%(start))
			print('-------------------------------------------')

			got_addr, addr, reg = lineObj.handle_get_pc_thunk(start)
			#stack_move = 'unknown'
			print("start CFG graph with %s"%(reg))
			got_ptr_set_list = [RegisterObject(reg)]
			
			if got_addr != got_base:
				pdb.set_trace()
		
			while addr != None:
				travel_cfg(lineObj, got_base, addr, got_ptr_set_list)
				#travel_cfg(lineObj, got_base, addr, got_ptr_set_list, stack_move)
				#pdb.set_trace()
				addr, got_ptr_set_list = lineObj.pop_node()
			

def expand_data(lineObj, data_end, bss_start, addr):
	DISA = lineObj.resdic['.data'][data_end][1][0]
	directive = DISA.split()[0]
	if directive == '.long':
		off = 4
	elif directive == '.byte':
		off = 1

	for addr in range(data_end+off, bss_start):
		lineObj.resdic['.data'][addr] = ['',[' .byte 0x00'], '', '']
		lineObj.global_map[addr] = '.data'
	

def get_symbolized_label(lineObj, argv, got_addr):

	disp_str = argv.split('(')[0]
	if '*' == disp_str[0]:
		prefix = '*'
		disp_str = disp_str[1:]
	else:
		prefix = ''	

	try:
		disp = int(disp_str, 16)
				
		if disp == 0:
			return argv
		
	except:
		return argv
		
	print('%20s label %x = %x + (%x)'%('\t',disp+got_addr, got_addr, disp))
	symbol_name = lineObj.get_symbol_name(disp+got_addr)

	if symbol_name is None:

		import pdb
		print('unknown???')		
		
		cur_idx, cur = lineObj.get_cur_line()
		cur[2] += '<-- this is unknown address'

		data_end = max(lineObj.resdic['.data'].keys())
		bss_start = min(lineObj.resdic['.bss'].keys())
		if disp+got_addr > data_end and disp+got_addr <= bss_start:
			return argv
			#expand_data(lineObj, data_end, bss_start, disp+got_addr)
			#return	get_symbolized_label(lineObj, argv, got_addr)


		pdb.set_trace()

		got_end = max(lineObj.resdic['.got'].keys())
		got_plt_start = min(lineObj.resdic['.got.plt'].keys())
		if disp+got_addr > got_end and disp+got_addr <= got_plt_start:
			return	argv


		abort()

	#TODO: if memory refers .got.plt. we gives exception
	if symbol_name == '.got.plt':
		return argv


	symbol_name = prefix + symbol_name
	if '@GOT' in symbol_name or '@plt' in symbol_name:
		return symbol_name.split('@')[0] 
	else:
		symbol_name += '@GOTOFF'
		return symbol_name + argv[len(prefix+disp_str):] 



def handle_argv(lineObj, instObj, got_addr, idx):

	argv = instObj.argv[idx]

	if '(' in argv:
		instObj.argv[idx] = get_symbolized_label(lineObj, argv, got_addr)

		if len(instObj.argv) > 2:
			instObj.argv[-2] += ','

		if 'imull' == instObj.op and len(instObj.argv) > 3:
			instObj.argv[-3] += ','			

		NEW_DISA = ' ' + ' '.join(instObj.argv) 
		lineObj.set_cur_disas(NEW_DISA)	

	
def handle_argv1(lineObj, instObj, got_addr):
	handle_argv(lineObj, instObj, got_addr,-1)

def handle_argv2(lineObj, instObj, got_addr):
	handle_argv(lineObj, instObj, got_addr,-2)

def travel_reverse_cfg(lineObj, end_addr):
	lineObj.set_line(end_addr)
	cur_idx, cur = lineObj.get_cur_line()

	label_set = set()

	start_idx = cur_idx

	while True:
		DISA = cur[1][0]
		instObj = InstParser(DISA)

		#print(DISA)		

		if instObj.op == 'calll':
			if instObj.argv[-1] in ['abort__MYSYM2', 'exit__MYSYM2', '__assert_fail__MYSYM2' , '_exit_MYSYM2']:
				break
		if 'retl' == instObj.op:
			break
		if instObj.op in ['jmpl', 'jmp']:
			#we give a exception when end of node is jmp
			if start_idx != cur_idx:
				break
		if 'hlt' == instObj.op:
			break	
	
		label = cur[0]

		if 'MYSYM' in label or 'main:' == label:
			#lineObj.push_jmp_site(label[:-1], size)
			label_set.add(label[:-1])
			print('--------------add :'+label[:-1])


		cur_idx, cur = lineObj.get_prev_line()

		if cur is None:
			import pdb
			#pdb.set_trace()
			break


	return label_set


def handle_single_argument(lineObj, instObj, got_ptr_set_list, cur_set, got_addr):
	remove_set = set()
	bContinue = True
	if instObj.op == 'popl':
		if instObj.argv[-1] in cur_set:
			remove_set.add(instObj.argv[-1])
	
	elif instObj.is_jmp_inst():
		label = instObj.argv[1]
		if instObj.op in [ 'jmpl', 'jmp']:
			res = re.findall('jmpl \*(%.*)',instObj.inst)
			if len(res) > 0:
				reg = res[0]
				if reg not in ['%eax','%ebx','%ecx','%edx','%edi','%esi','%ebp']:
					print(instObj.inst)
					abort()
				jump_list = jump_symbolize(lineObj, reg)
				
				for item in jump_list:
					lineObj.add_node(item, got_ptr_set_list)
			else:
				lineObj.add_node(label, got_ptr_set_list)

			bContinue = False
		else:
			lineObj.add_node(label, got_ptr_set_list)
		if instObj.op[:3] == 'jmp':
			bContinue = False
	elif instObj.op == 'calll':
		if instObj.is_exit_call():
			bContinue = False
		elif instObj.is_error_call():
			if is_arg1_non_zero(lineObj):
				bContinue = False
		elif '__x86.get_pc_thunk.' in instObj.argv[1]:
			bContinue = False
		elif lineObj.check_exit_callee(instObj.argv[1]):
			bContinue = False

		#remove_set.add(RegisterObject('%eax'))
		remove_set.add('%eax')


	else:
		# in case of floating pointer instruction
		# TODO: floating pointer handling
		for item in got_ptr_set_list:
			if item.check_contamination(instObj.argv[-1]):
				print('remove~~~~~~~~~~~~push!!')
				#db.set_trace()
				if isinstance(item, StackObject):
					remove_set.add(instObj.argv[-1])
				else:
					reg = instObj.get_register_names(instObj.argv[-1])[0]
					remove_set.add(reg)
				break
			elif item.check_use_of_got_pointer(instObj.argv[-1]):
				handle_argv1(lineObj, instObj, got_addr)
				break
	return bContinue, remove_set
		
def handle_multiple_arguments(lineObj, instObj, got_ptr_set_list, cur_set, got_addr):
	
	remove_set = set()
	add_set = set()
	for item in got_ptr_set_list:
		#got propagation
		if item.check_got_propagation(instObj.argv[-2]) and 'movl' == instObj.op:
			if '(' in instObj.argv[-1]:
				stack_got_ptr_set_list = [i.get_val() for i in got_ptr_set_list if isinstance(i, StackObject)]
				if len(stack_got_ptr_set_list) > 0 and instObj.argv[-1] not in stack_got_ptr_set_list:
					import pdb
					pdb.set_trace()
					#abort()

			add_set.add(instObj.argv[-1])
			break	
		#elif item in instObj.argv[-2] and len(instObj.get_register_names(item)) > 0:
		#check use of got pointer
		elif item.check_use_of_got_pointer(instObj.argv[-2]):
			#  leal.d8 0(%esi), %esi                             set(['%esi'])
			if 'leal' == instObj.op:
				res = re.findall('(.*)\((....)\)', instObj.argv[-2])
				if len(res) > 0:
					disp, reg1 = res[0]
					if 'MYSYM' not in disp and int(disp, 16) == 0 and reg1 == item:
						add_set.add(instObj.argv[-1])
						#add_set.add(StackObject(instObj.argv[-1]))
						break	
				
			handle_argv2(lineObj, instObj, got_addr)
		
		#check contemination of got pointer
		if item.check_contamination(instObj.argv[-1]):
			if instObj.op == 'movl' and instObj.argv[-2] in cur_set: #instObj.argv[-2] in got_ptr_set_list:
				continue
			elif 'cmp' in instObj.op:
				continue
			elif 'leal' == instObj.op:
				#exception
				#import pdb
				#pdb.set_trace()
				res = re.findall('(.*)\((....)\)',instObj.argv[-2])	
				if len(res) > 0:
					disp, reg2 = res[0]
					if disp == '0' and reg2 in cur_set:
						continue
			remove_set.add(item.get_val())		

		#elif item in instObj.argv[-1] and len(instObj.get_register_names(item)) > 0:
		#check use of got pointer
		elif item.check_use_of_got_pointer(instObj.argv[-1]):
			handle_argv1(lineObj, instObj, got_addr)


	return add_set, remove_set	

def emulate_stack_move(lineObj, instObj):
	stack_move = 0
	if instObj.op == 'pushl':
		stack_move = -4
	elif instObj.op == 'popl':
		stack_move = 4
	elif instObj.op == 'calll':
		if instObj.argv[1] in lineObj.label_retl_size_dict.keys():
			stack_move = - lineObj.label_retl_size_dict[instObj.argv[1]]
	elif instObj.op == 'leave':
		#remove all stack got_ptr_set_list
		stack_move = 'unknown'

	elif instObj.argv[-1] == '%esp':
		if instObj.op == 'addl' and '$' in instObj.argv[-2]:
			stack_move = int(instObj.argv[-2][1:], 16)
		elif instObj.op == 'subl' and '$' in instObj.argv[-2]:
			stack_move = -int(instObj.argv[-2][1:], 16)
		else:
			stack_move = 'unknown'
	return stack_move

#def travel_cfg(lineObj, got_addr, start_addr, got_ptr_set_list, stack_move):
def travel_cfg(lineObj, got_addr, start_addr, got_ptr_set_list):

	lineObj.set_line(start_addr)
	cur_idx, cur = lineObj.get_cur_line()

	stack_move = 0
		
	while True:
		'''
		if cur[0] == 'MYSYM_776:':
			import pdb
			pdb.set_trace()		
		'''

		#record got pointer set info
		lineObj.set_idx_def_dic(cur_idx, got_ptr_set_list)

		
		DISA = cur[1][0]
		instObj = InstParser(DISA)


		'''	
		if cur[0] == 'MYSYM_776:':
			import pdb
			pdb.set_trace()		
		'''

		#stack emulator operation.		
		stack_move = emulate_stack_move(lineObj, instObj)


		print '%-30s'%(DISA),
		print '\t\t%5d\t\t'%(cur_idx),
		bStack = False
		if stack_move != 'unknown':
			for item in got_ptr_set_list:
				if isinstance(item,StackObject):
					print '[%x]'%(item.stack_move+stack_move),
					bStack = True
		if not bStack:
			print '[u]',	
		print '\t\t',
		def_list = [str(item) for item in got_ptr_set_list ]
		#def_list = [item.get_val() for item in got_ptr_set_list ]
		print(def_list)


		#end condition #1
		if instObj.op == 'hlt':
			break
		elif instObj.op == 'retl' :
			for item in got_ptr_set_list:
				if isinstance(item, StackObject):
					if item.stack_move < 0:
						import pdb
						pdb.set_trace()
						abort()
			break

		remove_set = set()
		add_set = set()
		cur_set = set([item.get_val() for item in got_ptr_set_list])
		bContinue = True
		if len(instObj.argv) > 2:
			add_set, remove_set = handle_multiple_arguments(lineObj, instObj, got_ptr_set_list, cur_set, got_addr)
		#handle single argument
		elif len(instObj.argv) == 2:
			bContinue, remove_set = handle_single_argument(lineObj, instObj, got_ptr_set_list, cur_set, got_addr)
		#handlne no argument instruction
		elif len(instObj.argv) == 1:
			if instObj.op == 'cltd':
				remove_set.add('%edx')
				



		#cur_set -= remove_set
		#cur_set |= add_set
		#got_ptr_set_list = [item for item in got_ptr_set_list if item.get_val() in cur_set]

		remove_set -= add_set
		got_ptr_set_list = [item for item in got_ptr_set_list if item.get_val() not in remove_set]

		for item in add_set:
			if item not in cur_set:
				if '(' in item:
					got_ptr_set_list.append(StackObject(item))
				else:
					got_ptr_set_list.append(RegisterObject(item))

		

		if not bContinue:
			print('Break: bCondition is false')
			break
				

		#update got pointer set 
		#if esp register is untraceable delete all got pointer that related to esp register
		if stack_move == 'unknown':
			got_ptr_set_list = [item for item in  got_ptr_set_list if isinstance(item, RegisterObject) or item.reg != '$esp']
		else:
			for item in got_ptr_set_list:
				if isinstance(item, StackObject):
					item.update_stack(stack_move)	
			got_ptr_set_list = [item for item in  got_ptr_set_list if item.is_valid() ]


		cur_idx, cur = lineObj.get_next_line()
		if cur is None:
			print('Break: cur is None')
			break

		if len(cur[0])>0 and '__x86.get_pc_thunk.' not in cur[0]:
			print('Break: get reached to labeled address')
			lineObj.add_node(cur[0][:-1], got_ptr_set_list)
			break

			
	print('done!!')	


def is_arg1_non_zero(lineObj):
	cur_idx, cur = lineObj.get_cur_line()
	prv_idx, prv = lineObj.get_prev_line(option='cfg')
	
	bNonZero = False
	while cur_idx - 10 < prv_idx:
		prevInst = InstParser(prv[1][0])
	
		if prevInst.op == 'pushl':
			res = re.findall('\$(.)', prv[1][0])
			if len(res) > 0  and 'MYSYM' not in res[0]:
				val = int(res[0],16)
				if val != 0:
					print('done')
					bNonZero = True
			break


		prv_idx, prv = lineObj.get_prev_line(option='cfg')

	lineObj.set_position(cur_idx)
	return bNonZero
			
def transform_byte2dword(resdic, section_from, addr):
        candidate = ''
        print(resdic[section_from][addr][1][0])
        if resdic[section_from][addr][1][0].startswith(' .byte') or \
           resdic[section_from][addr+1][1][0].startswith(' .byte') or \
           resdic[section_from][addr+2][1][0].startswith(' .byte') or \
           resdic[section_from][addr+3][1][0].startswith(' .byte'):
                candidate += resdic[section_from][addr+3][1][0]
                candidate += resdic[section_from][addr+2][1][0]
                candidate += resdic[section_from][addr+1][1][0]
                candidate += resdic[section_from][addr+0][1][0]
                candidate = candidate.replace(' .byte 0x','')
                candidate = "0x"+candidate
                return candidate
        return None

import struct



def jump_step1(prevInst, reg, got_ptr_set_list):

	def_list = [item.get_val() for item in got_ptr_set_list if isinstance(item, RegisterObject)]
	print(def_list)
	if '@GOTOFF' in prevInst.argv[-2]:
		res = re.findall('(.*)@GOTOFF\((.*), (.*), (.*)\)',prevInst.argv[-2])
		if len(res) > 0:
			label, reg1, reg2, mul = res[0]
			reg = reg2
			mul = int(mul)
			return label, reg, mul
		else:
			label, reg1, reg2 = re.findall('(.*)@GOTOFF\((.*), (.*)\)',prevInst.argv[-2])[0]
			if reg1 in def_list:
				reg=reg2
			elif reg2 in def_list:
				reg=reg1
			return label, reg, 0


	elif prevInst.argv[-2] in def_list:
		return '', reg, 0
	elif prevInst.argv[-1] in def_list:
		return '', prevInst.argv[-2], 0
	else:
		abort()
	return '', reg, 0

def jump_step2(prevInst, reg, got_ptr_set_list):

	def_list = [item.get_val() for item in got_ptr_set_list if isinstance(item, RegisterObject)]
	res = re.findall('(.*)@GOTOFF\((.*), (.*), (.*)\)',prevInst.argv[-2])
	if len(res) > 0:
		label, reg1, reg2, mul = res[0]
		if reg1 in def_list:
			reg = reg2
		elif reg2 in def_list:
			reg = reg1
		mul = int(mul)
		return label, reg, mul
	else:
		label, reg1, reg2 = re.findall('(.*)@GOTOFF\((.*), (.*)\)',prevInst.argv[-2])[0]
		if reg1 in def_list:
			reg=reg2
		elif reg2 in def_list:
			reg_reg1
		return label, reg, 0


	abort()

def jump_symbolize(lineObj, reg):
	
	import pdb
	#pdb.set_trace()

	curIdx = lineObj.get_cur_line()[0]

	minIdx = curIdx - 20

	label = ''
	mul = 0
	prevIdx,prev = lineObj.get_prev_line(option='cfg')
	while prevIdx > minIdx:
		print('jump1: ' + prev[1][0])
		prevInst = InstParser(prev[1][0])
		prev_got_ptr_set_list = lineObj.get_idx_def_dic(prevIdx)
		if 'addl' == prevInst.op and reg == prevInst.argv[-1]:
			label, reg, mul = jump_step1(prevInst, reg, prev_got_ptr_set_list)
			break
		elif 'movl' == prevInst.op and reg == prevInst.argv[-1]:
			reg = prevInst.argv[-2]

		prevIdx,prev = lineObj.get_prev_line(option='cfg')

	if len(label) == 0:
		prevIdx,prev = lineObj.get_prev_line(option='cfg')
		while prevIdx > minIdx:
			print('jump2: ' + prev[1][0])
			prevInst = InstParser(prev[1][0])
			prev_got_ptr_set_list = lineObj.get_idx_def_dic(prevIdx)
			if 'movl' == prevInst.op and reg == prevInst.argv[-1]:
				label, reg, mul = jump_step1(prevInst, reg, prev_got_ptr_set_list)
				break			
			prevIdx,prev = lineObj.get_prev_line(option='cfg')

	if len(label) == 0:
		abort()

	myMax = 0
	if mul == 0:	
		prevIdx,prev = lineObj.get_prev_line(option='cfg')
		while prevIdx > minIdx:
			print('jump3: ' + prev[1][0])
			prevInst = InstParser(prev[1][0])
			if 'shll' == prevInst.op and reg == prevInst.argv[-1]:
				if '$2' != prevInst.argv[-2]:
					abort()
				break
			
			#TODO exception:
			if prevInst.op in ['cmpw', 'cmpl']:
				if '$' in prevInst.argv[-1]: 
					myMax = int(prevInst.argv[-1][1:], 16)
					break
				elif '$' in prevInst.argv[-2]:
					myMax = int(prevInst.argv[-2][1:], 16)
					break
			
			prevIdx,prev = lineObj.get_prev_line(option='cfg')

	if myMax == 0:
		target = reg
		conditional_jump = False

		prevIdx,prev = lineObj.get_prev_line(option='cfg')
		#while prevIdx > minIdx:
		for cnt in range(100):
			print('jump4: ' + prev[1][0])
			prevInst = InstParser(prev[1][0])
			if prevInst.argv[-1] == target:
				if prevInst.op == 'movl':
					target = prevInst.argv[-2]
				elif prevInst.op in ['movzbl', 'movzwl']:
					'''
					reg_names = prevInst.get_register_names(target)
					print(reg_names)
					if target not in reg_names:
						abort()	
					'''
					reg_names = prevInst.get_register_names(prevInst.argv[-2])
					if len(reg_names) > 0:
						target = reg_names[0]	
					else:
						target = prevInst.argv[-2]
			if prevInst.op == 'cmpl':
				if prevInst.argv[-1] == target:
					myMax = int(prevInst.argv[-2][1:], 16)
					break
				elif prevInst.argv[-2] == target:
					myMax = int(prevInst.argv[-1][1:], 16)
					break
			elif prevInst.op in ['cmpb', 'cmpw']:
				reg_names = prevInst.get_register_names(target)
				print(reg_names)
				if len(reg_names) == 0:
					if prevInst.argv[-1] == target: 
						myMax = int(prevInst.argv[-2][1:], 16)
					elif prevInst.argv[-2] == target:
						myMax = int(prevInst.argv[-1][1:], 16)
				else:
					for reg in reg_names:
						if prevInst.argv[-1] == reg:
							myMax = int(prevInst.argv[-2][1:], 16)
							break
						elif prevInst.argv[-2] == reg:
							myMax = int(prevInst.argv[-1][1:], 16)
							break
				if myMax != 0:
					break
			elif prevInst.op == 'calll':
				print('TODO: check it!!')
				import pdb
				pdb.set_trace()
				myMax = 6 
				break


			if conditional_jump and  prevInst.op in ['cmpl','cmpb','cmpw']: # heuristic
				if '$' == prevInst.argv[-1][0]: 
					myMax = int(prevInst.argv[-1][1:], 16)
				else:
					myMax = int(prevInst.argv[-2][1:], 16)
				break
			elif prevInst.is_jmp_inst() and prevInst.op not in ['jmp','jmpl']:
				conditional_jump = True


			prevIdx,prev = lineObj.get_prev_line(option='cfg')

	if myMax == 0:
		abort()

	got_base = min(lineObj.resdic['.got.plt'].keys())	
	section = '.rodata'
       	#label_dict = {lineObj.resdic[section][addr][0][:-1]:addr for addr in lineObj.resdic[section].keys() if 'MYSYM' in lineObj.resdic[section][addr][0]}
       	for addr in lineObj.resdic[section].keys():
		if 'MYSYM' in lineObj.resdic[section][addr][0] and label+':' == lineObj.resdic[section][addr][0]:
			jump_base = addr
			break	
	jump_list = []

	for idx in range(myMax+1):
		jump_addr = jump_base+4*idx
	
		res = re.findall('.long (.*)@GOTOFF',lineObj.resdic['.rodata'][jump_addr][1][0])	
		if len(res) > 0:
			jump_list.append(res[0])
			continue	

		data = transform_byte2dword(lineObj.resdic, '.rodata', jump_addr)
		offset = struct.unpack('>i',data[2:].decode('hex'))[0]

		target_addr = got_base + offset

		jump_label = lineObj.resdic['.text'][target_addr][0]

		if len(jump_label) == 0:
			jump_label = 'MYSYM_JMP_' + str(lineObj.get_unique_count())
			lineObj.resdic['.text'][target_addr][0] = jump_label + ':'
			#TODO: new label should be added to label_dict
			lineObj.label_dict[jump_label] = target_addr
		else:
			jump_label = jump_label[:-1]

		jump_list.append(jump_label)

		lineObj.resdic['.rodata'][jump_addr][1][0] = ' .long ' + jump_label + '@GOTOFF'
		lineObj.resdic['.rodata'].pop(jump_addr+1)
		lineObj.resdic['.rodata'].pop(jump_addr+2)
		lineObj.resdic['.rodata'].pop(jump_addr+3)
		print(lineObj.resdic['.rodata'][jump_addr][1][0])
	
	lineObj.set_position(curIdx)
	return jump_list

class InstParser:
	def __init__(self, inst):
		self.inst = inst 
		self.argv = self.parse_args(inst)
		self.argc = len(self.argv)
		self.op = self.argv[0].split('.')[0]

        def get_register_names(self, reg):
                eax_reg= ['%eax','%ax','%ah','%al']
                ebx_reg= ['%ebx','%bx','%bh','%bl']
                ecx_reg= ['%ecx','%cx','%ch','%cl']
                edx_reg= ['%edx','%dx','%dh','%dl']
                esi_reg= ['%esi','%si']
                edi_reg= ['%edi','%di']
                ebp_reg= ['%ebp','%bp']
                esp_reg= ['%esp','%sp']

                if reg in eax_reg: return eax_reg
                if reg in ebx_reg: return ebx_reg
                if reg in ecx_reg: return ecx_reg
                if reg in edx_reg: return edx_reg
                if reg in edi_reg: return edi_reg
                if reg in esi_reg: return esi_reg
                if reg in ebp_reg: return ebp_reg
                if reg in esp_reg: return esp_reg
                return []

        def parse_args(self, line):
                argv = list()
                word = ''
                rbranket = 0
                for idx in range(len(line)):

                        if line[idx].isspace():
                                if rbranket != 0:
                                        word += line[idx]
                                elif len(word) != 0:
                                        argv.append(word)
                                        word = ''
                        elif line[idx] == ',':
                                if rbranket == 0:
                                        argv.append(word)
                                        word = ''
                                else:
                                        word += line[idx]
                        else:
                                word += line[idx]
                                if line[idx] == '(':
                                        rbranket += 1
                                elif line[idx] == ')':
                                        rbranket -= 1


                if len(word) != 0:
                        argv.append(word)

                return argv

	def update_argument(self, arg, stack_move):
		if stack_move == 'unknown':
			return arg

		if '%esp' in arg:
			disp = int(re.findall('(.*)\(%esp\)', arg)[0], 16) 
			if disp-stack_move < 0:
				return 'invalid'	

			elif disp-stack_move >= 10:
				new_arg = '0x%x(%%esp)'%(disp - stack_move)
			else:
				new_arg = '%x(%%esp)'%(disp - stack_move)
			print(new_arg)

			return new_arg

		return arg
			

	def is_exit_call(self):
		if self.op == 'calll':
			
			funcs = ['abort', 'exit', '__assert_fail' , '_exit']
			funcs = [ item+'__MYSYM2' for item in funcs]
			if self.argv[1] in funcs:
				return True
		return False

	def is_error_call(self):
		if self.op == 'calll':
			funcs = ['error']
			funcs = [ item+'__MYSYM2' for item in funcs]
			if self.argv[1] in funcs:
				return True
		return False

	def is_jmp_inst(self):
		if self.op in [ 'jo'
                                ,'jno'
                                ,'js'
                                ,'jns'
                                ,'je','jz'
                                ,'jne','jnz'
                                ,'jb','jnae','jc'
                                ,'jnb','jae','jnc'
                                ,'jbe','jna'
                                ,'ja','jnbe'
                                ,'jl','jnge'
                                ,'jge','jnl'
                                ,'jle','jng'
                                ,'jg','jnle'
                                ,'jp','jpe'
                                ,'jnp','jpo'
                                ,'jcxz','jcxz'
                                ,'jcxz','jecxz'
                                ,'jmp'
				,'jmpl'
                                ]:
			return True
		return False
	
class StackObject:
	def __init__(self, init_val):
		self.init_val = init_val
		print(re.findall('(.*)\((%...)\)', init_val)[0])
		disp, self.reg = re.findall('(.*)\((%...)\)', init_val)[0]
		self.disp = int(disp, 16)
		self.stack_move = 0

	def get_val(self):
		return self.get_stack_val()

	def is_valid(self, move=0):
		if self.reg != '%esp':
			return True
		if self.disp-self.stack_move - move < 0:
			return False
		return True

	def get_stack_val(self):

		if self.reg != '%esp':
			return self.init_val

		if not self.is_valid():
			return 'invalid'
		if self.disp-self.stack_move >= 10:
			new_arg = '0x%x(%s)'%(self.disp - self.stack_move, self.reg)
		else:
			new_arg = '%x(%s)'%(self.disp - self.stack_move, self.reg)
		#print(new_arg)

		return new_arg

	def update_stack(self, stack_move):
		if self.reg != '%esp':
			return True

		self.stack_move += stack_move
		return self.is_valid()


	def __str__(self):
		return '%s [ %s + 0x%x]'%(self.get_stack_val(), self.init_val, self.stack_move)


	def check_use_of_got_pointer(self, arg):
		return False


	def check_got_propagation(self, arg):
		if self.get_stack_val() == arg:
			return True
		return False

	def check_contamination(self, arg):
		if self.get_stack_val() == arg:
			return True
		return False


class RegisterObject:
	def __init__(self, init_val):
		self.init_val = init_val
		self.reg = re.findall('(%...)', init_val)[0]
		self.reg_name_list = self.get_register_names(init_val)

	def is_valid(self, move=0):
		return True

	def get_val(self):
		return self.reg

	def check_use_of_got_pointer(self, arg):
		for reg_name in self.reg_name_list:
			if reg_name in arg:
				return True
		return False

	def check_contamination(self, arg):
		for reg_name in self.reg_name_list:
			if reg_name == arg:
				return True
		return False

	def check_got_propagation(self, arg):
		if self.reg == arg:
			return True
		return False

	def __str__(self):
		return self.init_val


        def get_register_names(self, reg):
                eax_reg= ['%eax','%ax','%ah','%al']
                ebx_reg= ['%ebx','%bx','%bh','%bl']
                ecx_reg= ['%ecx','%cx','%ch','%cl']
                edx_reg= ['%edx','%dx','%dh','%dl']
                esi_reg= ['%esi','%si']
                edi_reg= ['%edi','%di']
                ebp_reg= ['%ebp','%bp']
                esp_reg= ['%esp','%sp']

                if reg in eax_reg: return eax_reg
                if reg in ebx_reg: return ebx_reg
                if reg in ecx_reg: return ecx_reg
                if reg in edx_reg: return edx_reg
                if reg in edi_reg: return edi_reg
                if reg in esi_reg: return esi_reg
                if reg in ebp_reg: return ebp_reg
                if reg in esp_reg: return esp_reg	

		abort() 


class LineObject:
	def __init__(self, resdic, section='.text'):
		self.resdic = resdic
		self.section = section

        	self.get_pc_thunk_call_site_list = [addr for addr in resdic[self.section].keys() if 'get_pc_thunk' in resdic[self.section][addr][1][0]]
		self.get_pc_thunk_call_site_list.sort()

       	 	self.label_dict = {resdic[self.section][addr][0][:-1]:addr for addr in resdic[self.section].keys() if 'MYSYM' in resdic[self.section][addr][0]}
        	self.visit_site = set()

		self.line_list = sorted(resdic[self.section].keys())

		self.size = len(self.line_list)

        	self.navi_dict = {addr:idx for (idx,addr) in enumerate(self.line_list, 0)}
		
		self.position = -1

		self.node_list = []

		self.got_addr = 0
	
		self.global_map = dict()
		for section in resdic.keys():
			self.global_map.update({addr:section for addr in resdic[section].keys()})

		self.SYMBOL_INDEX = 0

		self.count = -1
	
		self.global_def_dic = dict()

		self.call_site = dict()


		self.jmp_site_dict = dict()
		self.retl_x_list = []
		self.retl_list = []
		self.exit_call_site = []
		self.error_call_site = []
		self.get_jmp_site_info()

		self.label_retl_size_dict = dict()	
		self.label_exit_callee_set = set()

	def get_jmp_site_info(self):
		for addr in self.resdic[self.section].keys():
			instObj = InstParser(self.resdic[self.section][addr][1][0])
			if instObj.op == 'retl':
				if len(re.findall('retl\s\$',self.resdic[self.section][addr][1][0])) > 0:
					self.retl_x_list.append(addr)
				self.retl_list.append(addr)
			elif instObj.op == 'calll' and instObj.argv[-1] in ['exit__MYSYM2']:
				self.exit_call_site.append(addr)
			elif instObj.op == 'calll' and instObj.argv[-1] in ['error__MYSYM2']:
				self.error_call_site.append(addr)
			elif instObj.is_jmp_inst() and 'MYSYM' in instObj.argv[1]:
				label = instObj.argv[1]
				if label in self.jmp_site_dict:
					self.jmp_site_dict[label].append(addr)
				else:
					self.jmp_site_dict[label] = [addr]

					
		

	def set_idx_def_dic(self, idx, def_dic):
		self.global_def_dic[idx] = list(def_dic)

	def get_idx_def_dic(self, idx):
		return self.global_def_dic[idx]
		

	def get_unique_count(self):
		self.count += 1
		return self.count
	
	def set_cur_disas(self, new_disas):
		addr = self.line_list[self.position]
		self.resdic[self.section][addr][1][0] = new_disas	
					
	def get_symbol_name(self, addr):
		if addr not in self.global_map.keys():
			return None


		section = self.global_map[addr]

		#TODO: prevent symbol error
		if self.section != '.plt' and section == '.got.plt':
			return '.got.plt'
		
		symbol_name = self.resdic[section][addr][0]

		if len(symbol_name) > 0:
			return symbol_name[:-1]

			
		symbol_name = "MYSYM_GOT_" + section[1:] + str(self.SYMBOL_INDEX)
		self.SYMBOL_INDEX += 1

		self.resdic[section][addr][0] = symbol_name + ':'

		return symbol_name

	def handle_retl_x(self, end):
		self.set_line(end)
		DISA = self.get_cur_line()[1][1][0]
		
		size =  int(re.findall('retl\s\$(.*)',DISA)[0], 16)

		self.get_prev_line()
		addr = self.get_cur_addr()

		return addr, size


	def handle_get_pc_thunk(self, start):
		self.set_line(start)
		DISA = self.get_cur_line()[1][1][0]

		print(DISA)
		reg = DISA.split('.')[-1]
		if reg not in ['ax','bx','cx','dx','si','di','bp']:
			print(DISA)
			print(reg)
			abort()

		reg = '%e' + reg

		DISA2 = self.get_next_line()[1][1][0]
		argv2, reg2 =  DISA2.split()[-2:]
		offset = int(argv2[1:-1],16)

		addr = self.get_cur_addr()	
		NEW_DISA2 = self.resdic[self.section][addr][1][0].replace(argv2[1:-1],'_GLOBAL_OFFSET_TABLE_')
		self.resdic[self.section][addr][1][0] = NEW_DISA2

		if reg != reg2:
			abort()

		print(NEW_DISA2)
		print('%x=%x+%x'%(offset + start+5, start+5, offset))

		'''	
		if offset == 0x140a0:
			import pdb
			pdb.set_trace()
		'''
		
		got_addr = offset + start + 5
		#got_ptr_set_list = set([reg])
		
		self.get_next_line()
		addr = self.get_cur_addr()	

		if self.got_addr == 0:
			self.got_addr = got_addr
		elif self.got_addr != got_addr:
			abort()

		return got_addr, addr, reg #got_ptr_set_list



	def set_position(self, position):
		self.position = position
	def set_line(self, addr):
		self.position = self.navi_dict[addr]

	def get_cur_line(self):
		addr = self.line_list[self.position]
		return (self.position, self.resdic[self.section][addr])


	def get_next_line(self):
		self.position += 1
		if self.position < 0 or self.position>= self.size:
			self.position = self.size
			return (self.position, None)
		addr = self.line_list[self.position]

		return (self.position, self.resdic[self.section][addr])

	def get_cur_addr(self):
		return self.line_list[self.position]


	def get_prev_line(self, option = ''):
		if option == 'cfg':
			cur_addr = self.line_list[self.position]
			label = self.resdic[self.section][cur_addr][0]
			if len(label):
				position = self.get_call_site(label[:-1])
				if position is None:
					import pdb
					pdb.set_trace()
					abort()
				self.position = position 
			else:
				self.position -= 1
		else:	
			self.position -= 1

		if self.position < 0 or self.position >= self.size:
			self.position = -1
			return (self.position, None)
		addr = self.line_list[self.position]

		return (self.position, self.resdic[self.section][addr])


	def get_next_get_pc_thunk(self):

		if len(self.get_pc_thunk_call_site) > 0:
			return self.get_pc_thunk_call_site.pop(0)

		return None

	def add_node(self, label, got_ptr_set_list):
		if label not in self.label_dict:
			return 

		addr = self.label_dict[label]
		if addr in self.visit_site:
			return None

		if addr in self.node_list:
			return None

		print '\t\t\t\t\tadd_node: %10s %x'%(label,addr), 
		tmp = [item.get_val() for item in got_ptr_set_list]
		print (tmp)

		self.record_call_site(label)

		new_got_ptr_set_list = []
		for item in got_ptr_set_list:
			if isinstance(item, RegisterObject):
				x = RegisterObject(item.init_val)
			else:
				x = StackObject(item.init_val)
				x.update_stack(item.stack_move)
			new_got_ptr_set_list.append(x)
				
		
		self.node_list.append((addr,new_got_ptr_set_list))
		return addr

	def record_call_site(self, label):
		if label not in self.call_site.keys():
			if label+':' == self.get_cur_line()[1][0] :
				self.call_site[label] = self.position - 1
			else:
				self.call_site[label] = self.position

	def get_call_site(self, label):
		if label not in self.call_site.keys():
			return None
		return self.call_site[label]

	def pop_node(self):
		if len(self.node_list) > 0:
			addr,got_ptr_set_list = self.node_list.pop(0)
			while addr in self.visit_site:
				if len(self.node_list) == 0:
					return None, None
				addr,got_ptr_set_list = self.node_list.pop(0)
			print '\t\t\t\t\tpop node : %x(u)'%(addr), 
			'''
			if 'unknown' == stack_move:
				print '\t\t\t\t\tpop node : %x(u)'%(addr), 
			else:
				print '\t\t\t\t\tpop node : %x(%x)'%(addr, stack_move), 
			'''
			tmp = [item.get_val() for item in got_ptr_set_list]
			print tmp



			#print str(got_ptr_set_list)
			self.mark_visit_site(addr)
			return addr, got_ptr_set_list

		return None,None

	def mark_visit_site(self, addr):
		self.visit_site.add(addr)
	'''	
	def push_jmp_site(self, label, size):
		print '\t\t\t\t\tpush label: %10s %x'%(label, size) 
		if label not in self.label_retl_size_dict:
			self.label_retl_size_dict[label] = size

			if label not in self.jmp_site_dict.keys():
				return
			print(self.jmp_site_dict[label])
			for addr in self.jmp_site_dict[label]:
				self.node_list.append((addr,size))
	'''
	
	def get_jmp_sites(self, label):
		if label not in self.jmp_site_dict.keys():
			return []
		
		print('%s: %s'%(label, str(['%x'%addr for addr in self.jmp_site_dict[label]])))
		return self.jmp_site_dict[label]
	'''	
	def pop_jmp_from_site(self):
		if len(self.node_list) > 0:
			addr,size = self.node_list.pop(-1)
			print '\t\t\t\t\tpop jmp from site: %x %x'%(addr, size), 
			return addr, size
		return None, None
	'''

	def register_retl_x_callee(self, label_set, size):
		for label in label_set:
			if label not in self.label_retl_size_dict:
				self.label_retl_size_dict[label] = size
			elif size != self.label_retl_size_dict[label]:
				abort()

	def register_exit_callee(self, label_set):
		self.label_exit_callee_set |= label_set
		print('Add exit callee set: ' + str(self.label_exit_callee_set))

	def check_exit_callee(self, label):
		if label in self.label_exit_callee_set:
			print('exit callee' + label)
			print(self.label_exit_callee_set)
			return True
		return False



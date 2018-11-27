#!/usr/bin/python
#-*- coding: utf-8 -*-
import sys 
import os
import binascii
from capstone import *
from elftools.elf.elffile import ELFFile
from elftools import *
from keystone import *
import pwn
from binary2dic import *
from etc import *
from symbolize import *
from global_variables import *

def PIE_set_getpcthunk_loc(resdic):
	SectionName = CodeSections_WRITE
	
	for Sname in SectionName:
		if Sname not in resdic.keys():
			continue

		SectionDic = resdic[Sname] # SectionDic 에는 resdic[Sname]에 대한 포인터가 들어가나봄 
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		for i in xrange(len(SORTED_ADDRESS)):
			orig_i_list = pickpick_idx_of_orig_disasm(SectionDic[SORTED_ADDRESS[i]][1])

			if len(orig_i_list) is 0 : continue
			orig_i = orig_i_list[0] # 대충 첨나오는얘가 원래바이너리의원래주소겠거니 하고 [0]으로 해준거,,, 알아서 나중에 오류나면 고쳐라 .
			DISASM = SectionDic[SORTED_ADDRESS[i]][1][orig_i]
			if '__x86.get_pc_thunk' in DISASM:
				EIP = str(SORTED_ADDRESS[i+1])
				SectionDic[SORTED_ADDRESS[i]][3] = EIP # string 이여야 gen_asm 에서 받아서 써줌. 



# COMMENT: 마이그레이션 완료. TODO: 코드 새니타이징.,,
# SectionDic[SORTED_ADDRESS[i]][3] = 만약 get_pc_thunk 호출부라면 EIP
#                                    아니라면 substitute 되기때문에 소거되는 RegName 을 memorial 로다가 써줌
def PIE_calculated_addr_symbolize(resdic):
	SectionName = CodeSections_WRITE # 최종적으로 추가되는 코드색션
	SectionName += []
	count = 0
	

	for sectionName_1 in SectionName:
		if sectionName_1 not in resdic.keys(): continue # 섹션이 없는경우에는 처리안해주고 걍 continue
		print "sectionName_1 : {}...".format(sectionName_1)
		
		SORTED_ADDRESS = resdic[sectionName_1].keys()
		SORTED_ADDRESS.sort()
		i = -1
		# for i in xrange(len(SORTED_ADDRESS)): #COMMENT: 이거 내가 손봐줬음. 문제생기면 다시 살리자. 
		while i < len(SORTED_ADDRESS) - 1:
			i += 1 
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i]][1])
			for orig_i in orig_i_list:

				DISASM = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_i]
				if '__x86.get_pc_thunk' in DISASM:
					slice_count = 0
	
					reg = {} # 자, 레지스터 에뮬레이션 준비~~ 
	
					REG_STHX = DISASM[DISASM.index('get_pc_thunk.') + len('get_pc_thunk.'):]
					REG_STHX = REG_STHX[REG_STHX.index('.')+1:]
					REG_STHX = 'e' + REG_STHX
					BASE = int(resdic[sectionName_1][SORTED_ADDRESS[i]][3]) # == EIP
					
					reg[REG_STHX] = BASE
					print "==========================================================="
					print "[{}] {} : {} ---{}---> {}              [[[START]]]".format(slice_count,hex(SORTED_ADDRESS[i]),DISASM,REG_STHX,hex(reg[REG_STHX]))
					slice_count += 1
	
					stepSlice = 0
					while 1: # 코드 슬라이싱 시작	 
						if stepSlice is 1: 
							break

						i += 1
						if i >= len(SORTED_ADDRESS): break # DISASM 을 설정하기위한 최소한의조건 충족안되면 break
						orig_j_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i]][1])


						for orig_j in orig_j_list:
	
							DISASM = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j]
		
							# 코드슬라이싱을 끝내는 조건 
							if 'ret' in DISASM: 
								stepSlice = 1
								break   # 베이직블락 끝나면 break
							if 'get_pc_thunk' in DISASM: 
								stepSlice = 1
								break # 또다른 블락의 시작이되면 break 
							
							# The Ultimate REGEX!
							_ = '.*?'
							p_add   = re.compile(' add' + _ + '[-+]?' + _ + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                     # add $0x1b53, %ebx
							p_sar   = re.compile(' sar' + _ + '[-+]?' + _ + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                     # sar $0x2, %ebx
							p_lea   = re.compile(' lea' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # leal.d32 -3(%ebx), %eax
							p_mov   = re.compile(' mov' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # movl.d32 -3(%ebx), %eax
							p_call  = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # calll.d32 *-0xf8(%ebx, %edi, 4)
							p_xor   = re.compile(' xor' + _ + '%' + _ + '%' + _)                                                      # xorl %edi, %edi
							p_push  = re.compile(' push' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                  # pushl.d32 -0xc(%ebx) 
		
		
							# EMU_01 : [addl $0x19c7, %ebx]
							if p_add.match(DISASM) is not None: 
								if len(extract_hex_addr(DISASM)) > 0:
									ADD_VALUE = extract_hex_addr(DISASM)[0]
									REGLIST   = extract_register(DISASM)
									INSTRUCTION = DISASM.split(' ')[1]
									if REGLIST[0] in reg.keys(): # addl $0x19c7, %ebx 에서 "%ebx" 가 keep tracking 하는 레지스터라면, 
										reg[REGLIST[0]] += ADD_VALUE
										DESTINATION = reg[REGLIST[0]] 
				
										print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
										slice_count += 1
										found_target = 0
										for sectionName_2 in resdic.keys():
											if DESTINATION in resdic[sectionName_2].keys() and sectionName_2 in AllSections_WRITE: # fortunatly, DESTINATION hits on current target
												found_target = 1
												# 심볼이름 셋팅 
												if resdic[sectionName_2][DESTINATION][0] == '': # symbol does not exist
													simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
													count += 1
													resdic[sectionName_2][DESTINATION][0] = simbolname + ':'
												else:  # symbol exists already at there. 
													simbolname = resdic[sectionName_2][DESTINATION][0][:-1]

										if found_target == 1 and sectionName_2 in AllSections_WRITE: # lea PIE_MYSYM_01, %eax 으로 바꾼다. 
											INSTRUCTION = 'lea'
											# COMMENT: a. 아래두줄 활성화해야함.  하시발 libstdbuf.so 자꾸에러떠서 우선 비활성화하고 add $_GLOBAL_OFFSET_TABLE_로 바꿔줬었음
											
											NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[0]
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											# resdic[sectionName_1][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군
											

									# COMMENT: b. 아래두줄 지워버려라. 아예.
									# 'addl $0x19c7, %ebx 에서 "%ebx" 가 keep tracking 하는 레지스터라면,' 를 따질필요가 없다. 
									'''
									orig_tmp_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i-1]][1])
									for orig_tmp in orig_tmp_list:
										DISASM_tmp = resdic[sectionName_1][SORTED_ADDRESS[i-1]][1][orig_tmp]
										if '__x86.get_pc_thunk' in DISASM_tmp: 
											NEWDISASM = ' ' + 'add' + ' ' + '$_GLOBAL_OFFSET_TABLE_' + ', ' + '%' + REGLIST[0]
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											print "       {}".format(NEWDISASM)
									'''
											


											
		
							# EMU_02 : [calll.d32 *-0xf8(%ebx, %edi, 4)]
							elif p_call.match(DISASM) is not None:
								ADD_VALUE = extract_hex_addr(DISASM)[0]
								MULI_VALUE = extract_hex_addr(DISASM)[1]
								REGLIST = extract_register(DISASM)
								INSTRUCTION = DISASM.split(' ')[1]
		
								if REGLIST[0] in reg.keys() and REGLIST[1] in reg.keys():
									DESTINATION = reg[REGLIST[0]] + (reg[REGLIST[1]]*MULI_VALUE) + ADD_VALUE
		
									print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
									slice_count += 1
									found_target = 0
									for sectionName_2 in resdic.keys():
										if DESTINATION in resdic[sectionName_2].keys() and sectionName_2 in AllSections_WRITE:
											if resdic[sectionName_2][DESTINATION][0] == '':
												simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
												count += 1
												resdic[sectionName_2][DESTINATION][0] = simbolname + ':'
											else: 
												simbolname = resdic[sectionName_2][DESTINATION][0][:-1]
											found_target = 1
											break
									if found_target == 1 and sectionName_2 in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
										NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + simbolname
										resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
										print "       {}".format(NEWDISASM)
										# resdic[sectionName_1][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군
		
							# EMU_03 : [pushl.d32 -0xc(%ebx)] 
							elif p_push.match(DISASM) is not None:
								ADD_VALUE       = extract_hex_addr(DISASM)
								REGLIST         = extract_register(DISASM)
								INSTRUCTION = DISASM.split(' ')[1]
								if len(ADD_VALUE) == 0: ADD_VALUE = 0 # 걍 push %ebx 일수도 있자나?
								else: ADD_VALUE = ADD_VALUE[0]
		
								if REGLIST[0] in reg.keys(): # 레지스터가 keep tracking 하는 레지스터라면 
									# reg[REGLIST[1]] = reg[REGLIST[0]] + ADD_VALUE # 레지스터 값의 변화는 없음  
									DESTINATION = reg[REGLIST[0]] + ADD_VALUE
		
									print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
									slice_count += 1
									found_target = 0
									for sectionName_2 in resdic.keys():
										if DESTINATION in resdic[sectionName_2].keys() and sectionName_2 in AllSections_WRITE:
											if resdic[sectionName_2][DESTINATION][0] == '':
												simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
												count += 1
												resdic[sectionName_2][DESTINATION][0] = simbolname + ':'
											else:
												simbolname = resdic[sectionName_2][DESTINATION][0][:-1]
											found_target = 1
											break
									if found_target == 1 and sectionName_2 in AllSections_WRITE:
										NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname
										resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM	
										print "       {}".format(NEWDISASM)
										# resdic[sectionName_1][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군 COMMENT: GOT based 로다가 접근하는경우에 %ebx라는값이 중요한 역할을 함. 그래서 [3]에다가 저장하였따
										resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST[0]
		
		
		
							elif p_sar.match(DISASM) is not None:
								REGLIST   = extract_register(DISASM)
								if REGLIST[0] in reg.keys(): del reg[REGLIST[0]] # reg deverts The Demension. Delete it. 
		
							elif p_xor.match(DISASM) is not None:
								REGLIST   = extract_register(DISASM)
								if REGLIST[0] == REGLIST[1]:
									reg[REGLIST[0]] = 0
		
		
							# EMU_02 : [lea -0xf4(%ebx),%esi] / [mov -0xf4(%ebx),%esi] 
							elif p_lea.match(DISASM) is not None or p_mov.match(DISASM) is not None:
								ADD_VALUE       = extract_hex_addr(DISASM)
								REGLIST         = extract_register(DISASM)

								
								if len(ADD_VALUE) == 0: ADD_VALUE = 0 # 걍 lea %ebx, %eax 일수도 있자나?
								else:ADD_VALUE = ADD_VALUE[0]
								
								if REGLIST[0] in reg.keys(): # 좌측의 레지스터가 keep tracking 하는 레지스터라면, 
									DESTINATION     = reg[REGLIST[0]] + ADD_VALUE 
									# Setting instruction and EmulationMemory
									if p_lea.match(DISASM) is not None:
										INSTRUCTION = 'lea'
										reg[REGLIST[1]] = DESTINATION 
									elif p_mov.match(DISASM) is not None:
										INSTRUCTION = 'mov'
									 	if REGLIST[1] in reg.keys():
									 		del reg[REGLIST[1]] # Stop tracking... out of same DEMENTION
									 	
									
									print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
									slice_count += 1
									found_target = 0
									for sectionName_2 in resdic.keys():
										if DESTINATION in resdic[sectionName_2].keys() and sectionName_2 in AllSections_WRITE:
											if resdic[sectionName_2][DESTINATION][0] == '':
												simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
												count += 1
												resdic[sectionName_2][DESTINATION][0] = simbolname + ':'
											else:
												simbolname = resdic[sectionName_2][DESTINATION][0][:-1]
											found_target = 1
											break
									if found_target == 1 and sectionName_2 in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
										NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[1]
										resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
										resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST[0]
										print "       {}... We momorize [{}]...".format(NEWDISASM, resdic[sectionName_1][SORTED_ADDRESS[i]][3])

						_rstr = ''
						for _r in reg.keys():
							_rstr += '{}:{} / '.format(str(_r), str(hex(reg[_r])))
						resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] + ' # emulating... {}'.format(_rstr)
		
					print ""




def PIE_LazySymbolize_GOTbasedpointer(pcthunk_reglist, resdic, CHECKSEC_INFO):  
	# The Ultimate REGEX!
	_ = '.*?'
	p_lea   = re.compile(' lea' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # leal.d32 -3(%ebx), %eax
	p_mov   = re.compile(' mov' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # movl.d32 -3(%ebx), %eax
	p_call  = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # calll.d32 *-0xf8(%ebx, %edi, 4)
	p_xor   = re.compile(' xor' + _ + '%' + _ + '%' + _)                                                      # xorl %edi, %edi
	p_push  = re.compile(' push' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                  # pushl.d32 -0xc(%ebx) 

	if CHECKSEC_INFO.relro == 'Full':
		GOT_baseaddr = sorted(resdic['.got'].keys())[0]
	else:
		GOT_baseaddr = sorted(resdic['.got.plt'].keys())[0]  # gdb에서  _GLOBAL_OFFSET_TABLE 곳의 주소가 .got.plt 섹션의 시작주소임. 

	count = 0 
	# 우선은 libstdbuf.so 에서 사용하는 패턴인 lea, mov 만 가지고 해보자. 
	SectionName = CodeSections_WRITE
	for Sname in SectionName:
		if Sname not in resdic.keys(): continue # 섹션이 없는경우에는 처리안해주고 걍 continue

		SORTED_ADDRESS = resdic[Sname].keys()
		SORTED_ADDRESS.sort()
		
		'''
		[0]이위치의 원래이름: 
		[1] cmp MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %(레지스터)
		    je MYSYM_YES_12

		    MYSYM_NO_12:
		     원본인스트럭션
		     jmp MYSYM_ORIGINAL_12

		    MYSYM_YES_12:
		     바뀐인스트럭션(심볼라이즈됨)
		     jmp MYSYM_ORIGINAL_12

		    MYSYM_OROGINAL: <- 다음인스트럭션의 심볼이 이미 붙어있다면 그것을 따르도록 한다. 
		     blabla...
		'''

		for i in xrange(len(SORTED_ADDRESS)):
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[Sname][SORTED_ADDRESS[i]][1])
			for orig_i in orig_i_list:
				DISASM = resdic[Sname][SORTED_ADDRESS[i]][1][orig_i]
	
				# TODO: 아마도 백퍼센트 jmp 0x12(%ebx) call 0x12(%eax) 등등 처리안해줘서 문제생길것이다. 나중에 언젠가 regex들을 추가확장하자. 
				if p_lea.match(DISASM) is not None or p_mov.match(DISASM) is not None:
	
					if p_lea.match(DISASM) is not None: # 슬데없이 leaw 이따구로 디스어셈블하는 경우, leaw SYMBOLNAME, %eax 할때 truncate 되므로, 그냥 복잡 ㄴㄴ하게 lea로 바꾼다. 
						INSTRUCTION = 'lea'
					elif p_mov.match(DISASM) is not None:
						INSTRUCTION = 'mov'
	
					ADD_VALUE = extract_hex_addr(DISASM)[0]
					REGLIST = extract_register(DISASM)
	
					if REGLIST[0] in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
						DESTINATION = GOT_baseaddr + ADD_VALUE 
						for target_section in resdic.keys():
							if DESTINATION in resdic[target_section].keys() and target_section not in DoNotWriteThisSection: 
								# 심볼이름 셋팅
								symbolname_yes  = SYMPREFIX[0] + 'MYSYM_PIE_YES_'    + str(count)
								symbolname_no   = SYMPREFIX[0] + 'MYSYM_PIE_NO_'     + str(count)
								# symbolname_next = ???
								if resdic[Sname][SORTED_ADDRESS[i+1]][0] == '':
									symbolname_next = SYMPREFIX[0] + 'MYSYM_PIE_ORIG_'   + str(count) 
									resdic[Sname][SORTED_ADDRESS[i+1]][0] = symbolname_next + ':'
								else :
									symbolname_next = resdic[Sname][SORTED_ADDRESS[i+1]][0][:-1] # ':' 요거 빼주기
								# symbolname = ??? 
								if resdic[target_section][DESTINATION][0] == '': 
									symbolname = SYMPREFIX[0] + 'MYSYM_PIE_REMAIN_' + str(count)
									resdic[target_section][DESTINATION][0] = symbolname + ':'
								else:
									symbolname = resdic[target_section][DESTINATION][0][:-1]
								count += 1
	
	
								NEWDISASM = ' ' + INSTRUCTION + ' ' + symbolname + ', ' + '%' + REGLIST[1]
								ORIDISASM = resdic[Sname][SORTED_ADDRESS[i]][1]
								
								CODEBLOCK_1 = []
								CODEBLOCK_2 = []
	
								CODEBLOCK_1.append(' #==========LazySymbolize_GOTbasedpointer==========#')
								CODEBLOCK_1.append(' pushf' + ' #+++++')
								CODEBLOCK_1.append(' cmp MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %' + REGLIST[0] + ' #+++++')
								CODEBLOCK_1.append(' je ' + symbolname_yes + ' #+++++')
								CODEBLOCK_1.append( symbolname_no + ':' + ' #+++++')
								
								CODEBLOCK_2.append(' popf' + ' #+++++')
								CODEBLOCK_2.append(' jmp ' + symbolname_next + ' #+++++')
								CODEBLOCK_2.append( symbolname_yes + ':' + ' #+++++')
								CODEBLOCK_2.append(NEWDISASM) # #+++++ 추가하면안댐. 그러면 _progname@GOT(REGISTER_WHO), %eax 처리못하니 주의!
								CODEBLOCK_2.append(' popf' + ' #+++++')
								CODEBLOCK_2.append(' jmp ' + symbolname_next + ' #+++++')
	
								resdic[Sname][SORTED_ADDRESS[i]][1] = list_insert(orig_i + 1, resdic[Sname][SORTED_ADDRESS[i]][1], CODEBLOCK_2) # 원본바이너리에도 #+++++ 추가안하는것처럼
								resdic[Sname][SORTED_ADDRESS[i]][1] = list_insert(orig_i, resdic[Sname][SORTED_ADDRESS[i]][1], CODEBLOCK_1)
	
	
								resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]
								print "[0] {} : {} ---> (DEST:{}), eliminated : {}".format(hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION),resdic[Sname][SORTED_ADDRESS[i]][3])


					
								
					


# pie 바이너리같은경우 .plt.got의 항이 jmp *0x12341234 이게아니라 jmp *0xc(%ebx) 이러케생겼따. 그러니깐 이걸 걍 계산해가지고 심볼화해주자.  
def PIE_LazySymbolize_GOTbasedpointer_pltgot(CHECKSEC_INFO, resdic):
	_ = '.*?'
	p_jmp   = re.compile(' jmp' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + '\(%' + _ + '\)') # jmpl.d32 *0xc(%ebx)

	if '.plt.got' in resdic.keys() or '.plt' in resdic.keys():  # 섹션이 없는경우 그만헤   
		  
		# 계산을 위한 GOT_baseaddr 얻어오기 
		if CHECKSEC_INFO.relro == 'Full': 
			GOT_baseaddr = sorted(resdic['.got'].keys())[0]
			PLT_sectionName = '.plt.got'
		else:
			GOT_baseaddr = sorted(resdic['.got.plt'].keys())[0]  # gdb에서  _GLOBAL_OFFSET_TABLE 곳의 주소가 .got.plt 섹션의 시작주소임. 
			PLT_sectionName = '.plt'

		SectionDic = resdic[PLT_sectionName]  
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
			
		for i in xrange(len(SORTED_ADDRESS)):
			orig_i_list = pickpick_idx_of_orig_disasm(SectionDic[SORTED_ADDRESS[i]][1])
			for orig_i in orig_i_list:
				DISASM = SectionDic[SORTED_ADDRESS[i]][1][orig_i]
				if p_jmp.match(DISASM) is not None:
					# SETUP
					ADD_VALUE = extract_hex_addr(DISASM)[0]
					REGLIST = extract_register(DISASM)
					INSTRUCTION = DISASM.split(' ')[1]
					DESTINATION = GOT_baseaddr + ADD_VALUE 
		
					NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + str(hex(DESTINATION))
		
					print SectionDic[SORTED_ADDRESS[i]][1][orig_i]
					print NEWDISASM
					print ''
		
					SectionDic[SORTED_ADDRESS[i]][1][orig_i] = NEWDISASM
					SectionDic[SORTED_ADDRESS[i]][3]         = REGLIST[0] # [3] 에다가 소거한 레지스터 저장해야겠따. 
			

def fill_blanked_symbolname_toward_GOTSECTION(resdic):
	print ""
	print ""
	print ""
	for SectionName in resdic.keys():
		for ADDR in resdic[SectionName].keys():
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[SectionName][ADDR][1])
			for orig_i in orig_i_list:
				if 'REGISTER_WHO' in resdic[SectionName][ADDR][1][orig_i]:
					
					if orig_i == -1: continue
					print "------------------------------------REGISTER_WHO------------------------------------"
					print hex(ADDR)
					print ''
	
					for kkk in resdic[SectionName][ADDR][1]:
						print kkk
	
					# 우선은 리플레이스해주고
					resdic[SectionName][ADDR][1][orig_i] = resdic[SectionName][ADDR][1][orig_i].replace('REGISTER_WHO', '%' + resdic[SectionName][ADDR][3])
	
					# 이제 앞뒤로다가 붙여준다. 
					CODEBLOCK_1 = []
					CODEBLOCK_2 = []
					CODEBLOCK_1.append(' ')
					CODEBLOCK_1.append(' push %' + resdic[SectionName][ADDR][3] + ' #+++++') # 레지스터 백업
					CODEBLOCK_1.append(' mov MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %' + resdic[SectionName][ADDR][3] + ' #+++++') 
					CODEBLOCK_2.append(' pop %' + resdic[SectionName][ADDR][3] + ' #+++++')
	
					resdic[SectionName][ADDR][1] = list_insert(orig_i+1, resdic[SectionName][ADDR][1], CODEBLOCK_2)
					resdic[SectionName][ADDR][1] = list_insert(orig_i, resdic[SectionName][ADDR][1], CODEBLOCK_1)
					print ''
					for kkk in resdic[SectionName][ADDR][1]:
						print kkk
					

def add_routine_to_get_GLOBAL_OFFSET_TABLE_at_init_array(resdic):

	CODEBLOCK_TEXT  = []
	CODEBLOCK_INITARRAY = []

	CODEBLOCK_TEXT.append('MYSYM_SET_GLOBAL_OFFSET_TABLE: #+++++')
	CODEBLOCK_TEXT.append(' .comm MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, 4 #+++++')
	
	CODEBLOCK_TEXT.append(' push %ebx #+++++') 										# [1] 먼저 %ebx 를 백업해두자. GOT주소를 여기에 저장할테니. 
	CODEBLOCK_TEXT.append(' call MYSYM_get_pc_thunk.bx #+++++') 					# [2] _GLOBAL_OFFSET_TABLE 구해오자
	CODEBLOCK_TEXT.append(' add $_GLOBAL_OFFSET_TABLE_, %ebx #+++++')
	CODEBLOCK_TEXT.append(' mov %ebx, MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_ #+++++')	# [3] 구해온값을 MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_ 에다가 저장
	CODEBLOCK_TEXT.append(' pop %ebx #+++++') 										# [4] %ebx 복원
	CODEBLOCK_TEXT.append(' ret #+++++')
	CODEBLOCK_TEXT.append(' ')
	CODEBLOCK_TEXT.append('MYSYM_get_pc_thunk.bx: #+++++')							# [+] 추가적인 준비물 ㅎ
	CODEBLOCK_TEXT.append(' mov (%esp), %ebx #+++++')
	CODEBLOCK_TEXT.append(' ret #+++++') # 리턴 
	CODEBLOCK_TEXT.append(' ')

	CODEBLOCK_INITARRAY.append('MYSYM_INIT_ARRAY_0: #+++++')
	CODEBLOCK_INITARRAY.append(' .long MYSYM_SET_GLOBAL_OFFSET_TABLE #+++++')



	# [01] CODEBLOCK_TEXT 은 텍스트섹션의 very end 에다가 깔쌈하게 붙여주자. LAST 여야함. 그래야 특정심볼의안에서 중복실행을 방지할수가있음 
	SORTED_ADDRESS = resdic['.text'].keys()
	SORTED_ADDRESS.sort()
	ADDR_LAST = SORTED_ADDRESS[-1] # 마지막주소

	resdic['.text'][ADDR_LAST + 1] = ['',
									CODEBLOCK_TEXT,
									'',
									'']

	# [02] 바이너리시작 즉시 MYSYM_SET_GLOBAL_OFFSET_TABLE가 실행될수있도록 생성자배열에다가 추가하자
	if '.init_array' in resdic.keys(): # 섹션이 원래있다면
		SORTED_ADDRESS = resdic['.init_array'].keys()
		SORTED_ADDRESS.sort()
		ADDR_FIRST = SORTED_ADDRESS[0] # 처음주소
	else: # 섹션이 원래없다면 섹션itself를 추가해줘야 함
		resdic['.init_array'] = {}
		ADDR_FIRST = 0x00000001

	resdic['.init_array'][ADDR_FIRST-1] = ['',
											CODEBLOCK_INITARRAY,
											'',
											'']



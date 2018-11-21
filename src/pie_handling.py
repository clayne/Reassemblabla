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
		SectionDic = resdic[Sname]
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		for i in xrange(len(SORTED_ADDRESS)):
			DISASM = SectionDic[SORTED_ADDRESS[i]][1]
			if '__x86.get_pc_thunk' in DISASM:
				EIP = str(SORTED_ADDRESS[i+1])
				SectionDic[SORTED_ADDRESS[i]][3] = EIP # string 이여야 gen_asm 에서 받아서 써줌. 
				
# SectionDic[SORTED_ADDRESS[i]][3] = 만약 get_pc_thunk호출부라면 EIP
#                                    아니라면 substitute되기때문에 소거되는 RegName을 memorial로다가 써줌
def PIE_calculated_addr_symbolize(resdic):
	SectionName = CodeSections_WRITE # 최종적으로 추가되는 코드색션
	SectionName += []
	count = 0
	
	for Sname in SectionName:
		if Sname not in resdic.keys(): continue # 섹션이 없는경우에는 처리안해주고 걍 continue
		print "Sname : {}...".format(Sname)
		
		SectionDic = resdic[Sname]  
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		for i in xrange(len(SORTED_ADDRESS)):
			DISASM = SectionDic[SORTED_ADDRESS[i]][1]
			
			if '__x86.get_pc_thunk' in DISASM:
				slice_count = 0

				reg = {} # 자, 레지스터 에뮬레이션 준비~~ 

				REG_STHX = DISASM[DISASM.index('get_pc_thunk.') + len('get_pc_thunk.'):]
				REG_STHX = REG_STHX[REG_STHX.index('.')+1:]
				REG_STHX = 'e' + REG_STHX
				BASE = int(SectionDic[SORTED_ADDRESS[i]][3]) # == EIP
				
				reg[REG_STHX] = BASE
				print "==========================================================="
				print "[{}] {} : {} ---{}---> {}              [[[START]]]".format(slice_count,hex(SORTED_ADDRESS[i]),DISASM,REG_STHX,hex(reg[REG_STHX]))
				slice_count += 1


				while 1: # 코드 슬라이싱 시작	 
					i += 1
					if i >= len(SORTED_ADDRESS): break # DISASM 을 설정하기위한 최소한의조건 충족안되면 break
					DISASM = SectionDic[SORTED_ADDRESS[i]][1]

					# 코드슬라이싱을 끝내는 조건
					if 'ret' in DISASM: break   # 베이직블락 끝나면 break
					if 'get_pc_thunk' in DISASM: break

					# 여러가지의 룰을 정의 
					_ = '.*?'
					p_add   = re.compile(' add' + _ + '[-+]?' + _ + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                     # add $0x1b53, %ebx
					p_sar   = re.compile(' sar' + _ + '[-+]?' + _ + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                     # sar $0x2, %ebx
					
					# The Ultimate REGEX!
					p_lea   = re.compile(' lea' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # leal.d32 -3(%ebx), %eax
					p_mov   = re.compile(' mov' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # movl.d32 -3(%ebx), %eax
					p_call  = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # calll.d32 *-0xf8(%ebx, %edi, 4)
					p_xor   = re.compile(' xor' + _ + '%' + _ + '%' + _)                                                      # xorl %edi, %edi
					p_push  = re.compile(' push' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                  # pushl.d32 -0xc(%ebx) 


					# EMU_01 : [addl $0x19c7, %ebx]
					# COMMENT: get_pc_thunk 바로뒤에 오는 add는 에뮬레이션만 해주되, NEWDISASM 로 바꾸지는 않는다.  --> COMMENT: 아냐. 바꿔야 해. 왜냐하면 get_pc_thunk에서 리턴하는 주소가 "원본바이너리에서의 주소"이므로 원본과 동일한오프셋으로 접근함으로서 크래시내야해.
					# COMMENT: 아냐,,, 바꾸지 말아야 해.. 왜냐하면 movl __progname(%ebx), %eax 와 같이 GOT relative하게 접근하는 뭔가가있을때, ebx는 GOT 여야하기 때문이야... 
					# COMMENT: 아! 그러면 바꾸고. 바꾸되, 레이지심볼화대상에 movl __progname(%ebx), %eax  를 추가하면되잖아?
					if p_add.match(DISASM) is not None: 
						if len(extract_hex_addr(DISASM)) > 0:
							ADD_VALUE = extract_hex_addr(DISASM)[0]
							REGLIST   = extract_register(DISASM)
							INSTRUCTION = DISASM.split(' ')[1]
							if REGLIST[0] in reg.keys(): # 좌측의 레지스터가 keep tracking 하는 레지스터라면, 
								reg[REGLIST[0]] += ADD_VALUE
								DESTINATION = reg[REGLIST[0]]
		
								print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
								slice_count += 1
								found_target = 0
								for target_section in resdic.keys():
									if DESTINATION in resdic[target_section].keys()  and target_section in AllSections_WRITE: # fortunatly, DESTINATION hits on current target
										if resdic[target_section][DESTINATION][0] == '': # symbol does not exist
											simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
											count += 1
											resdic[target_section][DESTINATION][0] = simbolname + ':'
										else:  # symbol exists already at there. 
											simbolname = resdic[target_section][DESTINATION][0][:-1]
										found_target = 1
										break
								if found_target == 1 and target_section in AllSections_WRITE: # lea PIE_MYSYM_01, %eax 으로 바꾼다. 
									INSTRUCTION = 'lea'
									NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[0]
									resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM
									print "       {}".format(NEWDISASM)
									# resdic[Sname][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군

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
							for target_section in resdic.keys():
								if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE:
									if resdic[target_section][DESTINATION][0] == '':
										simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else: 
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + simbolname
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM
								print "       {}".format(NEWDISASM)
								# resdic[Sname][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군

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
							for target_section in resdic.keys():
								if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE:
									if resdic[target_section][DESTINATION][0] == '':
										simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else:
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE:
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM	
								print "       {}".format(NEWDISASM)
								# resdic[Sname][SORTED_ADDRESS[i]][3] = 아, 소거되는 레지스터가 없군 COMMENT: GOT based 로다가 접근하는경우에 %ebx라는값이 중요한 역할을 함. 그래서 [3]에다가 저장하였따
								resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]



					elif p_sar.match(DISASM) is not None:
						REGLIST   = extract_register(DISASM)
						if REGLIST[0] in reg.keys(): del reg[REGLIST[0]] # reg deverts The Demension. Delete it. 

					elif p_xor.match(DISASM) is not None:
						REGLIST   = extract_register(DISASM)
						if REGLIST[0] == REGLIST[1]:
							reg[REGLIST[0]] = 0


					# EMU_02 : [lea -0xf4(%ebx),%esi] 
					elif p_lea.match(DISASM) is not None: 
						ADD_VALUE       = extract_hex_addr(DISASM)
						REGLIST         = extract_register(DISASM)
						INSTRUCTION = DISASM.split(' ')[1]
						if len(ADD_VALUE) == 0: ADD_VALUE = 0 # 걍 lea %ebx, %eax 일수도 있자나?
						else:ADD_VALUE = ADD_VALUE[0]
						
						if REGLIST[0] in reg.keys(): # 좌측의 레지스터가 keep tracking 하는 레지스터라면, 
							reg[REGLIST[1]] = reg[REGLIST[0]] + ADD_VALUE
							DESTINATION     = reg[REGLIST[0]] + ADD_VALUE  # 계산 결과는 꼭 "우측 레지스터값" 이 아닐수도 있음
							
							print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
							slice_count += 1
							found_target = 0
							for target_section in resdic.keys():
								if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE:
									if resdic[target_section][DESTINATION][0] == '':
										simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else:
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[1]
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM			
								resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]
								print "       {}... We momorize [{}]...".format(NEWDISASM, resdic[Sname][SORTED_ADDRESS[i]][3])


					elif p_mov.match(DISASM) is not None:
						ADD_VALUE = extract_hex_addr(DISASM)
						REGLIST = extract_register(DISASM)
						INSTRUCTION = DISASM.split(' ')[1]
						if len(ADD_VALUE) == 0: ADD_VALUE = 0
						else: ADD_VALUE = ADD_VALUE[0]

						if REGLIST[0] in reg.keys():
							DESTINATION     = reg[REGLIST[0]] + ADD_VALUE
							if REGLIST[1] in reg.keys(): del reg[REGLIST[1]] # Stop tracking... out of same DEMENTION

							print "[{}] {} : {} ---> (DEST:{})".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION))
							slice_count += 1
							found_target = 0
							for target_section in resdic.keys():
								if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE:
									if resdic[target_section][DESTINATION][0] == '':
										simbolname  = SYMPREFIX[0] + 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else: 
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[1] # TIP : movl 이 아니라, 원래있던 mov를 그대로 써줘야 함. 왜냐면 REGLIST[1] 이 1바이트짜리 레지스터일경우 movl인스트럭션을 감당못하기 때문
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM
								resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]
								print "       {}... We momorize [{}]...".format(NEWDISASM, resdic[Sname][SORTED_ADDRESS[i]][3])
				print ""





# leal.d32 -0x1334(%ebx), %edi // 이렇게 출처를 알수없는 ebx 나 edx 가 쓰일때는, if (GOT로 가정했을때) GOT-0x1334가 memory address에 fit 하면 --> 심볼라이즈, 아니라면 --> 안심볼라이즈 이렇게하자... 
def PIE_LazySymbolize_GOTbasedpointer(pcthunk_reglist, resdic,CHECKSEC_INFO):  
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

		SectionDic = resdic[Sname]  
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		
		'''
		[0]이위치의 원래이름: 
		[1] cmp $HEREIS_GLOBAL_OFFSET_TABLE_, %(레지스터)
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
			DISASM = SectionDic[SORTED_ADDRESS[i]][1]
			if p_lea.match(DISASM) is not None:
				# SETUP
				ADD_VALUE = extract_hex_addr(DISASM)[0]
				REGLIST = extract_register(DISASM)
				INSTRUCTION = DISASM.split(' ')[1]

				INSTRUCTION = 'lea' # 슬데없이 leaw 이따구로 디스어셈블하는 경우, leaw SYMBOLNAME, %eax 할때 truncate 되므로, 그냥 복잡 ㄴㄴ하게 lea로 바꾼다. 

				if REGLIST[0] in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
					DESTINATION = GOT_baseaddr + ADD_VALUE 
					for target_section in resdic.keys():
						if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE: # resdic 통틀어서 fit in 하는 memory addres가 있다면
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
							
							CODEBLOCK  = '\n'
							CODEBLOCK += '   pushf\n'
							CODEBLOCK += '   cmp $HEREIS_GLOBAL_OFFSET_TABLE_, %' + REGLIST[0] + '\n'
							CODEBLOCK += '   je ' + symbolname_yes + '\n'
							CODEBLOCK += '\n'
							CODEBLOCK += '   ' + symbolname_no + ':' + '\n'
							CODEBLOCK += '  ' + ORIDISASM + '\n'
							CODEBLOCK += '   popf\n'
							CODEBLOCK += '   jmp ' + symbolname_next + '\n'
							CODEBLOCK += '\n'
							CODEBLOCK += '   ' + symbolname_yes + ':' + '\n'
							CODEBLOCK += '  ' + NEWDISASM + '\n'
							CODEBLOCK += '   popf\n'
							CODEBLOCK += '   jmp ' + symbolname_next + '\n'
							CODEBLOCK += '\n'
							# 오케이. 프린트해보자 이제.
							resdic[Sname][SORTED_ADDRESS[i]][1] = CODEBLOCK
							resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]
							print "[0] {} : {} ---> (DEST:{}), eliminated : {}".format(hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION),resdic[Sname][SORTED_ADDRESS[i]][3])

			elif p_mov.match(DISASM) is not None:
				# SETUP
				ADD_VALUE = extract_hex_addr(DISASM)[0]
				REGLIST = extract_register(DISASM)
				INSTRUCTION = DISASM.split(' ')[1]

				INSTRUCTION = 'mov' # 슬데없이 movw 이따구로 디스어셈블하는 경우, movw SYMBOLNAME, %eax 할때 truncate 되므로, 그냥 복잡 ㄴㄴ하게 lea로 바꾼다. 

				if REGLIST[0] in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
					DESTINATION = GOT_baseaddr + ADD_VALUE
					for target_section in resdic.keys():
						if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE: # resdic 통틀어서 fit in 하는 memory addres가 있다면
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
							
							
							CODEBLOCK  = '\n'
							CODEBLOCK += '   pushf\n'
							CODEBLOCK += '   cmp $HEREIS_GLOBAL_OFFSET_TABLE_, %' + REGLIST[0] + '\n'
							CODEBLOCK += '   je ' + symbolname_yes + '\n'
							CODEBLOCK += '\n'
							CODEBLOCK += '   ' + symbolname_no + ':' + '\n'
							CODEBLOCK += '  ' + ORIDISASM + '\n'
							CODEBLOCK += '   popf\n'
							CODEBLOCK += '   jmp ' + symbolname_next + '\n'
							CODEBLOCK += '\n'
							CODEBLOCK += '   ' + symbolname_yes + ':' + '\n'
							CODEBLOCK += '  ' + NEWDISASM + '\n'
							CODEBLOCK += '   popf\n'
							CODEBLOCK += '   jmp ' + symbolname_next + '\n'
							CODEBLOCK += '\n'
							# 오케이. 프린트해보자 이제.
							resdic[Sname][SORTED_ADDRESS[i]][1] = CODEBLOCK
							resdic[Sname][SORTED_ADDRESS[i]][3] = REGLIST[0]
							print "[0] {} : {} ---> (DEST:{}), eliminated : {}".format(hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION),resdic[Sname][SORTED_ADDRESS[i]][3])
					
			# TODO: 아마도 백퍼센트 jmp 0x12(%ebx) call 0x12(%eax) 등등 처리안해줘서 문제생길것이다. 나중에 언젠가 regex들을 추가확장하자. 					
					


# pie 바이너리같은경우 .plt.got의 항이 jmp *0x12341234 이게아니라 jmp *0xc(%ebx) 이러케생겼따. 그러니깐 이걸 걍 계산해가지고 심볼화해주자.  
def PIE_LazySymbolize_GOTbasedpointer_pltgot(CHECKSEC_INFO, resdic):
	# The Ultimate REGEX!
	_ = '.*?'
	p_jmp   = re.compile(' jmp' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + '\(%' + _ + '\)') # jmpl.d32 *0xc(%ebx)

	# 이 함수를 필요로하지않는경우 걍리턴 ㄱㄱ
	if CHECKSEC_INFO.pie == False: return # PIE 아니면 이거돌릴필요X. 그만헤. (일반바이너리는 원래부터가 jmp *0x12341234 로 아주 straightforward함)
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
			DISASM = SectionDic[SORTED_ADDRESS[i]][1]
			if p_jmp.match(DISASM) is not None:
				# SETUP
				ADD_VALUE = extract_hex_addr(DISASM)[0]
				REGLIST = extract_register(DISASM)
				INSTRUCTION = DISASM.split(' ')[1]
				DESTINATION = GOT_baseaddr + ADD_VALUE 
	
				NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + str(hex(DESTINATION))
	
				print SectionDic[SORTED_ADDRESS[i]][1]
				print NEWDISASM
				print ''
	
				SectionDic[SORTED_ADDRESS[i]][1] = NEWDISASM
				SectionDic[SORTED_ADDRESS[i]][3] = REGLIST[0] # [3] 에다가 소거한 레지스터 저장해야겠따. 
			

			



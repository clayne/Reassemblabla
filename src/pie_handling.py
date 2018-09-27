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


def PIE_return_getpcthunk_loc(resdic):
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
				
# /bin/dash 안돌아가는거 왠지파악하기
def PIE_calculate_targetaddr(resdic):
	SectionName = CodeSections_WRITE # 최종적으로 추가되는 코드색션
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

					# reg[REGLIST[0]] != 0 이 조건 말고, 그냥 리스트에 더하거나 빼는걸로 가자~

					# EMU_01 : [addl $0x19c7, %ebx]
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
											simbolname  = 'MYSYM_PIE_' + str(count) 
											count += 1
											resdic[target_section][DESTINATION][0] = simbolname + ':'
										else:  # symbol exists already at there. 
											simbolname = resdic[target_section][DESTINATION][0][:-1]
										found_target = 1
										break
								if found_target == 1 and target_section in AllSections_WRITE: # lea PIE_MYSYM_01, %eax 으로 바꾼다. 
									NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[0]
									print "       {}".format(NEWDISASM)
									resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM

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
										simbolname  = 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else: 
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + simbolname
								print "       {}".format(NEWDISASM)
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM

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
										simbolname  = 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else:
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE:
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM	



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
										simbolname  = 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else:
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[1]
								print "       {}".format(NEWDISASM)
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM						



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
										simbolname  = 'MYSYM_PIE_' + str(count) 
										count += 1
										resdic[target_section][DESTINATION][0] = simbolname + ':'
									else: 
										simbolname = resdic[target_section][DESTINATION][0][:-1]
									found_target = 1
									break
							if found_target == 1 and target_section in AllSections_WRITE: # 가상 심볼이 아니라면, lea PIE_MYSYM_01, %eax 으로 바꾼다. 
								NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST[1] # TIP : movl 이 아니라, 원래있던 mov를 그대로 써줘야 함. 왜냐면 REGLIST[1] 이 1바이트짜리 레지스터일경우 movl인스트럭션을 감당못하기 때문
								print "       {}".format(NEWDISASM)
								resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM

				print ""

# leal.d32 -0x1334(%ebx), %edi // 이렇게 출처를 알수없는 ebx 나 edx 가 쓰일때는, if (GOT로 가정했을때) GOT-0x1334가 memory address에 fit 하면 --> 심볼라이즈, 아니라면 --> 안심볼라이즈 이렇게하자... 
# TODO: PIE_calculate_remainedpointer_HEURISTICALLY 이함수를 Getpcthunk 안에서 콜하는 대상이 되는 베이직블락 안에서도 유효값을가지는 레지스터들을 킵 트래킹하도록 수정하기 . ls 디스어셈블해보면 -1(%ebx), %eax 도 MYSYM_PIE_REMAIN_0 으로 심볼라이즈하고 난리났다 아주..
def PIE_calculate_remainedpointer_HEURISTICALLY(pcthunk_reglist, resdic):
	# The Ultimate REGEX!
	_ = '.*?'
	p_lea   = re.compile(' lea' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # leal.d32 -3(%ebx), %eax
	p_mov   = re.compile(' mov' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # movl.d32 -3(%ebx), %eax
	p_call  = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # calll.d32 *-0xf8(%ebx, %edi, 4)
	p_xor   = re.compile(' xor' + _ + '%' + _ + '%' + _)                                                      # xorl %edi, %edi
	p_push  = re.compile(' push' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                  # pushl.d32 -0xc(%ebx) 

	GOT_baseaddr = sorted(resdic['.got.plt'])[0] # gdb에서  _GLOBAL_OFFSET_TABLE 곳의 주소가 .got.plt 섹션의 시작주소임. 
	count = 0
	# 우선은 libstdbuf.so 에서 사용하는 패턴인 lea, mov 만 가지고 해보자. 
	# 우선은 쭉 트래킹해주는건 빼고, 걍 있는그대로 ebx-0x1234 의 위치만 계산해서 심볼라이즈해주는것까지만. 
	SectionName = CodeSections_WRITE
	print ""
	print ""
	print "pcthunk_reglist"
	print pcthunk_reglist
	print ""
	for Sname in SectionName:
		if Sname not in resdic.keys(): continue # 섹션이 없는경우에는 처리안해주고 걍 continue
		print "Sname : {}...".format(Sname)

		SectionDic = resdic[Sname]  
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		
		for i in xrange(len(SORTED_ADDRESS)):
			DISASM = SectionDic[SORTED_ADDRESS[i]][1]
			if p_lea.match(DISASM) is not None:
				# SETUP
				reg = DISASM[DISASM.index('(')+2:DISASM.index(')')]
				ADD_VALUE = extract_hex_addr(DISASM)[0]
				REGLIST = extract_register(DISASM)
				INSTRUCTION = DISASM.split(' ')[1]

				if reg in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
					DESTINATION = GOT_baseaddr + ADD_VALUE
					for target_section in resdic.keys():
						if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE: # resdic 통틀어서 fit in 하는 memory addres가 있다면# if target_section in DataSections_WRITE: # 그섹션이 바로 데이터섹션이오라면? (TODO: 데이터섹션만 ^알려지지않은 calculated code pointer^로 접근하는지 확인... 너무 휴리스틱한가??? )
							# 심볼라이즈 시작!!!
							print "++++++++++++"
							print reg
							print DISASM
							if resdic[target_section][DESTINATION][0] == '': 
								symbolname = 'MYSYM_PIE_REMAIN_' + str(count)
								count += 1
								resdic[target_section][DESTINATION][0] = symbolname + ':'
							else:
								symbolname = resdic[target_section][DESTINATION][0][:-1]
							NEWDISASM = ' ' + INSTRUCTION + ' ' + symbolname + ', ' + '%' + REGLIST[1]
							print "       {}".format(NEWDISASM)
							resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM
					print "++++++++++++\n"

			elif p_mov.match(DISASM) is not None:
				# SETUP
				reg = DISASM[DISASM.index('(')+2:DISASM.index(')')]
				ADD_VALUE = extract_hex_addr(DISASM)[0]
				REGLIST = extract_register(DISASM)
				INSTRUCTION = DISASM.split(' ')[1]

				if reg in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
					DESTINATION = GOT_baseaddr + ADD_VALUE
					for target_section in resdic.keys():
						if DESTINATION in resdic[target_section].keys() and target_section in AllSections_WRITE: # resdic 통틀어서 fit in 하는 memory addres가 있다면
							# 심볼라이즈 시작!!!
							print "++++++++++++"
							print reg
							print DISASM
							if resdic[target_section][DESTINATION][0] == '': 
								symbolname = 'MYSYM_PIE_REMAIN_' + str(count)
								count += 1
								resdic[target_section][DESTINATION][0] = symbolname + ':'
							else:
								symbolname = resdic[target_section][DESTINATION][0][:-1]
							NEWDISASM = ' ' + INSTRUCTION + ' ' + symbolname + ', ' + '%' + REGLIST[1]
							print "       {}".format(NEWDISASM)
							resdic[Sname][SORTED_ADDRESS[i]][1] = NEWDISASM
					print "++++++++++++\n"
					
					
					
#!/usr/bin/python
#-*- coding: utf-8 -*-
from binary2dic import *
from symbolize import *



def PIE_set_getpcthunk_loc(resdic):
	for SectionName in CodeSections_WRITE:
		if SectionName not in resdic.keys():
			continue

		SectionDic = resdic[SectionName]
		SORTED_ADDRESS = SectionDic.keys()
		SORTED_ADDRESS.sort()
		for i in xrange(len(SORTED_ADDRESS)):
			orig_i_list = pickpick_idx_of_orig_disasm(SectionDic[SORTED_ADDRESS[i]][1])
			if len(orig_i_list) is 0 : 
				continue 
			orig_i = orig_i_list[0] # TODO: 대충 처음나오는얘가 원래바이너리의원래주소겠거니 하고 [0]으로 해준거.. 오류나면 고칠 것
			DISASM = SectionDic[SORTED_ADDRESS[i]][1][orig_i]
			if '__x86.get_pc_thunk' in DISASM:
				EIP = str(SORTED_ADDRESS[i+1])
				SectionDic[SORTED_ADDRESS[i]][3] = EIP 


# emulation
def emulation(resdic, testingcrashhandler):
	count = 0
	symbolizebyemulation = 0

	for sectionName_1 in CodeSections_WRITE:
		if sectionName_1 not in resdic.keys(): 
			continue # 섹션이 없는경우
		print "sectionName_1 : {}...".format(sectionName_1)
		
		SORTED_ADDRESS = resdic[sectionName_1].keys()
		SORTED_ADDRESS.sort()
		i = -1
		while i < len(SORTED_ADDRESS) - 1:
			i += 1 
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i]][1])
			for orig_i in orig_i_list:
				DISASM = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_i]
				if '__x86.get_pc_thunk' in DISASM:
					# <<<<<에뮬레이션에 필요한 여러가지 값들을 셋팅한다.>>>>> 
					slice_count = 0
					reg = {} # 레지스터 에뮬레이션 준비 
					REG_STHX = DISASM[DISASM.index('get_pc_thunk.') + len('get_pc_thunk.'):]
					REG_STHX = REG_STHX[REG_STHX.index('.')+1:]
					REG_STHX = 'e' + REG_STHX
					BASE = int(resdic[sectionName_1][SORTED_ADDRESS[i]][3]) # == EIP
					reg[REG_STHX] = BASE
					print "╭───────────────────────────────────────────────────────────────────────────────────────────────────────────╮"
					print "│ [{}] {} : {}".format(slice_count,hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + "---{}---> {} [[[START]]]".format(REG_STHX,hex(reg[REG_STHX])).ljust(40) + '│'
					slice_count += 1
					symbolizebyemulation += 1
					stepSlice = 'keep going'

					while 1: # 코드 슬라이싱 시작	 
						if 'stop slicing' in stepSlice : 
							break
						elif 'new start of slicing' in stepSlice: # 만약 뒤의 어디에선가 call get_pc_thunk 때문에 슬라이싱이 중단된 상태라면, 여기서부터 다시 시작되므로, 셋팅과정이 필요.
							# <<<<<에뮬레이션에 필요한 여러가지 값들을 셋팅한다.>>>>> 
							slice_count = 0
							reg = {} # 레지스터 에뮬레이션 준비
							REG_STHX = DISASM[DISASM.index('get_pc_thunk.') + len('get_pc_thunk.'):]
							REG_STHX = REG_STHX[REG_STHX.index('.')+1:]
							REG_STHX = 'e' + REG_STHX
							BASE = int(resdic[sectionName_1][SORTED_ADDRESS[i]][3]) # == EIP
							reg[REG_STHX] = BASE
							print "╭───────────────────────────────────────────────────────────────────────────────────────────────────────────╮"
							print "│ [{}] {} : {}".format(slice_count,hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + "---{}---> {} [[[START]]]".format(REG_STHX,hex(reg[REG_STHX])).ljust(40) + '│'
							slice_count += 1
							symbolizebyemulation += 1
							stepSlice = 'keep going' # 셋팅 다해주고는 플래그를 다시 바꿔준다.

						i += 1 # 다음 인스트럭션 처리로 넘어간다
						if i >= len(SORTED_ADDRESS): 
							break # DISASM 을 설정하기위한 최소한의조건 충족안되면 break

						orig_j_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i]][1])

						for orig_j in orig_j_list: # TODO: 뭔가이거 나중에 문제될것으로 보인다. 문제발생시 그때 패치해줄 것. (왜냐면 orig_j에 대해서 모두 에뮬레이션을 해주는데, 레지스터값을 전역변수로 재활용하고 있다.)
							DISASM = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j]
							# 코드슬라이싱을 끝내는 조건. (베이직블락 끝나면 break)
							if 'ret' in DISASM: 
								stepSlice = 'stop slicing'
								break
							if 'get_pc_thunk' in DISASM: 
								stepSlice = 'new start of slicing'
								break 
							if DISASM.startswith(' j'): # 브랜치의 경우, 바로 코드슬라이싱을 끝내버리면 jmp *%eax <- 이거심볼화 안된다. 우선 jmp까지 처리는 해주고 break을 해주도록 함 
								stepSlice = 'this is last slice. after process it, stop slicing'
								# break
							if DISASM.startswith(' call'):
								stepSlice = 'this is last slice. after process it, stop slicing'
								# break

							_pass = 'no'
							for _segmentinstruction in segmentinstr: # 세그먼트 레지스터 관련한 인스트럭션이라면 심볼화하지 않는다.
								if DISASM.startswith(_segmentinstruction) or DISASM.startswith(' '+_segmentinstruction):
									_pass = 'yes' # 다음 DISASM 처리로 넘어간다
							if _pass is 'yes':
								continue

							hit_pattern = 'NO'

							# 크래시핸들러 기반 디자인이 아닐 경우에만 get_pc_thunk 이후의 add $0x1234, %eax 는 add $_GLOBAL_OFFSET_TABLE_, %eax 으로 바꿔준다.  
							if p_add.match(DISASM) and slice_count == 1: # TODO: 이거 get_pc_thunk 바로 뒤에 오는 add일때에만 _GLOBAL_OFFSET_TABLE_ 으로 바꾸어 주어야 한다. 근데 패치하기위한 최소코드 꼼수가 생각안나서 우선 보류함
								if hit_pattern == 'HIT': 
									break 
								HEX_VALUE       = extract_hex_values(DISASM)
								REGLIST         = classificate_registers(DISASM)
								INSTRUCTION 	= DISASM.split(' ')[1]

								if REGLIST['ORDINARY_REGISTER'][0] in reg.keys():
									reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + HEX_VALUE[0] # 에뮬레이션
								if testingcrashhandler is True: 
									NEWDISASM = DISASM # Preserve this adding offset
								else: # --testing 옵션이 없을 경우, add 하는 imm 을 $_GLOBAL_OFFSET_TABLE_ 으로 바꿈으로써 크래시를 방지한다. (...이럴경우 크래시는 안나지만, 반만 심볼화된다는 문제가 있음)
									NEWDISASM = ' ' + INSTRUCTION + ' ' + '$_GLOBAL_OFFSET_TABLE_' + ', ' + '%' + REGLIST['ORDINARY_REGISTER'][0] 
									resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
								
								print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]), DISASM).ljust(70) + "--------->{}".format(NEWDISASM).ljust(40) + '│'
								slice_count += 1
								symbolizebyemulation += 1
								continue # 처리끝. 다음 DISASM 처리로 넘어간다. 

							for pattern in p_PATTERN_01: # 인스트럭션 + REG + REGREF  // mov %eax, -3(%ebx)
								if hit_pattern == 'HIT': # 이미한번 HIT되어 처리가 완료된상태
									break
								if pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]

									alchemist_said = 'yes' # 레지스터들을 하나의 값으로 연금술할수가 있다.  # 만약 레퍼런스에 사용되는 모든 레지스터(ex, -0x3(%ebx) / 0x12(%eax, %ebx, 4) 에서 사용되는 레지스터)가 keep tracking 하는 레지스터라면, 
									for _r in REGLIST['REFERENCE_REGISTER']:
										if _r not in reg.keys(): # 메모리 레퍼런스로써 사용된 레지스터가 keep tracking 하는 레지스터라면, 연금술사는 yes라고 말할것이다. 
											alchemist_said = 'no'

									if alchemist_said is 'yes':
										# [01] Destination 값을 설정한다 
										if   len(HEX_VALUE) is 0 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type1) lea (%ebx), %eax
											DESTINATION  = reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type2) lea 12(%ebx), %eax
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type3) lea 0(%eax,%ebx,), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type4) lea 0(,%ebx,4), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] * HEX_VALUE[1]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type5) lea 0(%eax,%ebx,4), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]] * HEX_VALUE[1]

										# [02] 전파되는 레지스터값들을 설정한다(에뮬레이션을 위함). 
										if DISASM.startswith(' adc'): # R/M32 메모리에들어있는값을 [차원변경] 읽어와서, register의 값에다가 그 읽어온값을 더한다. 그러므로 트래킹 제외. 
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' add'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' and'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' btc'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' btr'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bts'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bt'): 
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' cmpxchg'): # 뭐 비교를해가지고 1st operand/2nd operand 를 %eax 에 로드한다. 따라서 %eax 트래킹 중단 
											#01. 전파값 셋팅
											if 'eax' in reg.keys(): 
												del reg['eax']
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' cmp'): # cmpxchg 이후에 비교해줄 것
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' mov'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' or'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sbb'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sub'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' test'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xadd'): # exchange and add. 1st operand와 2nd operand를 우선은 바꾸고나서, add결과를 메모리에다가 기록. 
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xchg'):
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xor'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'

										# 심볼라이즈 
										print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + ".......... Destination is {}".format(hex(DESTINATION)).ljust(40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
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
											NEWDISASM = ' ' + INSTRUCTION + ' ' + '%' + REGLIST['ORDINARY_REGISTER'][0] + ', ' + simbolname 
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST['REFERENCE_REGISTER'] # TODO: 나중에 이부분 패치할 것(이거 원래 레지스터 하나인시절에 구현했는데, "리스트" 로 바뀌면서 형식이 바뀜)
											print "│                 {}".format(NEWDISASM).ljust(70) + ".......... memorizing {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(40) + '│'


							for pattern in p_PATTERN_01R: # 인스트럭션 + REGISTER + REGISTER  // mov %eax, %ebx
								if hit_pattern == 'HIT':
									break

								if there_is_memory_reference(DISASM) is False and pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									
									alchemist_said = 'yes' # p_PATTERN_02R 경우에는 왼쪽의 레지스터값을 오른쪽에 셋팅하는경우도 있다. 그래서 모든레지스터가아니라 왼쪽레지스터만 keep tracking 하는 경우도 우선 에뮬레이션 시작가능하게 한다.
									if REGLIST['ORDINARY_REGISTER'][0] in reg.keys():
										alchemist_said = alchemist_said + ', left'
									if REGLIST['ORDINARY_REGISTER'][1] in reg.keys():
										alchemist_said = alchemist_said + ', right'
									if alchemist_said == 'yes': # 아무것도 안붙고... 디폴트값 그대로인경우는 둘다 트래킹안한다는 소리다. 
										alchemist_said = 'no'

									if 'yes' in alchemist_said:
										if DISASM.startswith(' btc'): # TODO: 이거 캐리무시하고 마치 add 랑 동일하게 처리했다. (그러케해주면 안댐. lazy symbolization 으로 처리할 수 있을것 같음.) 나중에 패치 ㄱㄱ 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = bitflip_the_index(reg[REGLIST['ORDINARY_REGISTER'][0]], reg[REGLIST['ORDINARY_REGISTER'][1]])
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단. 
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' btr'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = bitreset_the_index(reg[REGLIST['ORDINARY_REGISTER'][0]], reg[REGLIST['ORDINARY_REGISTER'][1]])
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단. 
											#02. suffix 셋팅
										elif DISASM.startswith(' bts'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = bitset_the_index(reg[REGLIST['ORDINARY_REGISTER'][0]], reg[REGLIST['ORDINARY_REGISTER'][1]])
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단. 
											#02. suffix 셋팅
										elif DISASM.startswith(' bt'):
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' cmpxchg'): #reg0이 작은딸, reg1가 큰딸. 0살1살 나이임ㅎ. eax가 현재 왕임. 현재왕이 큰딸이였다면, 큰딸자리에다가 작은딸을앉혀라(즉 레지스터두개다 작은딸). 현재왕이 작은딸이라면? 위험하고 잘못된상황 이므로 큰딸을 왕위에앉혀라(레지스터딸들은 그대로). 현재왕이 제3자라면 큰딸을 왕위에앉혀라.(레지스터딸들은 그대로)  
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												if 'eax' in reg.keys():
													king 		  = reg['eax']
													bigdaughter   = reg[REGLIST['ORDINARY_REGISTER'][1]]
													smalldaughter = reg[REGLIST['ORDINARY_REGISTER'][0]]
													if king == bigdaughter:
														reg[REGLIST['ORDINARY_REGISTER'][1]] = smalldaughter
													elif king == smalldaughter:
														reg['eax'] = bigdaughter
													else: # 왕위를 제3자가 하고잇따?
														reg['eax'] = bigdaughter
											#02. suffix 셋팅
										elif DISASM.startswith(' test'):
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' xadd'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												addresult = (reg[REGLIST['ORDINARY_REGISTER'][0]] + reg[REGLIST['ORDINARY_REGISTER'][1]])%0x100000000
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][1]]
												reg[REGLIST['ORDINARY_REGISTER'][1]] = addresult
										print "│ [{}] {} : {} ".format(slice_count, hex(SORTED_ADDRESS[i]), DISASM).ljust(40) + '│'
										for _r in reg.keys():
											print "│ {} : ".format(_r).rjust(70, ' ') + "{}".format(hex(reg[_r])).ljust(40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
										found_target = 0
									


							for pattern in p_PATTERN_02: # 인스트럭션 + REGREEF + REG // lea -3(%ebx), %eax
								if hit_pattern == 'HIT':
									break
								if pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									alchemist_said = 'yes' # 레지스터들을 하나의 값으로 연금술할수가 있다. 만약 레퍼런스에 사용되는 모든 레지스터(ex, -0x3(%ebx) / 0x12(%eax, %ebx, 4) 에서 사용되는 레지스터)가 keep tracking 하는 레지스터라면, 
									for _r in REGLIST['REFERENCE_REGISTER']:
										if _r not in reg.keys(): # 메모리 레퍼런스로써 사용된 레지스터가 keep tracking 하는 레지스터라면, 연금술사는 yes라고 말할것이다. 
											alchemist_said = 'no'
									
									if alchemist_said is 'yes':
										# [01]. Destination 값을 설정한다 
										if   len(HEX_VALUE) is 0 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type1) lea (%ebx), %eax
											DESTINATION  = reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type2) lea 12(%ebx), %eax
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type3) lea 0(%eax,%ebx,), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type4) lea 0(,%ebx,4), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] * HEX_VALUE[1]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type5) lea 0(%eax,%ebx,4), %ebx
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]] * HEX_VALUE[1]


										# [02]. 전파되는 레지스터값들을 설정한다(에뮬레이션을 위함). 
										if DISASM.startswith(' adc'): # R/M32 메모리에들어있는값을 [차원변경] 읽어와서, register의 값에다가 그 읽어온값을 더한다. 그러므로 트래킹 제외. 
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' add'):
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' and'):
											#01. 전파값 셋팅
											'Nothing to do' # carry flag 빼고는 달라지는레지스터가 없다
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bsf'): # 메모리안에 들어있는값이 0이라면 2nd operand의 레지스터값 유지, 아니라면 0으로만듦(?).. 근데 "content of the destination operand is undefined." 라는걸로바서 예측불가능한 값인것 같다.
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bsr'): # bsf와 마찬가지
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' cmov'): # cmova, cmovae, cmovb, cmovbe, cmovc, cmove, cmovg, cmovge, cmovl, cmovle, cmovna, cmovnae, cmovnb, cmovnbe, cmovnc, ... 한번에 핸들링
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' cmp'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' imul'): # destination 레지스터에는 multiply 된 값이 저장된다. 
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' lar'): # lar(load access right) access right 를 ZF에다가 load 한다. The processor performs access checks as part of the loading process. 
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' lsl'): # load segment limit. 그러고나서 ZF를 셋팅한다.
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' mov'):  
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] 
											#02. suffix 셋팅
										elif DISASM.startswith(' or'): 
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] # or 결과가 레지스터에 기록된다. 해당 레지스터 트래킹 중단.
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sbb'): # sub with burrow(?) sub긴 sub인데 뭐 캐리를 반영한다고함. 중요한건 sub결과가 레지스터에 적용되므로 트래킹 중단.
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] 
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sub'):
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] 
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xchg'): # xchg WRITABLE, %ebx 두 값을 바꿈. 
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] 
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xor'): # xor 결과가 레지스터에 기록됨
											#01. 전파값 셋팅
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										 		del reg[REGLIST['ORDINARY_REGISTER'][0]] 
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' lea'): # lea 는 SOURCE의 값이 그대로 DEST에다가 옮겨감 
											#01. 전파값 셋팅
											reg[REGLIST['ORDINARY_REGISTER'][0]] = DESTINATION 
											#02. suffix 셋팅
										
										
										# SOURCE OPERAND 를 심볼라이즈 
										print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + ".......... Destination is {}".format(hex(DESTINATION)).ljust(40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
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
											NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname + ', ' + '%' + REGLIST['ORDINARY_REGISTER'][0]
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST['REFERENCE_REGISTER'] # TODO: 위와 마찬가지로 [3]에 적히는 값이 리스트이므로 추후에 이쁘게 적히도록 바꿔줄것
											print "│                 {}".format(NEWDISASM).ljust(70) + ".......... memorizing {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(40) + '│'
									


							for pattern in p_PATTERN_02R: # 인스트럭션 + REGISTER + REGISTER  // mov %eax, %ebx
								if hit_pattern == 'HIT':
									break

								if there_is_memory_reference(DISASM) is False and pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									
									alchemist_said = 'yes' # p_PATTERN_02R 경우에는 왼쪽의 레지스터값을 오른쪽에 셋팅하는경우도 있다. 그래서 모든레지스터가아니라 왼쪽레지스터만 keep tracking 하는 경우도 우선 에뮬레이션 시작하도록 한다.
									if REGLIST['ORDINARY_REGISTER'][0] in reg.keys():
										alchemist_said = alchemist_said + ', left'
									if REGLIST['ORDINARY_REGISTER'][1] in reg.keys():
										alchemist_said = alchemist_said + ', right'

									if 'yes' in alchemist_said:
										if DISASM.startswith(' adc'): # TODO: 이거 캐리 무시하고 마치 add 랑 동일한것처럼 처리함.
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + reg[REGLIST['ORDINARY_REGISTER'][1]]
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단. 괴상한 예측불가한값을갖다가 더해놨으니깐.
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' add'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + reg[REGLIST['ORDINARY_REGISTER'][1]]
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단. 괴상한 예측불가한값을갖다가 더해놨으니깐.
											#02. suffix 셋팅
										elif DISASM.startswith(' and'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] & reg[REGLIST['ORDINARY_REGISTER'][1]])
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' bsf'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = bitscan(reg[REGLIST['ORDINARY_REGISTER'][0]], 'left')
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' bsr'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = bitscan(reg[REGLIST['ORDINARY_REGISTER'][0]], 'right')
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' cmov'): # TODO: 조건에 따른 cmov인데(CF=0 and ZF=0 / SF=OF 등등) 런타임값 모르자나?그러니깐 걍 마치 mov 와 동일하게 처리해줬다. 문제발생소지 있음.
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] 
											elif alchemist_said == 'yes, left': # 왼쪽만 트래킹중이면 mov 결과예측 가능 ㅎㅅㅎ
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] 
											elif alchemist_said == 'yes, right': 
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' cmp'): 
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' imul'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												reg[REGLIST['ORDINARY_REGISTER'][1]] = int(reg[REGLIST['ORDINARY_REGISTER'][1]] * reg[REGLIST['ORDINARY_REGISTER'][0]]) % 0x100000000
											elif alchemist_said == 'yes, right': 
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' lar'): # TODO: 이거 위에있는것들도 다 ZF만 바꾸는 nop instruction인줄알고 잘못핸들링햇엇음. 사실은 뭔가가 더 달라지는 인스트럭션인데 잘 모르겟다 우선 쓰루함
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' lsl'): # 얘도.
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' mov'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] 
											elif alchemist_said == 'yes, left': # 왼쪽만 트래킹중이면 mov 결과예측 가능하다.
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]] 
											elif alchemist_said == 'yes, right': 
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' or'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] | reg[REGLIST['ORDINARY_REGISTER'][1]])
											#02. suffix 셋팅
										elif DISASM.startswith(' sbb'): #TODO:subtraction with Borrow...Borrow는 버로우함 ㅎㅅㅎ
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][1]] - reg[REGLIST['ORDINARY_REGISTER'][0]]
											elif alchemist_said == 'yes, right': 
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' sub'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right': 
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][1]] - reg[REGLIST['ORDINARY_REGISTER'][0]]
											elif alchemist_said == 'yes, right': 
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' xchg'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												_tmp_exchange = reg[REGLIST['ORDINARY_REGISTER'][1]]
												reg[REGLIST['ORDINARY_REGISTER'][1]] = reg[REGLIST['ORDINARY_REGISTER'][0]]
												reg[REGLIST['ORDINARY_REGISTER'][0]] = _tmp_exchange
											elif alchemist_said == 'yes, left':
												del reg[REGLIST['ORDINARY_REGISTER'][0]] # 트래킹 중단
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											#02. suffix 셋팅
										elif DISASM.startswith(' xor'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, left, right':
												reg[REGLIST['ORDINARY_REGISTER'][1]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] ^ reg[REGLIST['ORDINARY_REGISTER'][1]])
											elif alchemist_said == 'yes, right':
												del reg[REGLIST['ORDINARY_REGISTER'][1]] # 트래킹 중단
											# 만약에 alchemist_said 가 디폴트상태(레지스터 둘다 트래킹을 안하는 상태이더라도)
											if REGLIST['ORDINARY_REGISTER'][0] == REGLIST['ORDINARY_REGISTER'][1]: # 만약 두개의 레지스터가 모두 트래킹을안해주는 상태라고 하더라도
												reg[REGLIST['ORDINARY_REGISTER'][1]] = 0
												alchemist_said = 'yes, left, right' # 아래에서 slice_count +1 해주도록할려구... 이름을이렇게 바꿔줌

											#02. suffix 셋팅
											'nothing to do'
										if alchemist_said == 'yes, left, right' or alchemist_said == 'yes, right':
											print "│ [{}] {} : {} ".format(slice_count, hex(SORTED_ADDRESS[i]), DISASM).ljust(40) + '│'
											for _r in reg.keys():
												print "│ {} : ".format(_r).rjust(70, ' ') + "{}".format(hex(reg[_r])).ljust(40) + '│'
											slice_count += 1
											symbolizebyemulation += 1
										
										found_target = 0



							for pattern in p_PATTERN_03: # 인스트럭션 + IMM + REGREF  // mov $0x1000, -3(%ebx)
								if hit_pattern == 'HIT':
									break

								if pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]

									alchemist_said = 'yes' # 레지스터들을 하나의 값으로 연금술할수가 있다.(레퍼런스에 사용되는 모든 레지스터가 keep tracking 하는 레지스터라면)
									for _r in REGLIST['REFERENCE_REGISTER']:
										if _r not in reg.keys(): # 메모리 레퍼런스로써 사용된 레지스터가 keep tracking 하는 레지스터라면, 연금술사는 yes라고 말할것이다. 
											alchemist_said = 'no'

									if alchemist_said is 'yes':
										# 11111. Destination 값을 설정한다 
										if   len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type1) mov $0x12, (%eax)
											DESTINATION  = reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type2) mov $0x12, 12(%ebx)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type3) mov $0x12,  0(%eax,%ebx,)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]]

										elif len(HEX_VALUE) is 3 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type4) mov $0x12, lea 0(,%ebx,4)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] * HEX_VALUE[2]

										elif len(HEX_VALUE) is 3 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type5) mov $0x12,  0(%eax,%ebx,4)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]] * HEX_VALUE[2]


										# [02]. 전파되는 레지스터값들을 설정한다(에뮬레이션을 위함). 
										if DISASM.startswith(' adc'): 
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' add'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' and'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' btc'):  # bit test. CF 플래그 셋팅. 
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' btr'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bts'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' bt'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' cmp'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' mov'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' or'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' rcr'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' rol'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' ror'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sal'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sar'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' shl'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' shr'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sbb'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' sub'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' test'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' xor'):
											#01. 전파값 셋팅
											'Nothing to do'
											#02. suffix 셋팅
											'Nothing to do'


										print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + ".......... Destination is {}".format(hex(DESTINATION)).ljust(40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
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
											NEWDISASM = ' ' + INSTRUCTION + ' ' + '$' + str(hex(IMM_VALUE)) + ', ' + simbolname # TODO:check it
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST['REFERENCE_REGISTER'] # TODO: 위와 동일한 문제.
											print "│                 {}".format(NEWDISASM).ljust(70) + ".......... memorizing {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(40) + '│'



							for pattern in p_PATTERN_03R: # 인스트럭션 + IMM + REGISTER  // mov $0x1000, %ebx
								if hit_pattern == 'HIT':
									break

								if there_is_memory_reference(DISASM) is False and pattern.match(DISASM) is not None:
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									IMM_VALUE   = HEX_VALUE[0]
									alchemist_said = 'yes' # 우선 디폴트로 yes임. 왜냐면 IMM값이 레지스터로다가 들어갈수도 있기때문 
									if  REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										alchemist_said = 'yes, right'

									if 'yes' in alchemist_said:
										# [01]. Destination 값을 설정한다 
										if   len(HEX_VALUE) is 0 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type1) call (%eax)
											DESTINATION  = reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type2) call 12(%ebx)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type3) call  0(%eax,%ebx,)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type4) call lea 0(,%ebx,4)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] * HEX_VALUE[2]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type5) call  0(%eax,%ebx,4)
											DESTINATION  = HEX_VALUE[1] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]] * HEX_VALUE[2]



										# [02]. 전파되는 레지스터값들을 설정한다(에뮬레이션을 위함). 
										if DISASM.startswith(' adc'): # (add with carry flag. CF가 설정되어있는 경우 결과값은 1을 더 더해줌.) TODO: 이거 add랑 마치 똑같은거인것처럼 처리했다. 문제발생소지 있음.
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + IMM_VALUE
											#02. suffix 셋팅
											'Nothing to do'
										elif DISASM.startswith(' add'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + IMM_VALUE
											#02. suffix 셋팅
										elif DISASM.startswith(' and'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] & IMM_VALUE)
											#02. suffix 셋팅
										elif DISASM.startswith(' btc'): # bit test and compliment. CF 는 내가 상관해줄거가 아니고.
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitflip_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]])
											#02. suffix 셋팅
										elif DISASM.startswith(' btr'): # bit test and reset
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitreset_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]])
											#02. suffix 셋팅
										elif DISASM.startswith(' bts'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitset_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]])
											#02. suffix 셋팅
										elif DISASM.startswith(' bt'):
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' cmp'):
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' mov'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = IMM_VALUE
											elif alchemist_said == 'yes':
												alchemist_said = 'yes, right' # 이제는 트래킹을 해주는거니깐. 
												reg[REGLIST['ORDINARY_REGISTER'][0]] = IMM_VALUE
											#02. suffix 셋팅
										elif DISASM.startswith(' or'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] | IMM_VALUE)
											#02. suffix 셋팅
										elif DISASM.startswith(' ror'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitrotate_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right')
											#02. suffix 셋팅
										elif DISASM.startswith(' rol'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitrotate_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left')
											#02. suffix 셋팅
										elif DISASM.startswith(' rcr'): # TODO: 사실은 이거 캐리 고려해가지고 설계해야하는데, static하게 CF플래그를 알수가없서서 걍 ror하고 동일하게 처리함. 문제발생소지 있음.
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right': 
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitrotate_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right')
											#02. suffix 셋팅
										elif DISASM.startswith(' rcl'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitrotate_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left')
											#02. suffix 셋팅
										elif DISASM.startswith(' sal'): # bitshift_arithmetic_the_index인줄알았는데에... shl 하고 synonym 이라고함. 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left') 
											#02. suffix 셋팅
										elif DISASM.startswith(' sar'): 
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_arithmetic_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right') 
											#02. suffix 셋팅
										elif DISASM.startswith(' shl'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left') 
											#02. suffix 셋팅
										elif DISASM.startswith(' shr'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(IMM_VALUE, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right') 
											#02. suffix 셋팅
										elif DISASM.startswith(' sbb'): # 이것도 빼줄때 (IMM_VALUE+CF플래그값) 을 마이너스해줘야하는데... static하게 알수아 겂으므로 sub랑 동일하게 구현함
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] - IMM_VALUE
											#02. suffix 셋팅
										elif DISASM.startswith(' sub'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] - IMM_VALUE
											#02. suffix 셋팅
										elif DISASM.startswith(' test'):
											#01. 전파값 셋팅
											'nothing to do'
											#02. suffix 셋팅
										elif DISASM.startswith(' xor'):
											#01. 전파값 셋팅
											if alchemist_said == 'yes, right':
												reg[REGLIST['ORDINARY_REGISTER'][0]] = int(reg[REGLIST['ORDINARY_REGISTER'][0]] ^ IMM_VALUE)
											#02. suffix 셋팅

										#03. 공통적으로 DESTINATION 셋팅 
										if alchemist_said == 'yes, right': 
											DESTINATION = reg[REGLIST['ORDINARY_REGISTER'][0]]

											# lea MYSYM, %eax 이런식으로 수정해줌.
											print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + ".......... Destination is {}".format(hex(DESTINATION)).ljust(40) + '│'
											slice_count += 1
											symbolizebyemulation += 1
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
											if found_target == 1 and sectionName_2 in AllSections_WRITE: # lea PIE_MYSYM_01, %eax 으로 바꾼다.
												#COMMENT: IMM과의 연산결과의 어떤 헥스값이... 100% 메모리주소라고 확신할 수 없으므로... 우선은 비활성화해줌.
												#NEWDISASM = ' lea' + ' ' +  simbolname + ', ' + '%' + REGLIST['ORDINARY_REGISTER'][0] # ---
												NEWDISASM = DISASM # +++
												resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
												print "│--------------> {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j]).ljust(110) + '│'


							for pattern in p_PATTERN_04: # 인스트럭션 + REGREF // call 0x12(%eax, %ebx, 4)
								if hit_pattern == 'HIT':
									break

								if one_operand_instruction(DISASM) is True and there_is_memory_reference(DISASM) is True and pattern.match(DISASM) is not None: 
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									found_memory_reference = 0
									alchemist_said = 'yes' 

									for _r in REGLIST['REFERENCE_REGISTER']:
										if _r not in reg.keys(): # 메모리 레퍼런스로써 사용된 레지스터가 keep tracking 하는 레지스터라면, 연금술사는 yes라고 말할것이다. 
											alchemist_said = 'no'

									if alchemist_said is 'yes':
										# 11111. Destination 값을 설정한다 
										if   len(HEX_VALUE) is 0 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type1) call (%ebx)
											DESTINATION  = reg[REGLIST['REFERENCE_REGISTER'][0]]
										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type2) call 12(%ebx)
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]]

										elif len(HEX_VALUE) is 1 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type3) call 0(%eax,%ebx,)
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 1: # type4) call 0(,%ebx,4)
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] * HEX_VALUE[1]

										elif len(HEX_VALUE) is 2 and len(REGLIST['REFERENCE_REGISTER']) is 2: # type5) call 0(%eax,%ebx,4)
											DESTINATION  = HEX_VALUE[0] + reg[REGLIST['REFERENCE_REGISTER'][0]] + reg[REGLIST['REFERENCE_REGISTER'][1]] * HEX_VALUE[1]

										# [02]. 인스트럭션결과 레지스터값이 바뀌거나/다른레지스터값들이 셋팅되는경우가 있다면 트래킹해준다. 
										if DISASM.startswith(' call'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' dec'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' div'):# EAX = 몫, EDX = 나머지. 레지스터값 달라짐. 
											#01. 전파값 셋팅 
											if 'eax' in reg.keys(): 
												del reg['eax'] 
											if 'edx' in reg.keys():
												del reg['edx'] 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' idiv'):# EAX = 몫, EDX = 나머지. 레지스터값 달라짐. 
											#01. 전파값 셋팅
											if 'eax' in reg.keys(): 
												del reg['eax'] 
											if 'edx' in reg.keys():
												del reg['edx']  
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' imul'): # EDX:EAX 곱셈결과가 여기에 저장됨. 레지스터값 달라짐.
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' inc'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' j'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' mul'): # EDX:EAX 곱셈결과가 여기에 저장됨. 레지스터값 달라짐.
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' neg'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' not'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' pop'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' push'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' sal'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' sar'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' shl'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif  DISASM.startswith(' shr'):
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'

										# 심볼라이즈 
										print "│ [{}] {} : {}".format(slice_count, hex(SORTED_ADDRESS[i]),DISASM).ljust(70) + ".......... Destination is {}".format(hex(DESTINATION)).ljust(40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
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
										if found_target == 1 and sectionName_2 in AllSections_WRITE: # 가상 심볼이 아니라면, 심볼화해준다.  
											if DISASM.startswith(' j') or DISASM.startswith(' call'): # branch instruction 에서는 메모리참조를 좀 이상하케 표현해준다. (https://blog.naver.com/eternalklaus/221447661076) 
												NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + simbolname
											else:
												NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname
											resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
											resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST['REFERENCE_REGISTER'] # TODO: 위와 동일
											print "│                 {}".format(NEWDISASM).ljust(70) + ".......... memorizing {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(40) + '│'

							for pattern in p_PATTERN_04R: # 인스트럭션 + REG // call %eax
								if hit_pattern == 'HIT':
									break

								if one_operand_instruction(DISASM) is True and there_is_memory_reference(DISASM) is False and pattern.match(DISASM) is not None: # TODO: regex 이쁘게 표현해주면 좋겠지만 어렵다..(예를들어 shl은 shl %eax, %eax도 가능하고 shl %eax도 가능함.)
									hit_pattern     = 'HIT'
									HEX_VALUE       = extract_hex_values(DISASM)
									REGLIST         = classificate_registers(DISASM)
									INSTRUCTION 	= DISASM.split(' ')[1]
									found_memory_reference = 0
									alchemist_said = 'no' 
									if  REGLIST['ORDINARY_REGISTER'][0] in reg.keys(): 
										alchemist_said = 'yes'

									if alchemist_said is 'yes':
										# [01]. Destination 값을 설정한다 
										DESTINATION = reg[REGLIST['ORDINARY_REGISTER'][0]] 

										# [02]. 인스트럭션결과 레지스터값이 바뀌거나/다른레지스터값들이 셋팅되는경우가 있다면 트래킹해준다. 
										if DISASM.startswith(' call'): # decrement by 1
											#01. 전파값 셋팅 
											found_memory_reference = 1
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' dec'): # decrement by 1
											#01. 전파값 셋팅 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] - 1
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' div'): # edx + eax / register -----> EAX = 몫, EDX = 나머지
											#01. 전파값 셋팅 
											if 'eax' in reg.keys() and 'edx' in reg.keys(): # dividend. (곧 몫이 됨)
												quotient, remainder = instruction_div(reg['edx'], reg['eax'], reg[REGLIST['ORDINARY_REGISTER'][0]])
												reg['eax'] = quotient
												reg['edx'] = remainder
											else: # 몫과 나머지를 예측할수가 없게된다...더이상 트래킹 불가!
												if 'eax' in reg.keys(): 
													del reg['eax'] 
												if 'edx' in reg.keys():
													del reg['edx'] 
											#02. suffix 셋팅 
											'Nothing to do'

										elif DISASM.startswith(' idiv'):
											#01. 전파값 셋팅 
											if 'edx' in reg.keys() and 'eax' in reg.keys(): 	    # 나뉨수정보가 있음
												quotient, remainder = instruction_idiv(reg['edx'], reg['eax'], reg[REGLIST['ORDINARY_REGISTER'][0]])
												reg['eax'] = quotient
												reg['edx'] = remainder
											else:
												if 'edx' in reg.keys():
													del reg['edx']
												if 'eax' in reg.keys():
													del reg['eax']
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' imul'): 
											#01. 전파값 셋팅 
											if 'eax' in reg.keys():
												leftpart, rightpart = instruction_imul(reg['eax'], reg[REGLIST['ORDINARY_REGISTER'][0]])
												reg['eax'] = rightpart
												reg['edx'] = leftpart
											#02. suffix 셋팅 
											'Nothing to do' 
										elif DISASM.startswith(' inc'): 
											#01. 전파값 셋팅 
											if reg[REGLIST['ORDINARY_REGISTER'][0]] == 0xffffffff:
												reg[REGLIST['ORDINARY_REGISTER'][0]] = 0
											else:
												reg[REGLIST['ORDINARY_REGISTER'][0]] = reg[REGLIST['ORDINARY_REGISTER'][0]] + 1
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' j'): 
											#01. 전파값 셋팅 
											found_memory_reference = 1
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' mul'): # eax * reg 결과는 eax와 edx에다가 저장
											#01. 전파값 셋팅 
											if 'eax' in reg.keys():
												leftpart, rightpart = instruction_mul(reg['eax'], reg[REGLIST['ORDINARY_REGISTER'][0]])
												reg['eax'] = rightpart
												reg['edx'] = leftpart
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' neg'): 
											#01. 전파값 셋팅 
											negtmp = unsigned2signed(reg[REGLIST['ORDINARY_REGISTER'][0]]) # 이제 부호가 생겼당...
											negtmp = negtmp * (-1)
											negtmp = signed2unsigned(negtmp)
											reg[REGLIST['ORDINARY_REGISTER'][0]] = negtmp
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' not'):
											#01. 전파값 셋팅 
											nottmp = signed2unsigned(reg[REGLIST['ORDINARY_REGISTER'][0]])
											nottmp = nottmp ^ 0xffffffff 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = nottmp
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' pop'): 
											#01. 전파값 셋팅 
											if REGLIST['ORDINARY_REGISTER'][0] in reg.keys():
												del reg[REGLIST['ORDINARY_REGISTER'][0]]
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' push'): 
											#01. 전파값 셋팅 
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' sal'): # 1번만 shift 
											#01. 전파값 셋팅 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(1, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left')
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' sar'): 
											#01. 전파값 셋팅 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_arithmetic_the_index(1, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right') 
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' shl'): 
											#01. 전파값 셋팅 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(1, reg[REGLIST['ORDINARY_REGISTER'][0]], 'left')
											#02. suffix 셋팅 
											'Nothing to do'
										elif DISASM.startswith(' shr'): 
											#01. 전파값 셋팅 
											reg[REGLIST['ORDINARY_REGISTER'][0]] = bitshift_the_index(1, reg[REGLIST['ORDINARY_REGISTER'][0]], 'right') 
											#02. suffix 셋팅 
											'Nothing to do'


										# 심볼라이즈 
										print "│ [{}] {} : {} ".format(slice_count, hex(SORTED_ADDRESS[i]), DISASM).ljust(70 + 40) + '│'
										for _r in reg.keys():
											print "│ {} : ".format(_r).rjust(70, ' ') + "{}".format(hex(reg[_r])).ljust(70+40) + '│'
										slice_count += 1
										symbolizebyemulation += 1
										found_target = 0

										if found_memory_reference == 1: 
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
												if INSTRUCTION.startswith('j'): # BUG: GAS ATT 디자인버그때문에 완성되는 인스트럭션이 jmpl main 이라면, jmpl *main 으로 잘못컴파일한다. jmp만 그럼. (https://blog.naver.com/eternalklaus/221452300591)
													INSTRUCTION = 'jmp'
												NEWDISASM = ' ' + INSTRUCTION + ' ' + simbolname

												resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] = NEWDISASM
												resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST['ORDINARY_REGISTER'] # TODO: 위와 동일
												print "│                 {}".format(NEWDISASM).ljust(70) + ".......... memorizing {}".format(resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(40) + '│'
										


						str_tracking_registers = ''
						if stepSlice is 'keep going': # 에뮬레이션중인 레지스터값 정보를 디스어셈블리 파일에도 프린트
							for _r in reg.keys():
								str_tracking_registers += '{}:{} / '.format(str(_r), str(hex(reg[_r])))
							resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_j] +=' # emulating... {}'.format(str_tracking_registers)

					print "╰───────────────────────────────────────────────────────────────────────────────────────────────────────────╯"
					print ""

	symbolize_counter("emulation : {}".format(symbolizebyemulation))

# emulation_got
def emulation_got(pcthunk_reglist, resdic, CHECKSEC_INFO):  
	# The Ultimate REGEX!
	symbolizebyemulation = 0
	_ = '.*?'
	p_lea   = re.compile(' lea' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # ex) leal.d32 -3(%ebx), %eax
	p_mov   = re.compile(' mov' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)          # ex) movl.d32 -3(%ebx), %eax
	p_call  = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # ex) calll.d32 *-0xf8(%ebx, %edi, 4)
	p_xor   = re.compile(' xor' + _ + '%' + _ + '%' + _)                                                      # ex) xorl %edi, %edi
	p_push  = re.compile(' push' + _ + ' ' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ )                  # ex) pushl.d32 -0xc(%ebx) 

	if CHECKSEC_INFO.relro == 'Full':
		GOT_baseaddr = sorted(resdic['.got'].keys())[0]
	else:
		GOT_baseaddr = sorted(resdic['.got.plt'].keys())[0]  

	count = 0 
	SectionName = CodeSections_WRITE
	for sectionName_1 in SectionName:
		if sectionName_1 not in resdic.keys(): 
			continue # 섹션이 없는경우
		print "sectionName_1 : {}...".format(sectionName_1)
		SORTED_ADDRESS = resdic[sectionName_1].keys()
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
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[sectionName_1][SORTED_ADDRESS[i]][1])

			for orig_i in orig_i_list:
				DISASM = resdic[sectionName_1][SORTED_ADDRESS[i]][1][orig_i]
				if '#' in DISASM:
					DISASM = DISASM[:DISASM.index('#')] # 주석 제거

				if p_lea.match(DISASM) is not None or p_mov.match(DISASM) is not None:
	
					if p_lea.match(DISASM) is not None: # leaw, leal 의 경우 lea MYSYM, %eax 으로 바꾼다. 
						INSTRUCTION = 'lea'
					elif p_mov.match(DISASM) is not None:
						INSTRUCTION = 'mov'
	
					ADD_VALUE = extract_hex_values(DISASM)[0]
					REGLIST = extract_register(DISASM)
	
					if REGLIST[0] in pcthunk_reglist: # pcthunk 에서 리턴하는 레지스터라면, 
						DESTINATION = GOT_baseaddr + ADD_VALUE # 심볼대상지점을 게싱한다.. (got베이스로부터 해당오프셋만큼 떨어진 지점)
						for sectionName_2 in resdic.keys():
							if DESTINATION in resdic[sectionName_2].keys() and sectionName_2 not in DoNotWriteThisSection: 
								# 심볼이름 셋팅
								symbolname_startoflazy = SYMPREFIX[0] + 'MYSYM_PIE_STARTOFLAZY_' + str(count)
								symbolname_yes         = SYMPREFIX[0] + 'MYSYM_PIE_YES_'         + str(count)
								symbolname_no          = SYMPREFIX[0] + 'MYSYM_PIE_NO_'          + str(count)

								# symbolname_next = ???
								if resdic[sectionName_1][SORTED_ADDRESS[i+1]][0] == '':
									symbolname_next = SYMPREFIX[0] + 'MYSYM_PIE_ORIG_'   + str(count) 
									resdic[sectionName_1][SORTED_ADDRESS[i+1]][0] = symbolname_next + ':'
								else :
									symbolname_next = resdic[sectionName_1][SORTED_ADDRESS[i+1]][0][:-1] # ':' 요거 빼주기
								# symbolname = ??? 
								if resdic[sectionName_2][DESTINATION][0] == '': 
									symbolname = SYMPREFIX[0] + 'MYSYM_PIE_REMAIN_' + str(count)
									resdic[sectionName_2][DESTINATION][0] = symbolname + ':'
								else:
									symbolname = resdic[sectionName_2][DESTINATION][0][:-1]
								count += 1
	
								NEWDISASM = ' ' + INSTRUCTION + ' ' + symbolname + ', ' + '%' + REGLIST[1]
								
								CODEBLOCK_1 = []
								CODEBLOCK_2 = []

								CODEBLOCK_1.append(' ')
								CODEBLOCK_1.append(' #==========LazySymbolize_GOTbasedpointer==========#') 
								if resdic[sectionName_1][SORTED_ADDRESS[i]][0] == '': # 이 인스트럭션의 [0]에 이미 심볼이 붙어있다면 심볼화 (X)
									CODEBLOCK_1.append( symbolname_startoflazy + ':' + ' #+++++')
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
								CODEBLOCK_2.append(' ')

								resdic[sectionName_1][SORTED_ADDRESS[i]][1] = list_insert(orig_i + 1, resdic[sectionName_1][SORTED_ADDRESS[i]][1], CODEBLOCK_2) # 원본바이너리에도 #+++++ 추가안하는것처럼
								resdic[sectionName_1][SORTED_ADDRESS[i]][1] = list_insert(orig_i, resdic[sectionName_1][SORTED_ADDRESS[i]][1], CODEBLOCK_1)
	
	
								resdic[sectionName_1][SORTED_ADDRESS[i]][3] = REGLIST[0] 
								print "╭───────────────────────────────────────────────────────────────────────────────────────────────────────────╮"
								print "│ [0] {} : {}  ...... Destination is {}, eliminated is {}".format(hex(SORTED_ADDRESS[i]),DISASM,hex(DESTINATION),resdic[sectionName_1][SORTED_ADDRESS[i]][3]).ljust(110) + '│'
								print '│                 {}'.format(NEWDISASM).ljust(110) + '│'
								print "╰───────────────────────────────────────────────────────────────────────────────────────────────────────────╯"
								print ''
								symbolizebyemulation += 1

	symbolize_counter("emulation_got : {}".format(symbolizebyemulation))

					
# pie 바이너리같은경우 .plt.got 의 항이 jmp *0x12341234 이게아니라 jmp *0xc(%ebx) 이렇게 생겼다. (이때 %ebx는 항상 GOT의 시작주소이므로 휴리스틱하게 대상 주소를 구할 수 있다는점을 이용)  
def emulation_pltfix(CHECKSEC_INFO, resdic):
	_ = '.*?'
	p_jmp   = re.compile(' jmp' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + '\(%' + _ + '\)') # jmpl.d32 *0xc(%ebx)
	symbolizebyemulation = 0

	if '.plt.got' in resdic.keys() or '.plt' in resdic.keys(): 
		# relro 방식에 따라 GOT baseaddress가 다르다. PLT_sectionName 도 다르다. 
		if CHECKSEC_INFO.relro == 'Full': 
			GOT_baseaddr = sorted(resdic['.got'].keys())[0]
			PLT_sectionName = '.plt.got'
		else:
			GOT_baseaddr = sorted(resdic['.got.plt'].keys())[0] 
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
					ADD_VALUE = extract_hex_values(DISASM)[0]
					REGLIST = extract_register(DISASM)
					INSTRUCTION = DISASM.split(' ')[1]
					DESTINATION = GOT_baseaddr + ADD_VALUE 
		
					NEWDISASM = ' ' + INSTRUCTION + ' ' + '*' + str(hex(DESTINATION))
		
					
					SectionDic[SORTED_ADDRESS[i]][1][orig_i] = NEWDISASM
					SectionDic[SORTED_ADDRESS[i]][3]         = REGLIST[0] # TODO: [3] 에다가 소거한 레지스터 저장. 위와 동일하게 형식 통일해야함.
					symbolizebyemulation += 1
	symbolize_counter('emulation_pltfix : {}'.format(symbolizebyemulation))


def fill_blanked_symbolname_toward_GOTSECTION(resdic):
	for SectionName in resdic.keys():
		for ADDR in resdic[SectionName].keys():
			orig_i_list = pickpick_idx_of_orig_disasm(resdic[SectionName][ADDR][1])
			for orig_i in orig_i_list:
				if 'REGISTER_WHO' in resdic[SectionName][ADDR][1][orig_i]:
					
					if orig_i == -1: continue
	
					# 우선은 리플레이스해주고
					eliminated_register_name = ''
					if type(resdic[SectionName][ADDR][3]).__name__ == 'list':
						eliminated_register_name = resdic[SectionName][ADDR][3][0]
					else:
						eliminated_register_name = resdic[SectionName][ADDR][3]

					resdic[SectionName][ADDR][1][orig_i] = resdic[SectionName][ADDR][1][orig_i].replace('REGISTER_WHO', '%' + eliminated_register_name)
	
					# 이제 앞뒤로다가 붙여준다. 
					CODEBLOCK_1 = []
					CODEBLOCK_2 = []
					CODEBLOCK_1.append(' ')
					CODEBLOCK_1.append(' push %' + eliminated_register_name + ' #+++++') # 레지스터 백업
					CODEBLOCK_1.append(' mov MYSYM_HEREIS_GLOBAL_OFFSET_TABLE_, %' + eliminated_register_name + ' #+++++') 
					CODEBLOCK_2.append(' pop %' + eliminated_register_name + ' #+++++')
	
					resdic[SectionName][ADDR][1] = list_insert(orig_i+1, resdic[SectionName][ADDR][1], CODEBLOCK_2)
					resdic[SectionName][ADDR][1] = list_insert(orig_i, resdic[SectionName][ADDR][1], CODEBLOCK_1)
					

def addRoutineToGetGLOBALOFFSETTABLE_in_init_array(resdic):

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
	CODEBLOCK_TEXT.append('MYSYM_get_pc_thunk.bx: #+++++')							# [+] 추가적인 준비물
	CODEBLOCK_TEXT.append(' mov (%esp), %ebx #+++++')
	CODEBLOCK_TEXT.append(' ret #+++++') # 리턴 
	CODEBLOCK_TEXT.append(' ')

	CODEBLOCK_INITARRAY.append('MYSYM_INIT_ARRAY_SETGOT: #+++++')
	CODEBLOCK_INITARRAY.append(' .long MYSYM_SET_GLOBAL_OFFSET_TABLE #+++++')



	# [01] CODEBLOCK_TEXT 은 텍스트섹션의 맨끝뒤에다가 append해준다. LAST 여야함. (그래야 특정심볼의안에서 중복실행을 방지할수가있음)
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


 
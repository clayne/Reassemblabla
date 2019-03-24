#!/usr/bin/python
#-*- coding: utf-8 -*-
import re

# 섹션 선언
CodeSections_WRITE = ['.text','.init','.fini', '.ctors', '.dtors', '.plt.got','.plt']
DataSections_WRITE = ['.data','.rodata','.bss','.init_array','.fini_array','.got', '.jcr', '.data1', '.rodata1', '.tbss', '.tdata','.got.plt'] # <.jcr> added for handling pie binary.
AllSections_WRITE  = CodeSections_WRITE + DataSections_WRITE

# 아래 섹션들은 text/data 섹션으로써 디스어셈블리에 쓰인다
TreatThisSection2TEXT = ['.init','.fini', '.ctors', '.dtors', '.plt.got', '.plt']
TreatThisSection2DATA = ['.jcr', '.data1', '.rodata1', '.tbss', '.tdata', '.got', '.got.plt']

# 네임드 심볼을 지정
MyNamedSymbol = ['main', '__x86.get_pc_thunk']
crts = "/usr/lib/i386-linux-gnu/crtn.o "

# 세그먼트 레지스터를 사용한 인스트럭션
segmentinstr = ['cmps', 'lds', 'lods', 'movs', 'outs', 'ins', 'rep', 'scas', 'stos', 'xlat']


# 우선 모든섹션 다 써준다. 
DoNotWriteThisSection = [] 
# 심볼의 프리픽스
SYMPREFIX = ['']

# 레지스터
GENERAL_REGISTERS = ['%eax', '%ebx', '%ecx', '%edx', '%edi', '%esi', '%ebp', '%esp', '%eip']

# global regex
_ = '.*?'
REG1REF = _ + '(0x)?' + '[0-9a-f]+' +  _ + '%' + _  	# ex) 0x12(%ebx)
REG    = _ + '%' + _ 						   	   		# ex) %eax
IMM    = _ + '(\$)' + '(0x)?' + '[0-9a-f]+' + _   		# ex) $0x123. 
RM32 = {}

# 메모리 레퍼런스값
RM32['M_REG']    = _ + '[(]' + _ + '%' + _ + '[)]' + _ 		# R이긴 한데 메모리레퍼런스에 쓰이는 R (%eax) / (%eax, %ebx, 4)
RM32['M_HEX']    = _ + '(0x)?' + '[0-9a-f]+' + _ 			# M32. 0x1234
RM32['R_REG']        = REG									# 단지 그냥 레지스터

# 근데 사실 RM32['M']  는 쓸모없는게, 왜냐면 애초에 이러케 헥스값으로다가 생겨먹은얘들은 symbolize단계에서 다 심볼화된상태이기때문임. 
p_cmp = []
p_cmp.append(re.compile(' cmp' + IMM + REG1REF))
p_cmp.append(re.compile(' cmp' + REG1REF + REG))
p_cmp.append(re.compile(' cmp' + REG + REG1REF))

p_PATTERN_01  = [] # instruction + REG + RM32['R']
p_PATTERN_01R = [] # instruction + REG + RM32['R']
p_PATTERN_02  = [] # instruction + RM32['R'] + REG
p_PATTERN_02R = [] # instruction + RM32['R'] + REG
p_PATTERN_03  = [] # instruction + IMM + RM32['R']
p_PATTERN_03R = []
p_PATTERN_04  = [] # instruction + RM32['R'] + IMM
p_PATTERN_04R = [] # instruction + RM32['R'] + IMM
p_PATTERN_05  = [] 

p_PATTERN_01.append(re.compile(' adc'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' add'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' and'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' btc'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' btr'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' bts'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' bt'      + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' cmpxchg' + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' cmp'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' mov'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' or'      + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' sbb'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' sub'     + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' test'    + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' xadd'    + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' xchg'    + REG + RM32['M_REG']))
p_PATTERN_01.append(re.compile(' xor'     + REG + RM32['M_REG']))

# p_PATTERN_01R.append(re.compile(' adc'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' add'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' and'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
p_PATTERN_01R.append(re.compile(' btc'     + REG + RM32['R_REG']))
p_PATTERN_01R.append(re.compile(' btr'     + REG + RM32['R_REG']))
p_PATTERN_01R.append(re.compile(' bts'     + REG + RM32['R_REG']))
p_PATTERN_01R.append(re.compile(' bt'      + REG + RM32['R_REG']))
p_PATTERN_01R.append(re.compile(' cmpxchg' + REG + RM32['R_REG']))
# p_PATTERN_01R.append(re.compile(' cmp'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' mov'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' or'      + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' sbb'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' sub'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
p_PATTERN_01R.append(re.compile(' test'    + REG + RM32['R_REG']))
p_PATTERN_01R.append(re.compile(' xadd'    + REG + RM32['R_REG']))
# p_PATTERN_01R.append(re.compile(' xchg'    + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재
# p_PATTERN_01R.append(re.compile(' xor'     + REG + RM32['R_REG'])) # p_PATTERN_02R 에 동일한패턴 존재



p_PATTERN_02.append(re.compile(' adc'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' add'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' and'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' bsf'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' bsr'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmova'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovae'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovb'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovbe'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovc'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmove'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovg'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovge'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovl'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovle'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovna'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnae' + RM32['M_REG'] + REG )) 
p_PATTERN_02.append(re.compile(' cmovnb'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnbe' + RM32['M_REG'] + REG )) 
p_PATTERN_02.append(re.compile(' cmovnc'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovne'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovng'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnge' + RM32['M_REG'] + REG )) 
p_PATTERN_02.append(re.compile(' cmovnl'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnle' + RM32['M_REG'] + REG )) 
p_PATTERN_02.append(re.compile(' cmovno'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnp'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovns'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovnz'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovo'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovp'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovpe'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovpo'  + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovs'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmovz'   + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' cmp'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' imul'    + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' lar'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' lsl'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' mov'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' or'      + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' sbb'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' sub'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' xchg'    + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' xor'     + RM32['M_REG'] + REG ))
p_PATTERN_02.append(re.compile(' lea'     + RM32['M_REG'] + REG )) # lea 는 lea + m + r32 로 c9x.me에 나와있는데, m은 진짜 m임. "lea (%esi), %esi"이나 "lea 0x11111111, %edi" 는 가능하지만  "lea %esi, %esi"->불가 "lea $0x11111111, %edi"->불가 


p_PATTERN_02R.append(re.compile(' adc'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' add'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' and'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' bsf'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' bsr'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmova'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovae'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovb'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovbe'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovc'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmove'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovg'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovge'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovl'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovle'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovna'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnae' + RM32['R_REG'] + REG )) 
p_PATTERN_02R.append(re.compile(' cmovnb'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnbe' + RM32['R_REG'] + REG )) 
p_PATTERN_02R.append(re.compile(' cmovnc'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovne'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovng'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnge' + RM32['R_REG'] + REG )) 
p_PATTERN_02R.append(re.compile(' cmovnl'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnle' + RM32['R_REG'] + REG )) 
p_PATTERN_02R.append(re.compile(' cmovno'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnp'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovns'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovnz'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovo'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovp'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovpe'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovpo'  + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovs'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmovz'   + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' cmp'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' imul'    + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' lar'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' lsl'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' mov'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' or'      + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' sbb'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' sub'     + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' xchg'    + RM32['R_REG'] + REG ))
p_PATTERN_02R.append(re.compile(' xor'     + RM32['R_REG'] + REG ))
# p_PATTERN_02R.append(' lea'     + RM32['R_REG'] + REG ) -> 없다이런룰은. 


p_PATTERN_03.append(re.compile(' adc'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' add'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' and'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' btc'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' btr'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' bts'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' bt'      + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' cmp'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' mov'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' or'      + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' ror'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' rol'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' rcr'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' rcl'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' sal'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' sar'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' shl'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' shr'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' sbb'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' sub'     + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' test'    + IMM + RM32['M_REG']))
p_PATTERN_03.append(re.compile(' xor'     + IMM + RM32['M_REG']))

p_PATTERN_03R.append(re.compile(' adc'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' add'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' and'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' btc'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' btr'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' bts'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' bt'      + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' cmp'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' mov'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' or'      + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' ror'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' rol'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' rcr'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' rcl'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' sal'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' sar'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' shl'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' shr'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' sbb'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' sub'     + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' test'    + IMM + RM32['R_REG']))
p_PATTERN_03R.append(re.compile(' xor'     + IMM + RM32['R_REG']))

# 1-operand instruction
p_PATTERN_04.append(re.compile(' call'  + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' dec'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' div'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' idiv'  + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' imul'  + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' inc'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' j'     + RM32['M_REG'])) # jmp, jne, je...
p_PATTERN_04.append(re.compile(' mul'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' neg'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' not'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' pop'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' push'  + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' sal'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' sar'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' shl'   + RM32['M_REG']))
p_PATTERN_04.append(re.compile(' shr'   + RM32['M_REG']))

p_PATTERN_04R.append(re.compile(' call'  + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' dec'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' div'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' idiv'  + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' imul'  + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' inc'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' j'     + RM32['R_REG'])) # jmp, jne, je...
p_PATTERN_04R.append(re.compile(' mul'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' neg'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' not'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' pop'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' push'  + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' sal'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' sar'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' shl'   + RM32['R_REG']))
p_PATTERN_04R.append(re.compile(' shr'   + RM32['R_REG']))


# 0-operand instruction. 
# TODO: 이 뒤에 무언가가 붙는 경우도 핸들링할 수 있도록 룰을 마련하기 ex) ret 0x10
# TODO: 이 연산결과 레지스터값이 달라지는 경우, 에뮬레이션하는것들 중 del 해주기
p_PATTERN_05.append(re.compile(' cbw'      ))
p_PATTERN_05.append(re.compile(' cwde'     ))
p_PATTERN_05.append(re.compile(' clc'      ))
p_PATTERN_05.append(re.compile(' cld'      ))
p_PATTERN_05.append(re.compile(' cli'      ))
p_PATTERN_05.append(re.compile(' clts'     ))
p_PATTERN_05.append(re.compile(' cmc'      ))
p_PATTERN_05.append(re.compile(' cmpsb'    ))
p_PATTERN_05.append(re.compile(' cmpsw'    ))
p_PATTERN_05.append(re.compile(' cmpsd'    ))
p_PATTERN_05.append(re.compile(' cpuid'    ))
p_PATTERN_05.append(re.compile(' cwd'      ))
p_PATTERN_05.append(re.compile(' cdq'      ))
p_PATTERN_05.append(re.compile(' daa'      ))
p_PATTERN_05.append(re.compile(' das'      ))
p_PATTERN_05.append(re.compile(' emms'     ))
p_PATTERN_05.append(re.compile(' f2xm1'    ))
p_PATTERN_05.append(re.compile(' fabs'     ))
p_PATTERN_05.append(re.compile(' faddp'    ))
p_PATTERN_05.append(re.compile(' fchs'     ))
p_PATTERN_05.append(re.compile(' fclex'    ))
p_PATTERN_05.append(re.compile(' fnclex'   )) 
p_PATTERN_05.append(re.compile(' fcom'     ))
p_PATTERN_05.append(re.compile(' fcomp'    ))
p_PATTERN_05.append(re.compile(' fcompp'   )) 
p_PATTERN_05.append(re.compile(' fcos'     ))
p_PATTERN_05.append(re.compile(' fdecstp'  ))  
p_PATTERN_05.append(re.compile(' fdivp'    ))
p_PATTERN_05.append(re.compile(' fdivrp'   )) 
p_PATTERN_05.append(re.compile(' ffree'    ))
p_PATTERN_05.append(re.compile(' fincstp'  ))  
p_PATTERN_05.append(re.compile(' finit'    ))
p_PATTERN_05.append(re.compile(' fninit'   )) 
p_PATTERN_05.append(re.compile(' fld1'     ))
p_PATTERN_05.append(re.compile(' fldl2t'   )) 
p_PATTERN_05.append(re.compile(' fldl2e'   )) 
p_PATTERN_05.append(re.compile(' fldpi'    ))
p_PATTERN_05.append(re.compile(' fldlg2'   )) 
p_PATTERN_05.append(re.compile(' fldln2'   )) 
p_PATTERN_05.append(re.compile(' fldz'     ))
p_PATTERN_05.append(re.compile(' fmulp'    ))
p_PATTERN_05.append(re.compile(' fnop'     ))
p_PATTERN_05.append(re.compile(' fpatan'   )) 
p_PATTERN_05.append(re.compile(' fprem'    ))
p_PATTERN_05.append(re.compile(' fprem1'   )) 
p_PATTERN_05.append(re.compile(' frndint'  ))  
p_PATTERN_05.append(re.compile(' fscale'   )) 
p_PATTERN_05.append(re.compile(' fsin'     ))
p_PATTERN_05.append(re.compile(' fsincos'  ))  
p_PATTERN_05.append(re.compile(' fsqrt'    ))
p_PATTERN_05.append(re.compile(' fsubp'    ))
p_PATTERN_05.append(re.compile(' fsubrp'   )) 
p_PATTERN_05.append(re.compile(' ftst'     ))
p_PATTERN_05.append(re.compile(' fucom'    ))
p_PATTERN_05.append(re.compile(' fucomp'   )) 
p_PATTERN_05.append(re.compile(' fucompp'  ))  
p_PATTERN_05.append(re.compile(' fxam'     ))
p_PATTERN_05.append(re.compile(' fxch'     ))
p_PATTERN_05.append(re.compile(' fxtract'  ))  
p_PATTERN_05.append(re.compile(' fyl2x'    ))
p_PATTERN_05.append(re.compile(' fyl2xp1'  ))  
p_PATTERN_05.append(re.compile(' hlt'      ))
p_PATTERN_05.append(re.compile(' into'     ))
p_PATTERN_05.append(re.compile(' invd'     ))
p_PATTERN_05.append(re.compile(' iret'     ))
p_PATTERN_05.append(re.compile(' lahf'     ))
p_PATTERN_05.append(re.compile(' leave'    ))
p_PATTERN_05.append(re.compile(' lfence'   )) 
p_PATTERN_05.append(re.compile(' lock'     ))
p_PATTERN_05.append(re.compile(' lodsb'    ))
p_PATTERN_05.append(re.compile(' lodsw'    ))
p_PATTERN_05.append(re.compile(' mfence'   )) 
p_PATTERN_05.append(re.compile(' monitor'  ))  
p_PATTERN_05.append(re.compile(' movsb'    ))
p_PATTERN_05.append(re.compile(' movzb'    ))
p_PATTERN_05.append(re.compile(' movsw'    ))
p_PATTERN_05.append(re.compile(' movzw'    ))
p_PATTERN_05.append(re.compile(' movsd'    ))
p_PATTERN_05.append(re.compile(' movzd'    ))
p_PATTERN_05.append(re.compile(' mwait'    ))
p_PATTERN_05.append(re.compile(' nop'      ))
p_PATTERN_05.append(re.compile(' outsb'    ))
p_PATTERN_05.append(re.compile(' outsw'    ))
p_PATTERN_05.append(re.compile(' pause'    ))
p_PATTERN_05.append(re.compile(' pusha'    ))
p_PATTERN_05.append(re.compile(' pushf'    ))
p_PATTERN_05.append(re.compile(' rdmsr'    ))
p_PATTERN_05.append(re.compile(' rdpmc'    ))
p_PATTERN_05.append(re.compile(' rdtsc'    ))
p_PATTERN_05.append(re.compile(' ret'      ))
p_PATTERN_05.append(re.compile(' rsm'      ))
p_PATTERN_05.append(re.compile(' sahf'     ))
p_PATTERN_05.append(re.compile(' scasb'    ))
p_PATTERN_05.append(re.compile(' scasw'    ))
p_PATTERN_05.append(re.compile(' sfence'   )) 
p_PATTERN_05.append(re.compile(' stc'      ))
p_PATTERN_05.append(re.compile(' std'      ))
p_PATTERN_05.append(re.compile(' sti'      ))
p_PATTERN_05.append(re.compile(' stosb'    ))
p_PATTERN_05.append(re.compile(' stosw'    ))
p_PATTERN_05.append(re.compile(' sysenter' ))   
p_PATTERN_05.append(re.compile(' ud2'      ))
p_PATTERN_05.append(re.compile(' wait'     ))
p_PATTERN_05.append(re.compile(' fwait'    ))
p_PATTERN_05.append(re.compile(' wbinvd'   )) 
p_PATTERN_05.append(re.compile(' wrmsr'    ))
p_PATTERN_05.append(re.compile(' xlatb'    ))


p_PATTERN_INFORMATION_LOSS = []
# TODO: pop %eax 하면 %eax 값이 loss되므로, 에물레이션 stop됨. 
# 이렇게 register 값을 변경하는 인스트럭션 모아보기.


# 세그먼트 레지스터를 이용한 메모리 레퍼런스
p_PATTERN_SEGMENTREGISTER = re.compile( '(%cs|%ds|%ss|%es)' + '(\:)' + '\(' + '(%eax|%ebx|%ecx|%edx|%edi|%esi|%ebp|%esp|%eip)' + '\)' ) # ex) %ds:(%esi)
# 일반 메모리 레퍼런스
#p_PATTERN_MEMREF_REGISTER = re.compile( '(-)?' + '(0x)?' + '[0-9a-f]+' + '(\()' + _ + '(\))') # ex) 0x12(%eax,%ebx,4) 
p_PATTERN_MEMREF_REGISTER = re.compile( '[^\ ]+' + '(\()' + _ + '(\))') # ex) 0x12(%eax,%ebx,4) 

# 원래있던것
p_add     = re.compile(' add' + IMM + REG)                     # add $0x1b53, %ebx
p_sar     = re.compile(' sar' + IMM + REG)                     # sar $0x2, %ebx
p_lea     = re.compile(' lea' + RM32['M_REG'] + REG)           # leal.d32 -3(%ebx), %eax
p_mov     = re.compile(' mov' + RM32['M_REG'] + REG)           # movl.d32 -3(%ebx), %eax
p_xor     = re.compile(' xor' + REG + REG)                     # xorl %edi, %edi
p_push    = re.compile(' push' + RM32['M_REG'])                # pushl.d32 -0xc(%ebx)          
p_call    = re.compile(' call' + _ + ' ' + '\*' + '[-+]?' + '(0x)?' + '[0-9a-f]+' + _ + '%' + _ + '%' + _)  # calll.d32 *-0xf8(%ebx, %edi, 4)
p_bracket = re.compile('\<.*?\>')

# 아래 함수의 파라미터들은 (데이터임에도 불구하고)휴리스틱하게 심볼라이즈 해줍니다

# COMMENT: 1000 이 곱해져있는경우는, n번째 파라미터부터 쭉- 무한대까지 심볼라이즈를 해준다.
# COMMENT: jmp 로 라이브러리함수를 호출한다면, '__fprintf_chk':[4000] 이렇게 파라미터자리가 한칸 +된다.
symbolize_heuristic_list_call = {'__cxa_atexit':[1], '__printf_chk':[2000], '__fprintf_chk':[3000], 'qsort':[1,4], '__lxstat64':[2], '__xstat64':[2], 'error':[3000], 'getopt_long':[3,4], 'read':[2], 'openat64':[2], 'strlen':[1], 'strchr':[1], 'strrchr':[1], 'strchrnul':[1], 're_compile_pattern':[1,3]}
symbolize_heuristic_list_jmp  = {'__cxa_atexit':[2], '__printf_chk':[3000], '__fprintf_chk':[4000], 'qsort':[2,5], '__lxstat64':[3], '__xstat64':[3], 'error':[4000], 'getopt_long':[4,5], 'read':[3], 'openat64':[3], 'strlen':[2], 'strchr':[2], 'strrchr':[2], 'strchrnul':[2], 're_compile_pattern':[2,4]}

symbolize_heuristic_list_call_multidemension = {'sigaction':[2]}
symbolize_heuristic_list_jmp_multidemension  = {'sigaction':[3]}
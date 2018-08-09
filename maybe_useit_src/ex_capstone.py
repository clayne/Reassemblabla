from capstone import *

f = open('ex_relro', 'rb')
content = f.read()

content = content[0x40b:]
print len(content)

ergebnism = open("ex_relro.capstone", "w")
mi = Cs(CS_ARCH_X86, CS_MODE_32)
for i in mi.disasm(content, 0x0000):    
    ergebnism.write("0x%x:\t%s\t%s" %(i.address, i.mnemonic, i.op_str))
    ergebnism.write("\n")
ergebnism.close()



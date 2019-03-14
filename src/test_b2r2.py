import clr
clr.AddReferenceToFileAndPath("FSharp.Core.4.5.2/lib/netstandard1.6/FSharp.Core.dll")
clr.AddReferenceToFileAndPath("B2R2.FrontEnd.0.1.0/lib/netstandard2.0/B2R2.Core.dll")
clr.AddReferenceToFileAndPath("B2R2.FrontEnd.0.1.0/lib/netstandard2.0/B2R2.FrontEnd.Core.dll")
clr.AddReferenceToFileAndPath("B2R2.FrontEnd.0.1.0/lib/netstandard2.0/B2R2.FrontEnd.Library.dll")

from B2R2 import *
from B2R2.FrontEnd import *

isa = ISA.OfString("x86")
binary = ByteArray.ofHexString('65ff1510000000')
handler = BinHandler.Init(isa, binary)
ins = handler.ParseInstr(handler, 0)
print(ins.Disasm())

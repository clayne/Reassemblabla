nasm -f bin32  z.nasm.s -o z.nasm
objdump -D -b binary -m i8086 z.nasm

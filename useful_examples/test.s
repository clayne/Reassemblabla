.global main

main:
# 1-operand instruction
  call get_pc_thunk.si

  call  (%esi)
  dec   (%esi)
  div   (%esi)
  idiv  (%esi)
  imul  (%esi)
  inc   (%esi)
  jmp   (%esi) 
  mul   (%esi)
  neg   (%esi)
  not   (%esi)
  pop   (%esi)
  push  (%esi)
  sal   (%esi)
  sar   (%esi)
  shl   (%esi)
  shr   (%esi)

get_pc_thunk.si:
 mov (%esp), %esi
 ret 

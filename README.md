# Reassemblabla
Disassembler creates the reassemblable disassembly  
**100% correctness** in reassemble experiment on Coreutils binaries. 

## How to use it

    $ python Reassemblablabla_x86.py --file <Binary name> --align
    
Above command creates reassemblable disassembly file.  
We highly recommend to use `--align` option which aligns datas since data-aliment instruction exists in general binaries.  
(Once those instruction is called with non-aligned data, program crashes)
  
    $ python Reassemblablabla_x86.py --file <Binary name> --align --comment
`--comment` option appends original bytepattern as a commant in the output disassembly.   
  
<br>  
<br>

## Result
Reassemblabla runs, and finally below messages appears on shell.  

    ...
    ...
    
    ...done!
    [*] input binary   : mytest
    [+] assembly file  : mytest_reassemblable.s
    [+] compile script : mytest_compile.sh

실행 결과 2개의 파일이 생성됩니다.  
- `mytest_reassemblable.s` : reassemblable disassembly file
- `mytest_compile.sh`       : compile script used to compile above disassembly file. 

<br>
<br>  

## Let's Reassemble!
    $ ./mytest_compile.sh
Once you run compile script emit from Reassemblabla, output binary compiled.  

<br>
<br>

## Technical deatils
### Lazy symbilization


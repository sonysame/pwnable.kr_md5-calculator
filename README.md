# pwnable.kr_md5-calculator
pwnable

####main function
```cpp
int __cdecl main(int argc, const char **argv, const char **envp)
{
  unsigned int v3; // eax
  int v5; // [esp+18h] [ebp-8h]
  int v6; // [esp+1Ch] [ebp-4h]

  setvbuf(stdout, 0, 1, 0);
  setvbuf(stdin, 0, 1, 0);
  puts("- Welcome to the free MD5 calculating service -");
  v3 = time(0);
  srand(v3);
  v6 = my_hash();
  printf("Are you human? input captcha : %d\n", v6);
  __isoc99_scanf("%d", &v5);
  if ( v6 != v5 )
  {
    puts("wrong captcha!");
    exit(0);
  }
  puts("Welcome! you are authenticated.");
  puts("Encode your data with BASE64 then paste me!");
  process_hash();
  puts("Thank you for using our service.");
  system("echo `date` >> log");
  return 0;
}
```
####my_hash function
```cpp
int my_hash()
{
  signed int i; // [esp+0h] [ebp-38h]
  char v2[4]; // [esp+Ch] [ebp-2Ch]
  int v3; // [esp+10h] [ebp-28h]
  int v4; // [esp+14h] [ebp-24h]
  int v5; // [esp+18h] [ebp-20h]
  int v6; // [esp+1Ch] [ebp-1Ch]
  int v7; // [esp+20h] [ebp-18h]
  int v8; // [esp+24h] [ebp-14h]
  int v9; // [esp+28h] [ebp-10h]
  unsigned int v10; // [esp+2Ch] [ebp-Ch]

  v10 = __readgsdword(0x14u);
  for ( i = 0; i <= 7; ++i )
    *(_DWORD *)&v2[4 * i] = rand();
  return v6 - v8 + v9 + v10 + v4 - v5 + v3 + v7;
}
```
####process_hash function
```cpp
unsigned int process_hash()
{
  int v0; // ST14_4
  void *ptr; // ST18_4
  char v3; // [esp+1Ch] [ebp-20Ch]
  unsigned int v4; // [esp+21Ch] [ebp-Ch]

  v4 = __readgsdword(0x14u);
  memset(&v3, 0, 0x200u);
  while ( getchar() != 10 )
    ;
  memset(g_buf, 0, sizeof(g_buf));
  fgets(g_buf, 1024, stdin);
  memset(&v3, 0, 0x200u);
  v0 = Base64Decode(g_buf, (int)&v3);
  ptr = (void *)calc_md5(&v3, v0);
  printf("MD5(data) : %s\n", ptr);
  free(ptr);
  return __readgsdword(0x14u) ^ v4;
}
```

Firstly, we have to know how the base64 encoding works, then we can find a buffer overflow vulnerability.
![base64encoding](https://i.stack.imgur.com/asR79.png  "base64encoding")

3bytes(24bits) are encoded to 4 Base64 data(32bits) that only contain 64 different ASCII characters(0-9A-Za-z+/). If there are only two or one byte left, padding(=) is added.

Therefore, after Base64 decoding, 4bytes are shortend to 3bytes approximately.

We get the input and store it to the variable g_buf which is in bss area.
Next, g_buf is decoded as Base64 and stored in the variable v3 which is in stack area.
The varible v3 only takes 0x200 bytes. However, the maximum of g_buf is 1024bytes, so the maximum of the data that will be stored in v3 is 1024/4*3=768bytes. And here is the vurnabilty!

We have the address of system function, so we can get the shell by using stack overflow and the system address.

However, there is a canary, so we have to figure out what the canary is. We can get the canary from the captcha data printed. It uses the rand function and the canary. The rand function uses time(0) as a seed. Therefore, I made canary.c which uses the captcha data printed as an argument and time(0) as a seed. The function canary calculates the canary. If that canary ends with \x00, the value is correct!

Now, we know what the canary is, we can overflow the stack that reaches to the return address, and we also know the system address. Last but not least, "/bin/sh\x00" string can be stored in bss section by input, and the address is fixed. 

The input is base64encode("a"*0x200 +canary+dummies+system address+dummy+the address of "/bin/sh\x00")+the address of "/bin/sh\x00"

DONE!






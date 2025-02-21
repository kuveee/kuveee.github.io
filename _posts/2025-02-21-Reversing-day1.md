---
title: Day1-reverse
date: 2025-02-12 00:00:00 +0800
categories: [rev]
tags: [rev]
author: "kuvee"
layout: post
---


## Reversing ELF

### crackme1 

file : 1 file 64 bit dynamic 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ file crackme1
crackme1: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=672f525a7ad3c33f190c060c09b11e9ffd007f34, not stripped
```

- bài này chỉ cần chạy file là có flag 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme1
flag{not_that_kind_of_elf}
```

### crackme2

- run nó lên thì có lẽ ta cần nhập password -> 1 bài check password

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme2
Usage: ./crackme2 password
```

- đây là hàm main của bài , ở đây nó sẽ check password ta nhập vào ```super_secret_password``` sẽ cho ta flag 

```cs
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( argc == 2 )
  {
    if ( !strcmp(argv[1], "super_secret_password") )
    {
      puts("Access granted.");
      giveFlag();
      return 0;
    }
    else
    {
      puts("Access denied.");
      return 1;
    }
  }
  else
  {
    printf("Usage: %s password\n", *argv);
    return 1;
  }
}
```
- và đơn giản là ta có flag

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme2 super_secret_password
Access granted.
flag{if_i_submit_this_flag_then_i_will_get_points}
```

### crackme 3

- file : 1 file 32 bit , dynamic và được strippedstripped

```cs
ploi@PhuocLoiiiii:~/tryhackme$ file crackme3
crackme3: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=4cf7250afb50109f0f1a01cc543fbf5ba6204a73, stripped
```

- tiếp tục là 1 bài check passwd 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme3
Usage: ./crackme3 PASSWORD
```

- dùng strings thì ta thấy có 1 chuỗi khá giống với base64 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ strings crackme3
/lib/ld-linux.so.2
__gmon_start__
libc.so.6
_IO_stdin_used
puts
strlen
malloc
stderr
fwrite
fprintf
strcmp
__libc_start_main
GLIBC_2.0
PTRh
iD$$
D$,;D$
UWVS
[^_]
Usage: %s PASSWORD
malloc failed
ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==
Correct password!
Come on, even my aunt Mildred got this one!
ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/
;*2$"8
GCC: (Ubuntu/Linaro 4.6.3-1ubuntu5) 4.6.3
.shstrtab
.interp
.note.ABI-tag
.note.gnu.build-id
.gnu.hash
.dynsym
.dynstr
.gnu.version
.gnu.version_r
.rel.dyn
.rel.plt
.init
.text
.fini
.rodata
.eh_frame_hdr
.eh_frame
.ctors
.dtors
.jcr
.dynamic
.got
.got.plt
.data
.bss
.comment
```

- đây là hàm main của bài , ta thấy v4 trỏ đến địa chỉ được malloc 

```cs
int __cdecl main(int a1, char **a2)
{
  const char *v2; // edi
  size_t v3; // eax
  const char *v4; // esi
  size_t v5; // eax

  if ( a1 == 2 )
  {
    v2 = a2[1];
    v3 = strlen(v2);
    v4 = (const char *)malloc(2 * v3);
    if ( v4 )
    {
      v5 = strlen(v2);
      sub_80486B0(v2, v4, v5, 0);
      if ( strlen(v4) == 64 && !strcmp(v4, "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==") )
      {
        puts("Correct password!");
        return 0;
      }
      puts("Come on, even my aunt Mildred got this one!");
    }
    else
    {
      fwrite("malloc failed\n", 0xEu, 1u, stderr);
    }
  }
  else
  {
    fprintf(stderr, "Usage: %s PASSWORD\n", *a2);
  }
  return -1;
}
```

- sub_80486B0() : hàm này sẽ là hàm mã hóa base64 chuỗi ta nhập vào , hình bên dưới là khi mình nhập chuỗi "ctf" thì nó -> "Y3Rm"   


![here](/assets/images/rev/tryhackme/1.png)

- vậy ta chỉ cần giải mã chuỗi base64 cần so sánh là được "ZjByX3kwdXJfNWVjMG5kX2xlNTVvbl91bmJhc2U2NF80bGxfN2gzXzdoMW5nNQ==" -> f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5


```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme3 f0r_y0ur_5ec0nd_le55on_unbase64_4ll_7h3_7h1ng5
Correct password!
```


### crackme4

- file : 1 file 64 bit dynamic 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ file crackme4
crackme4: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.24, BuildID[sha1]=862ee37793af334043b423ba50ec91cfa132260a, not stripped
```

- tiếp tục là bài checkpasswd , thử thách nói là chuỗi sẽ được ẩn và chúng ta sử dụng ```strcmp```

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme4
Usage : ./crackme4 password
This time the string is hidden and we used strcmp
```

- compare_pwd: đây sẽ là hàm mã hóa của ta , 

```cs
unsigned __int64 __fastcall compare_pwd(const char *input)
{
  char s1[8]; // [rsp+10h] [rbp-20h] BYREF
  __int64 v3; // [rsp+18h] [rbp-18h]
  char v4[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  *(_QWORD *)s1 = 0x7B175614497B5D49LL;
  v3 = 0x547B175651474157LL;
  strcpy(v4, "S@");
  get_pwd((__int64)s1);
  if ( !strcmp(s1, input) )
    puts("password OK");
  else
    printf("password \"%s\" not OK\n", input);
  return __readfsqword(0x28u) ^ v5;
}
```

- get_pwd : hàm này sẽ duyệt đến byte NULL , nó sẽ xor mỗi kí tự của s1 với 0x24 

```cs
__int64 _c_fastcall get_pwd(__int64 a1)
{
  __int64 result; // rax
  int i; // [rsp+14h] [rbp-4h]

  for ( i = -1; ; *(_BYTE *)(a1 + i) = *(_BYTE *)(i + a1) ^ 0x24 )
  {
    result = *(unsigned __int8 *)(++i + a1);
    if ( !(_BYTE)result )
      break;
  }
  return result;
}
```

- vậy ta sẽ viết exp để lấy mật khẩu 

exp: 

```cs
passwd = [0x49, 0x5D, 0x7B, 0x49, 0x14, 0x56, 0x17, 0x7B, 0x57,0x41, 0x47, 0x51, 0x56, 0x17, 0x7B, 0x54 ,0x53 , 0x40]
result = ""
for i in passwd:
    result += chr(i ^ 0x24)
print(result)
```

- flag là mật khẩu

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme4 my_m0r3_secur3_pwd
password OK
```


### crack5 

- file : lại là 1 file 64 bit dynamic linked 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ file crackme5
crackme5: ELF 64-bit LSB executable, x86-64, version 1 (SYSV), dynamically linked, interpreter /lib64/ld-linux-x86-64.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=a426dcf8ed3de8cb02f3ee4f38ee36b4ed568519, not stripped
```

- ta sẽ được nhập 1 input 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme5
Enter your input:
abcef
Always dig deeper
```

- main: sao chép chuỗi vào v5 , tiếp theo ta sẽ được nhập dữ liệu vào ```v4``` 

```cs
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _BYTE v4[32]; // [rsp+20h] [rbp-50h] BYREF
  _BYTE v5[40]; // [rsp+40h] [rbp-30h] BYREF
  unsigned __int64 v6; // [rsp+68h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  qmemcpy(v5, "OfdlDSA|3tXb32~X3tX@sX`4tXtz", 28);
  puts("Enter your input:");
  __isoc99_scanf("%s", v4);
  if ( !(unsigned int)strcmp_(v4, v5) )
    puts("Good game");
  else
    puts("Always dig deeper");
  return 0;
}
```

- strcmp_ : loop đầu có lẽ sẽ kh liên quan đến bài , ta sẽ nhìn vào loop thứ hai , nó sẽ xor input[i] với key và cuối cùng là check với chuỗi ```OfdlDSA|3tXb32~X3tX@sX`4tXtz```

```cs
int __fastcall strcmp_(const char *input, const char *buf)
{
  int v3; // [rsp+14h] [rbp-1Ch]
  int i; // [rsp+18h] [rbp-18h]
  int j; // [rsp+1Ch] [rbp-14h]

  v3 = 0;
  for ( i = 0; i <= 0x15; ++i )
    v3 = (v3 + 1) ^ 0x17;
  for ( j = 0; j < strlen(input); ++j )
    input[j] ^= key;
  return strncmp(input, buf, 28uLL);
}
```

- tuy nhiên key là 0 -> input đúng sẽ là ```OfdlDSA|3tXb32~X3tX@sX`4tXtz``` luôn

### crackme6

- 1 bài check input 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme6
Usage : ./crackme6 password
Good luck, read the source
```

- vì dễ nên sẽ nói nhanh , nó sẽ check từng kí tự như bên dưới và đó cũng chính là password

```cs
__int64 __fastcall my_secure_test(_BYTE *a1)
{
  if ( *a1 != '1' )
    return 0xFFFFFFFFLL;
  if ( a1[1] != 51 )
    return 0xFFFFFFFFLL;
  if ( a1[2] != 51 )
    return 0xFFFFFFFFLL;
  if ( a1[3] != 55 )
    return 0xFFFFFFFFLL;
  if ( a1[4] != 95 )
    return 0xFFFFFFFFLL;
  if ( a1[5] != 112 )
    return 0xFFFFFFFFLL;
  if ( a1[6] != 119 )
    return 0xFFFFFFFFLL;
  if ( a1[7] != 100 )
    return 0xFFFFFFFFLL;
  if ( a1[8] )
    return 0xFFFFFFFFLL;
  return 0LL;
}
```

### crackme7

- main : check option mà ta nhập vào là 31337 là có flag

```cs
int __cdecl main(int argc, const char **argv, const char **envp)
{
  char v4[100]; // [esp+0h] [ebp-78h] BYREF
  int v5; // [esp+64h] [ebp-14h] BYREF
  int v6; // [esp+68h] [ebp-10h] BYREF
  _DWORD v7[3]; // [esp+6Ch] [ebp-Ch] BYREF

  v7[1] = &argc;
  while ( 1 )
  {
    while ( 1 )
    {
      puts("Menu:\n\n[1] Say hello\n[2] Add numbers\n[3] Quit");
      printf("\n[>] ");
      if ( __isoc99_scanf("%u", v7) != 1 )
      {
        puts("Unknown input!");
        return 1;
      }
      if ( v7[0] != 1 )
        break;
      printf("What is your name? ");
      memset(v4, 0, sizeof(v4));
      if ( __isoc99_scanf("%99s", v4) != 1 )
      {
        puts("Unable to read name!");
        return 1;
      }
      printf("Hello, %s!\n", v4);
    }
    if ( v7[0] != 2 )
      break;
    printf("Enter first number: ");
    if ( __isoc99_scanf("%d", &v6) != 1 || (printf("Enter second number: "), __isoc99_scanf("%d", &v5) != 1) )
    {
      puts("Unable to read number!");
      return 1;
    }
    printf("%d + %d = %d\n", v6, v5, v6 + v5);
  }
  if ( v7[0] == 3 )
  {
    puts("Goodbye!");
  }
  else if ( v7[0] == 31337 )
  {
    puts("Wow such h4x0r!");
    giveFlag();
  }
  else
  {
    printf("Unknown choice: %d\n", v7[0]);
  }
  return 0;
}
```
-flag: 


```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme7
Menu:

[1] Say hello
[2] Add numbers
[3] Quit

[>] 31337
Wow such h4x0r!
flag{much_reversing_very_ida_wow}
```

### crackme8 

- bài cuối cùng , cũng là 1 bài check input tiếp 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme8 abcd
Access denied.
```

- main: nó check số mà ta nhập vào và in flag 

```cs
int __cdecl main(int argc, const char **argv, const char **envp)
{
  if ( argc == 2 )
  {
    if ( atoi(argv[1]) == 3405705229 )
    {
      puts("Access granted.");
      giveFlag();
      return 0;
    }
    else
    {
      puts("Access denied.");
      return 1;
    }
  }
  else
  {
    printf("Usage: %s password\n", *argv);
    return 1;
  }
}
```

- tuy nhiên khi nhập đúng với giá trị đó sao lại không được? 

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme8 3405705229
Access denied.
```
- đó là do atoi nó trả về kiểu int nhưng 3405705229 lại vượt quá range ```int``` -> integer_overflow

range của int 

```cs
-2,147,483,648 → 2,147,483,647
```

range của uint :

```cs
0 → 4,294,967,295
```

- và ```0xCAFEF00D``` ->  3405705229 > ```2,147,483,647``` nên nó sẽ trở thành số âm 

- vậy ta sẽ tìm nó bằng cách trừ nó đi 2^32 là sẽ ra số cần tìm 

```cs
>>> 3405705229 - 2**32
-889262067
```

- flag

```cs
ploi@PhuocLoiiiii:~/tryhackme$ ./crackme8 -889262067
Access granted.
flag{at_least_this_cafe_wont_leak_your_credit_card_numbers}
```
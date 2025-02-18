---
title: writeup-NewStar-2024
date: 2025-02-12 00:00:00 +0800
categories: [NewStarr 2024]
tags: [crypto,rev,misc,web]
author: "kuvee"
layout: post
---

### week1

#### rev

##### Simple_encryption

- ta được cho 1 file exe , và đây là hàm main của bài , biến ```len``` có gía trị là 0x1E , vậy flag cũng sẽ có lenght tương tự

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int k; // [rsp+24h] [rbp-Ch]
  int j; // [rsp+28h] [rbp-8h]
  int i; // [rsp+2Ch] [rbp-4h]

  _main(argc, argv, envp);
  puts("please input your flag:");
  for ( i = 0; i < len; ++i )
    scanf("%c", &input[i]);
  for ( j = 0; j < len; ++j )
  {
    if ( !(j % 3) )
      input[j] -= 31;
    if ( j % 3 == 1 )
      input[j] += 41;
    if ( j % 3 == 2 )
      input[j] ^= 0x55u;
  }
  for ( k = 0; k < len; ++k )
  {
    printf("0x%02x ", input[k]);
    if ( input[k] != buffer[k] )
    {
      printf("error");
      return 0;
    }
  }
  putchar(10);
  printf("success!");
  return 0;
}
```

- 1 vòng lặp thay đổi giá trị của từng kí tự  ,modulo để checkcheck

```c
for ( j = 0; j < len; ++j )
  {
    if ( !(j % 3) )
      input[j] -= 31;
    if ( j % 3 == 1 )
      input[j] += 41;
    if ( j % 3 == 2 )
      input[j] ^= 0x55u;
  }
```

- cuối cùng là in ra những byte ở dạng hex và check từng kí tự với ```buffer```

```cs
  0x47, 0x95, 0x34, 0x48, 0xA4, 0x1C, 0x35, 0x88, 0x64, 0x16, 
  0x88, 0x07, 0x14, 0x6A, 0x39, 0x12, 0xA2, 0x0A, 0x37, 0x5C, 
  0x07, 0x5A, 0x56, 0x60, 0x12, 0x76, 0x25, 0x12, 0x8E, 0x28, 
```

- vậy như ta thấy thì nó chỉ check 1 trong 3 trường hợp ở trên thôi , và ta cũng đã biết giá trị cần so sánh , vậy đơn giản là ta sẽ lấy giá trị này làm ngược lại

exp: 

```cs
ploi@PhuocLoiiiii:~/pwn/NewStart-CTF-2024/week1/rev/simple_encryption$ cat solve.py
array= [ 0x47, 0x95, 0x34, 0x48, 0xA4, 0x1C, 0x35, 0x88, 0x64, 0x16,
  0x88, 0x07, 0x14, 0x6A, 0x39, 0x12, 0xA2, 0x0A, 0x37, 0x5C,
  0x07, 0x5A, 0x56, 0x60, 0x12, 0x76, 0x25, 0x12, 0x8E, 0x28]

for i in range(len(array)):
    if i % 3 == 0:
        array[i] += 31
    elif i % 3 == 1:
        array[i] -= 41
    elif i % 3 == 2:
        array[i] ^= 0x55

print(''.join([chr(x) for x in array]))
```

flag: 

```
flag{IT_15_R3Al1y_V3Ry-51Mp1e}
```


##### base64

![here](/assets/images/newstart/week1/rev/1.png)

- đầu tiên chạy file thì ta sẽ được nhập 1 flag

![here](/assets/images/newstart/week1/rev/2.png)

- ta có thể dùng ```shift+f12``` để tìm string trong file , ta sẽ tham chiếu đến nó

![here](/assets/images/newstart/week1/rev/3.png)

- ở đây ta thấy chuỗi ```correct flag``` và đây có lẽ cũng là target của bài  

![here](/assets/images/newstart/week1/rev/4.png)

- ta thấy nó dùng strlen() để check , có lẽ đó là độ dài flag , tiếp theo là so sánh chuỗi với input()  , chuỗi đó nhìn khá giống ```base64``` , ngoài ra còn 1 hàm ```sub_1400014E0``` mà ta chưa xem xét

```cs
char *__fastcall sub_1400014E0(char *a1, int a2, _BYTE *a3)
{
  char *result; // rax
  __int64 v5; // rcx
  int v6; // ebx
  char v7; // r9
  __int64 v8; // rdx
  __int64 i; // rdx
  __int64 v10; // rdi
  __int64 v11; // rax
  void *v12; // rcx
  size_t v13; // r8
  unsigned __int8 v14; // [rsp+29h] [rbp-1Fh] BYREF
  unsigned __int8 v15; // [rsp+2Ah] [rbp-1Eh]
  unsigned __int8 v16; // [rsp+2Bh] [rbp-1Dh]
  _DWORD v17[7]; // [rsp+2Ch] [rbp-1Ch]

  result = a1;
  if ( a2 )
  {
    v5 = (__int64)&a1[a2 - 1 + 1];
    v6 = 0;
    do
    {
      while ( 1 )
      {
        v7 = *result;
        v8 = v6++;
        ++result;
        *(&v14 + v8) = v7;
        if ( v6 == 3 )
          break;
        if ( result == (char *)v5 )
          goto LABEL_8;
      }
      v17[0] = (v14 >> 2) | (((unsigned __int8)((v15 >> 4) + ((16 * v14) & 0x30)) | (((unsigned __int8)((v16 >> 6) + ((4 * v15) & 0x3C)) | ((v16 & 0x3F) << 8)) << 8)) << 8);
      for ( i = 0LL; i != 4; ++i )
        a3[i] = aWhydo3sthis7ab[*((unsigned __int8 *)v17 + i)];
      a3 += 4;
      v6 = 0;
    }
    while ( result != (char *)v5 );
LABEL_8:
    if ( v6 )
    {
      if ( v6 > 2 )
      {
        v10 = v6;
        v17[0] = (v14 >> 2) | (((unsigned __int8)((v15 >> 4) + ((16 * v14) & 0x30)) | (((unsigned __int8)((v16 >> 6) + ((4 * v15) & 0x3C)) | ((v16 & 0x3F) << 8)) << 8)) << 8);
      }
      else
      {
        v10 = v6;
        memset(&v14 + v6, 0, (unsigned int)(3 - v6));
        v17[0] = (v14 >> 2) | (((unsigned __int8)((v15 >> 4) + ((16 * v14) & 0x30)) | (((unsigned __int8)((v16 >> 6) + ((4 * v15) & 0x3C)) | ((v16 & 0x3F) << 8)) << 8)) << 8);
        if ( v6 < 0 )
        {
LABEL_14:
          v12 = a3;
          v13 = (unsigned int)(3 - v6);
          a3 += v13;
          result = (char *)memset(v12, 61, v13);
          goto LABEL_15;
        }
      }
      v11 = 0LL;
      do
      {
        a3[v11] = aWhydo3sthis7ab[*((unsigned __int8 *)v17 + v11)];
        ++v11;
      }
      while ( v6 >= (int)v11 );
      a3 += v10 + 1;
      goto LABEL_14;
    }
  }
LABEL_15:
  *a3 = 0;
  return result;
}
```

- ta thấy có 1 biến khá nghi ngờ , nhìn khá giống bảng mã của base64 , vậy có nghĩa là input của ta bị mã hóa bởi base64

```
.rdata:0000000140011080 aWhydo3sthis7ab db 'WHydo3sThiS7ABLElO0k5trange+CZfVIGRvup81NKQbjmPzU4MDc9Y6q2XwFxJ/',0
```

- vậy kết hợp những điều đó lại ta sẽ giải mã nó ra 

![here](/assets/images/newstart/week1/rev/5.png)

```
flag{y0u_kn0w_base64_well}
```
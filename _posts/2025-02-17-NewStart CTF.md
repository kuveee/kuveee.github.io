---
title: writeup-NewStar-2024
date: 2025-02-12 00:00:00 +0800
categories: [NewStarr 2024]
tags: [crypto,rev,misc,web]
author: "kuvee"
layout: post
published: false
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

##### begin

- 1 bài giới thiệu về cách sử dụng IDA 

- nó bảo rằng flag có độ dài là 50 và không có khoảng trống , có 3 part cần phải tìm 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _main(argc, argv, envp);
  puts(
    "This program will teach you the basic use of IDA, including viewing variables, searching strings, cross referencing, etc");
  puts("Please open this program with IDA, and we will tell you the flag step by step");
  puts("First:You should press F5 to decompile the main function");
  strcpy((char *)&flag_part1, "OK,You can click on this variable to discover the first part\n");
  puts("The flag has three parts with a total length of 50");
  puts("There are no spaces in the flag");
  puts("If you find that flag part1 is garbled, please press the ' a ' key");
  puts("The second part of the flag can be achieved by pressing shift+F12");
  system("pause");
  return 0;
}
```

- part 1 sẽ ở trong 1 biến có tên là ```flag_part1``` : 

```
0x6B614D7B67616C66
```

- part 2 có được bằng cách dùng ```shift + f12``` để tìm kiếm chuỗi: 

![here](/assets/images/newstart/week1/rev/6.png)


```3Ff0rt_tO_5eArcH_```

- part cuối thì ta tham chiếu đến hàm chứa chuỗi này và flag cũng chính là tên hàm 

![here](/assets/images/newstart/week1/rev/7.png)

- cuối cùng ghép tất cả lại , ta có: 

```
flag{Mak3Ff0rt_tO_5eArcH_F0r_th3_f14g_C0Rpse}
```

##### ezAndroidStudy

- đề cho ta 1 file .apk nên ta sẽ dùng JADX chuyển sang code java cho dễ đọc 

- sau 1 lúc tim kiếm thì ta tìm được 1 hàm chứa đoạn đầu của flag , hoặc ta có thể search strings để tìm 

![here](/assets/images/java.png)



#### crypto 

##### xor

- đầu tiên là nó chuyển 13 kí tự đầu của flag thành 1 số nguyên -> m1
- lưu các kí tự còn lại -> m2
- tiếp theo nó sẽ ```xor``` m1 với key -> c1
- cuối cùng là ```xor``` key với m2

như đã thấy ở trên nó dùng ```^``` và ```xor``` để ví dụ cho ta thấy rằng xor có thể hoạt động trên các kiểu dữ liệu khác nhau  

```python
#As a freshman starting in 2024, you should know something about XOR, so this task is for you to sign in.

from pwn import xor
#The Python pwntools library has a convenient xor() function that can XOR together data of different types and lengths
from Crypto.Util.number import bytes_to_long

key = b'New_Star_CTF'
flag='flag{*******************}'

m1 = bytes_to_long(bytes(flag[:13], encoding='utf-8'))
m2 = flag[13:]

c1 = m1 ^ bytes_to_long(key)
c2 = xor(key, m2)
print('c1=',c1)
print('c2=',c2)

'''
c1= 8091799978721254458294926060841
c2= b';:\x1c1<\x03>*\x10\x11u;'
'''

vậy đơn giản là ta xor kết quả của c1 và c2 với key và cộng kết quả lại là sẽ ra flag 


```python
from pwn import *
#The Python pwntools library has a convenient xor() function that can XOR together data of different types and lengths
from Crypto.Util.number import *

c1= 8091799978721254458294926060841
c2= b';:\x1c1<\x03>*\x10\x11u;'

key = b'New_Star_CTF'

flag1 = (c1 ^ bytes_to_long(key))
flag2 = xor(c2,key)
flag = long_to_bytes(flag1) + flag2
print(flag)
```

![here](/assets/images/crypzzz.png)


##### strangeking

description: 

```
Một vị hoàng đế thích vẽ Sharp 5 muốn tiến bộ mỗi ngày, cho đến khi anh ta cưới một người mẫu, trở về điểm xuất phát và tặng miễn phí mọi thứ 😅 Đây là tin nhắn cuối cùng anh ta để lại: ksjr{EcxvpdErSvcDgdgEzxqjql}, lá cờ được bao quanh bằng văn bản thuần túy có thể đọc được
```

- dựa vào description ta có thể thấy rằng flag vẫn giữ nguyên index không thay đổi nên có lẽ đó là caesar 
- format flag là flag{}  và flag bị mã hóa là ksjr{    f -> k với key là 5 , l -> s sẽ là 7 và a -> j sẽ là 9 vậy key tăng thêm 2 mỗi lần 

exp:

```python
def caeasar(flag):
    result = ""
    shift = 5
    for i in flag:
        if i.isalpha():
            start = ord('A') if i.isupper() else ord('a')
            result += chr((ord(i) - start - shift) %26 + start)
        else:
            result += i
        shift += 2
    return result
flag_encrypt = "ksjr{EcxvpdErSvcDgdgEzxqjql}"
print(caeasar(flag_encrypt))
```

- đây là code encrypt: 

```python
def caesar(flag):
    result = ""
    key = 5
    for i in flag:
        start = ord('A') if i.isupper() else ord('a')
        if i.isalpha():
            result += chr((ord(i) - start + key) % 26 + start)
        else:
            result += i
        key += 2
    return result



flag = "flag{PleaseDoNotStopLearing}"
print(caesar(flag))
```

#####  Base

- tên bài đã nói lên tất cả , ta chỉ cần chuyển đoạn này thành chuỗi xong rồi dùng base32 và base64 để giải mã nó 

```cs
This is a base question!

4C4A575851324332474E324547554B494A5A4446513653434E564D444154545A4B354D45454D434E4959345536544B474D5134513D3D3D3D
```

exp: 

```cs
import base64

hex_ = "4C4A575851324332474E324547554B494A5A4446513653434E564D444154545A4B354D45454D434E4959345536544B474D5134513D3D3D3D"

text = bytes.fromhex(hex_).decode()

b32decode = base64.b32decode(text)

b64decode = base64.b64decode(b32decode)
print(b64decode)
```

- và ta cũng cần tìm quá trình mã hóa của nó , trước hết nó sẽ chuyển chuỗi sang nhị phân , ví dụ "ctf" -> c -> 99 -> 01100011 , t -> 116 -> 01110100 , sau khi ghép lại thì ta có đoạn này ```011000110111010001100110``` , nếu nó nhỏ hơn 8 bit thì ta cần padding nó vào 

- tiếp theo sẽ là cắt bỏ các số nhị phân và vì nó được mã hóa theo  base64 nên quy tắc là ( 2^6 =64 ) , nó sẽ cắt bớt theo lũy thừa của 2 

- tiếp theo là chia nó thành từng nhóm 6 bit và ánh xạ với 1 kí tự trong bản base64

```cs
Nhị phân	Giá trị thập phân	  Ký tự Base64
010011	    19	              T
010110	    22	              W
000101	    5	                F
101110	    46	              u
```

- nếu độ dài không chia hết cho 3 thì base64 thêm padding "=" để đảm bảo độ dài chuỗi luôn là bội số của 4 
- Ví dụ: "Ma" có 2 ký tự (16-bit), sau khi mã hóa sẽ thêm "="

```
"Ma" → "TWE="
```

- nếu chỉ có 1 bytes ( 8 bit) sẽ thêm == : 

```cs
"M" → "TQ=="
```

- lưu ý :  Base64 không phải là mã hóa bảo mật, nó chỉ là một phương pháp mã hóa dữ liệu thành dạng có thể in được , ứng dụng của nó là trong truyền dữ liệu nhị phân (hình ảnh , file) , mã hóa JSON , JWT , URL

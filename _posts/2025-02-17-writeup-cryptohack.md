---
title: writeup-CryptoHack
date: 2025-02-12 00:00:00 +0800
categories: [crypto]
tags: [crypto]
author: "kuvee"
layout: post
---





## introduction to cryptohack


### bài 1


- bài đầu nói sơ qua về format flag thôi

![here](/assets/images/cryptohack.png)

### bài 2 

bài tiếp theo sẽ nói về python3 , nó sẽ giúp ích ta rất nhiều trong việc giải quyết những vấn đề , bài cho ta 1 file và ta chỉ cần chạy để lấy flag

```python
#!/usr/bin/env python3

import sys
# import this

if sys.version_info.major == 2:
    print("You are running Python 2, which is no longer supported. Please update to Python 3.")

ords = [81, 64, 75, 66, 70, 93, 73, 72, 1, 92, 109, 2, 84, 109, 66, 75, 70, 90, 2, 92, 79]

print("Here is your flag:")
print("".join(chr(o ^ 0x32) for o in ords))
```

flag: 

![here](/assets/images/cryptohack1.png)

### ascii

- ascii là 1 chuẩn mã hóa 7 bit cho phép biểu diễn văn bản bằng các số nguyên từ 0-127 , chall này yêu cầu chuyển đổi mã ascii thành kí tự tương ứng để có flag 


```[99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]```


exp: 

```
asciii = [99, 114, 121, 112, 116, 111, 123, 65, 83, 67, 73, 73, 95, 112, 114, 49, 110, 116, 52, 98, 108, 51, 125]

print(''.join([chr(x) for x in asciii]))
```

```cs
ploi@PhuocLoiiiii:~/pwn/FSOP/_IO_FILE Arbitrary Address Read$ python3 test.py
crypto{ASCII_pr1nt4bl3}
```



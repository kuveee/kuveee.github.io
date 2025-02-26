---
title: writeup-CryptoHack
date: 2025-02-12 00:00:00 +0800
categories: [crypto]
tags: [crypto]
author: "kuvee"
layout: post
published: false
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

### hex


- khi ta mã hóa cái gì đó , bản mã thường có các bytes không phải là kí tự ascii . challenge này yêu cầu ta giải mã chuỗi hex thành các byte để có flag


```
63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d
```

- vậy đơn giản là ta sẽ dùng ```byte.fromhex()``` để chuyển nó thành byte và lấy flag 


```cs
hex_to_byte = "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
hex_bytes = bytes.fromhex(hex_to_byte)
byte_hex = hex_bytes.hex()
print(hex_bytes)
print(byte_hex)
```

![here](/assets/images/crypp.png)

1 cách khác là dùng ```shell``` trên terminal 


```
 xxd -r -p <<< "63727970746f7b596f755f77696c6c5f62655f776f726b696e675f776974685f6865785f737472696e67735f615f6c6f747d"
```


### base64 

- 1 mã hóa phổ biến khác là base64 , cho phép biểu diễn dữ liệu nhị phân dưới dạng chuỗi ascii bằng bảng chữ cái gồm 64 kí tự . 1 kí tự chuỗi base64 mã hóa 6 chữ số nhị phân , do đó 4 kí tự base64 mã hóa 3 byte 

```
72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf
```

```
Trong Python, sau khi nhập mô-đun base64 với import base64, bạn có thể sử dụng base64.b64encode()hàm. Hãy nhớ giải mã hex trước như mô tả thử thách nêu.
```

exp : 

```python
import base64

bytestr = "72bca9b68fc16ac7beeb8f849dca1d8a783e8acf9679bf9269f7bf"
hex_bytes = bytes.fromhex(bytestr)
print(hex_bytes)
print(base64.b64encode(hex_bytes))
```

![here](/assets/images/crypzzz.png)


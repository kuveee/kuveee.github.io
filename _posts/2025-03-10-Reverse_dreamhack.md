--- 
title: Dreamhack Reverse
date: 2025-02-16 00:00:00 +0800
categories: [writeup]
tags: [reverse]
author: "kuvee"
layout: post
---

## rev-basic-0

- đọc code asm ta thấy được nó sẽ in kêu ta nhập input 
![image](https://hackmd.io/_uploads/rkrTkOXk1g.png)
 
 - tiếp tho là call sub_7FF7347211F0 , ta thấy đối số truyền vào là %256s , nên nghĩ đến scanf ngay vậy đây là hàm nhập của ta

- tiếp tục là hàm  sub_7FF734721000 : nó nhận 1 biến trên stack vào làm đối số  ta thấy nó sẽ mov [rsp+str1], tiếp tục mov str2(là chuỗi "Compar3_the_str1ng" vào rdx , chuỗi đối số được mov vào rcx ) và strcmp , nếu bằng thì mov 0 vào  [rsp+38h+var_18] còn kh thì mov 1 vào địa chỉ đó

![image](https://hackmd.io/_uploads/B1hoZdXkJg.png)

- sau đó khi thực hiện hàm này xong nó sẽ trở về hàm main ban đầu , và test eax,eax  điều này có nghĩa nếu eax=0 thì đúng còn 0 thì sai 
- vậy ta chỉ cần nhập chuỗi ở trên vào 

![image](https://hackmd.io/_uploads/BJTRf_XJkg.png)


## rev-basic-1


khá giống với bài trước , ta sẽ vào hàm check xem nó làm gì 





![image](https://hackmd.io/_uploads/HyiSVuQJ1l.png)

ở đây nó sẽ check từng điều kiện , nếu đúng
![image](https://hackmd.io/_uploads/H1JvHOQyJl.png)

- so sánh từng kí tự nhập vào
![image](https://hackmd.io/_uploads/HkeiA8umyke.png)

viết đoạn code để decode : 
```
list_ = [67,111,109,112,97,114,51,95,116,104,101,95,99,104,52,114,97,99,116,51,114]
a = ""
for i in list_:
    a += chr(i)
print(a)
```



![image](https://hackmd.io/_uploads/SyXwai7Jyx.png)

## rev-basic-03


- baì này cũng tương tự các bài trước , ta chỉ cần giải hệ phương trình đơn giản như sau :
``` a = i ^ x[i] + (2*i) ``` 

-> x[i] = a - (2*i) ^ i

script đơn giản như sau : 



![image](https://hackmd.io/_uploads/HkrfBJNk1x.png)


script đơn giản như sau : 
```
list_ = [0x49, 0x60, 0x67, 0x74, 0x63, 0x67, 0x42, 0x66, 0x80, 0x78,
  0x69, 0x69, 0x7B, 0x99, 0x6D, 0x88, 0x68, 0x94, 0x9F, 0x8D,
  0x4D, 0xA5, 0x9D, 0x45]

a = ""
for i in range(0x18):
    a += chr(list_[i] - (2*i) ^ i)
print(a)
```


## rev-basic-04


- tuơng tự các bài ở trên , xử lý input làm sao để bằng với các byte trong mảng 
![image](https://hackmd.io/_uploads/HJ9cpkN1ye.png)

vd : nếu đầu vào của ta là 0x24 
 
thì 0x24 << 4 | 0x24 >> 4  sẽ bằng 0x242 và lúc này nó sẽ lấy giá trị 0x42 nó sẽ đảo đầu vào của ta  , thử với các giá trị khác thì cũng tương tự , vậy ta sẽ để đầu vào của ta là 0x42 -> sau các phép tính thì nó sẽ oke !!!




script 
```

list_ = [0x24, 0x27, 0x13, 0xC6, 0xC6, 0x13, 0x16, 0xE6, 0x47, 0xF5,
  0x26, 0x96, 0x47, 0xF5, 0x46, 0x27, 0x13, 0x26, 0x26, 0xC6,
  0x56, 0xF5, 0xC3, 0xC3, 0xF5, 0xE3, 0xE3, 0x00, 0x00, 0x00,
  0x00, 0x00]
print(len(list_))
a = ""
for i in range(len(list_)):
    a += chr( list_[i]*16 & 0xf0  | list_[i] >> 4)
print(a)

#ans = [0x24, 0x27, 0x13, 0xC6, 0xC6, 0x13, 0x16, 0xE6, 0x47, 0xF5, 0x26, 0x96, 0x47, 0xF5, 0x46, 0x27,
 #      0x13, 0x26, 0x26, 0xC6, 0x56, 0xF5, 0xC3, 0xc3, 0xF5, 0xE3, 0xE3]

#for i in range(len(ans)):
  #  print(chr((ans[i]<<4 | ans[i]>>4) % (16 * 16)), end='')
```

--------

## path


- ta được cung cấp 1 file exe , khi chạy các ctrinh không đáng tin cậy thì ta cần chạy nó ở máy ảo còn nếu ta đã nắm bắt được mô tả của thử thách thì ta tiến hành phân tích tĩnh luôn

![image](https://hackmd.io/_uploads/S1PGpLNSye.png)


khi ta chạy thì sẽ có giao diện như này , có lẽ nhiệm vụ là xóa bỏ các ô đen đó và lấy flag 

## Tìm hàm winmain


vì file này là 1 chương trình GUI được xây dựng bằng WinAPI , chúng ta cần tìm hàm WinMain (Winman thường xử lý việc tạo số và các tác vụ khởi tạo liên quan)

ở đây IDA sẽ tự động tìm cho ta , nhưng chúng ta sẽ tự tìm bằng cách vào ```import``` -> và thông qua ```xref``` của  CreateWindowExW
![image](https://hackmd.io/_uploads/SJRW0LNrkx.png)


ta thấy rằng hàm RegisterClassExW Là hàm đăng kí lớp cửa sổ và có ```v11``` là biến làm đối số , Phần quan trọng nhất của hàm này là dòng 14, nơi lệnh gọi lại thông báo của cửa sổ được đặt.

![image](https://hackmd.io/_uploads/BJiHALEB1e.png)

- Nếu không quen với WinAPI thì ta nên tìm kiếm các hàm có liên quan để hiểu mục đích của nó ,   Tài liệu về hàm WinAPI trên MSDN bao gồm mọi thứ từ mục đích của hàm đến mô tả về các đối số của nó. Các chương trình sử dụng WinAPI thường tận dụng các API tương tự, vì vậy nếu bạn tìm hiểu về các hàm mà bạn không nhận ra bất cứ khi nào bạn gặp chúng, bạn có thể phân tích các tệp nhị phân khác hiệu quả hơn trong tương lai.



- hình ảnh bên dưới cho ta thấy rằng nó chứa 1 câu lệnh switch case với ba trường hợp , 1 trong số đó , tương ứng với 0xF , xử lý các tác vụ liên quan đến việc vẽ , Nó nằm giữa các hàm BeginPaint và EndPaint nơi cờ có khả năng được vẽ, khiến sub_140002C40 hàm trở thành ứng cử viên cho phân tích để hiểu cách cờ được hiển thị.
![image](https://hackmd.io/_uploads/SJdFyvVBJg.png)

đây có lẽ là hàm xử lý ảnh , từ dòng 51-75 ta thấy nó gọi hàm ```sub_140002B80``` nhiều lần , tiếp theo là các lệnh gọi đến nhiều hàm khác nhau ở các địa chỉ khác nhau. Mặc dù chúng ta chưa phân tích nội dung của các hàm này, chúng ta có thể đưa ra giả thuyết:

- sub_140002B80 : Với các lệnh gọi lặp đi lặp lại, có khả năng nó sẽ vẽ một cái gì đó theo cách lặp đi lặp lại.

- Các chức năng khác : Có thể vẽ các thành phần đồ họa khác nhau, có thể là từng chữ cái của lá cờ.
![image](https://hackmd.io/_uploads/Byp1lv4H1g.png)

đi vào hàm ```sub_140002B80``` thì Như được hiển thị trong kết quả dịch ngược ở trên , chúng ta có thể thấy rằng GdipCreatePen1tạo ra một cây bút và GdipDrawLineI vẽ một đường thẳng. Lần này, chúng ta hãy phân tích sub_1400017A0 hàm được gọi sau sub_140002B80 để so sánh nội dung của các hàm.

![image](https://hackmd.io/_uploads/HyrqgvEBkg.png)

đây là hàm ```sub_1400017A0``` , ta sẽ tiến hành debug nó 



--------------


## simple_crack_me


- bài này mới vào đọc code là ra luôn , tuy nhiên vì mới bắt đầu học nên sẽ cần phân tích kĩ 


đây sẽ là hàm chính của bài 

![image](https://hackmd.io/_uploads/Hk7FRSBB1g.png)


```__fastcall``` : Hàm này đề cập đến quy tắc gọi mà các tham số được truyền qua thanh ghi. Thông thường, tham số thứ nhất và thứ hai (a1, a2) được sử dụng qua RCX và RDX record. Tham số thứ ba (a3) ​​​​được truyền qua R8.

```__noreturn ``` : Điều này có nghĩa là hàm sẽ không kết thúc và chương trình sẽ dừng lại hoặc thoát. (Nó có thuộc tính này vì __halt() .)

- ta cần chú ý đến các biến ( kiểu dữ liệu là gì?  , và kiểu dữ liệu đó là bao nhiêu byte)

- tiếp theo hàm ```sub_40BB20``` sẽ được gọi và truyền vào các đối số , trong đó có 1 con trỏ hàm```unk_4B6004``` , ta có thể phỏng đoán là con trỏ hàm này sẽ được gọi và xử lí cái gì đó 
- tiếp theo ta thấy nó check biến check xem có bằng giá trị ```322376503``` , nếu có thì sẽ in ```correct```


nhập vào thì đúng luôn :D

![image](https://hackmd.io/_uploads/B1AaxUSSJx.png)


- ta sẽ thử xài với GHIDRA

đầu tiên chắc chắn là phải tìm 1 chuỗi nào đó , nếu nhập đúng hoặc sai thì nó sẽ in chuỗi đó ra ... 

giới hạn nó thành 10 kí tự : 

![image](https://hackmd.io/_uploads/rJxPzUBB1l.png)

ta sẽ dùng chức năng reference trong GHIDRA tham chiếu đến nơi sử dụng chuỗi này

![image](https://hackmd.io/_uploads/ry8I7UBHJg.png)


ta có thể thấy ở đây nó check xem biến ```check``` có bằng giá trị trong hình không , nếu không thì in chuỗi wrong... và nếu đúng thì in corret, đây cũng chính là số mà ta cần tìm 

![image](https://hackmd.io/_uploads/Sk5h7LHHkg.png)


ta cần đổi hex -> dec    : 0x13371337 = 322376503



## Check Function Argument



link chall: https://dreamhack.io/wargame/challenges/671

- cách giải bài này thì đã được nói ở tên bài và cả trong source code 

![image](https://hackmd.io/_uploads/ry7avprBkl.png)


- nó bảo flag sẽ là đối số của hàm ở dưới , là hàm ```sub_4015E2```

![image](https://hackmd.io/_uploads/BJaAP6HS1x.png)

- ta cũng thấy được khi gọi 1 hàm thì nó sẽ lấy từ các thanh ghi , full thanh ghi thì nó sẽ lấy từ stack , cụ thể ở đây là trước khi call ```sub_4015E2``` thì nó truyền 1 cái gì đó từ ```qword_4040D0``` vô thanh ghi ```rax``` và từ ```rax``` truyền vào ```rdi```

![image](https://hackmd.io/_uploads/SJrmdTHr1l.png)

dùng pwndbg để xem nó chứa cái gì thì nó sẽ là 1 con trỏ chứa địa chỉ của 1 chuỗi , ta có thể đổi nó thành chuỗi rồi xem là oke  

![image](https://hackmd.io/_uploads/BkA9KarSkl.png)

cách đơn giản hơn là nhìn vào reg ```rdi``` là có flag luôn

![image](https://hackmd.io/_uploads/HkXxcaSryl.png)


code để decode thành flag: 

```
#!/usr/bin/python3
hex_list = [
    "0x3a20656d2074756f",
    "0x692067616c462029",
    "0x6433367b48442073",
    "0x6332353330333062",
    "0x3665356639663961",
    "0x3530633935613862",
    "0x7d6565623732"
]

def hex_to_string(hex_list):
    result = ""
    for hex_string in hex_list:
        hex_string = hex_string[2:]
        print(f"after remove 0x {hex_string}")
        try:
            decode_part = bytes.fromhex(hex_string).decode('utf-8',errors='ignore')[::-1]
            result += decode_part
        except ValueError as e:
            print(f"chuoi khong hop le: {hex_string}, {e}")
    return result

decoded_string = hex_to_string(hex_list)
print(f"ket qua sau khi decode: {decoded_string}")
```

![image](https://hackmd.io/_uploads/Bk2P-ABHke.png)



## Easy Assembly


link chall : https://dreamhack.io/wargame/challenges/1095?writeup_page=1


check file : ![image](https://hackmd.io/_uploads/By5IR1wBJg.png)


![image](https://hackmd.io/_uploads/rk-_AkvSke.png)


- tiếp theo ta chạy nó thử thì nó yêu cầu 1 key làm đối số 

![image](https://hackmd.io/_uploads/HJf9CkvB1g.png)

- nhập đại 1 cái gì đó thì sẽ như thế này : 

![image](https://hackmd.io/_uploads/HyuiRyPS1x.png)

- vậy có lẽ bài này yêu cầu 1 key đúng , ta sẽ thử tìm chuỗi này bằng IDA và tham chiếu đến nó xem thử

![image](https://hackmd.io/_uploads/BJsxkxvH1e.png)

- ta thấy rõ ràng ở đây nó sẽ gọi hàm ```check_password``` , sau khi xong hàm này thì check xem ```eax``` có bằng 0 không?  , nếu không bằng thì là sai  , và ngược lại có lẽ là đúng , vậy ta sẽ thử phân tích từ đầu 

- biến v1 có lẽ là check xem có đối số nào được truyền không , nếu không thì in chuỗi lúc nãy ra 

![image](https://hackmd.io/_uploads/SkMukgwH1g.png)

- ta thấy khi ta nhập vào 1 chuỗi gì đó thì nó sẽ lưu ở stack , lúc này lệnh ```pop ecx``` sẽ thấy chuỗi của ta vào ecx và mov nó qua eax và gọi hàm strlen() để check độ dài chuỗi nhập vào

- hàm strlen() sẽ check xem byte này có phải là null không , nếu không thì tiếp tục tăng và cứ lặp lại , đây chắc chắn là 1 hàm tính độ dài của chuỗi 

![image](https://hackmd.io/_uploads/B14qxgvrye.png)


- tiếp tục phân tích ta thấy nó sẽ lưu giá trị vào ```0x804a10c``` , ecx lúc này chứa chuỗi ta nhập vào sẽ được di chuyển vào ```esi```  , enc_flag mov vào ```edi``` , ```xor ecx,ecx``` sẽ thiết lập ecx về 0 , ta thấy trước khi vào hàm check_password nó đã thiết lập tất cả các reg

![image](https://hackmd.io/_uploads/ByFPZlvByl.png)

-------- check_password : 

- đầu tiên ctrinh ```xor edx,edx``` để xóa dữ liệu trong edx để ở phía dưới nó sẽ xử lí dữ liệu ở thanh ghi này 
- tiếp theo là mov 1 byte là giá trị đầu tiên của ```esi``` cũng chính là chuỗi ta nhập vào -> dl  , tiếp theo byte này sẽ ```xor``` với độ dài của chuỗi ta nhập vào , cuối cùng là ```xor``` kí tự đầu của enc_flag với giá trị vừa được xor 

ta cần hiểu tính chất của xor : https://medium.com/@Harshit_Raj_14/useful-properties-of-xor-in-coding-bitwise-manipulation-and-bitmasking-2c332256bd61

- cuối cùng nó sẽ tăng các giá trị của các con trỏ chứa chuỗi lên 1 để tiếp tục loop và ```or ecx,edx``` -> thằng này sẽ rất quan trọng , nó sẽ được ```mov``` vào eax sau khi xong hàm ```check_password```



![image](https://hackmd.io/_uploads/HkI4zewSJx.png)


- ta cũng thấy được rằng nó sẽ check eax có bằng 0  không , nếu không bằng thì sẽ sai -> muốn eax bằng 0 -> ecx phải bằng 0 -> edx phải bằng 0 -> kết quả của các phép xor = 0  -> các giá trị này phải giống nhau , vd : 1 ^ 1 = 0 , 2 ^ 2 = 0
![image](https://hackmd.io/_uploads/Sk9m4ewH1l.png)

vậy đơn giản sẽ là input() ta nhập vào xor với len() = enc_flag  ->  enc_flag ^ len() = input()

- chuỗi enc_flag sẽ ở đoạn này : 

![image](https://hackmd.io/_uploads/S1E8HlPB1g.png)


- code tìm key : 


C
```
#include<stdio.h>

int main() {
    int arr[] = {0x74,0x78,0x4B,0x65 ,0x77 ,0x48 ,0x5C ,0x69  ,0x68 ,0x7E ,0x5C ,0x79 ,0x77 ,0x62 ,0x46 ,0x79
                ,0x77 ,0x05 ,0x46 ,0x54 ,0x73 ,0x72 ,0x59 ,0x69  ,0x68 ,0x7E ,0x5C ,0x7E ,0x5A ,0x61 ,0x57 ,0x6A
                ,0x77 ,0x66 ,0x5A ,0x52 ,0x02 ,0x62 ,0x5C ,0x79  ,0x77 ,0x5C ,0x00 ,0x7C ,0x57 ,0x0D ,0x0D ,0x4D};
    int lenght = sizeof(arr) / sizeof(arr[0]);
    int key[lenght];
    for(int i = 0;i<lenght;i++) {
        key[i] = arr[i] ^ lenght;
    }
    for(int i = 0;i<lenght;i++) {
        printf("%c",key[i]);
    }
    return 0;

}
```

python

```
enc_flag = [0x74,0x78,0x4B,0x65 ,0x77 ,0x48 ,0x5C ,0x69  ,0x68 ,0x7E ,0x5C ,0x79 ,0x77 ,0x62 ,0x46 ,0x79
,0x77 ,0x05 ,0x46 ,0x54 ,0x73 ,0x72 ,0x59 ,0x69  ,0x68 ,0x7E ,0x5C ,0x7E ,0x5A ,0x61 ,0x57 ,0x6A
,0x77 ,0x66 ,0x5A ,0x52 ,0x02 ,0x62 ,0x5C ,0x79  ,0x77 ,0x5C ,0x00 ,0x7C ,0x57 ,0x0D ,0x0D ,0x4D]

print(f"enc_flag: {enc_flag}\nwith len: {len(enc_flag)}")
key = [enc_flag[i] ^ len(enc_flag) for i in range(len(enc_flag))]

for i in key:
    print(chr(i),end="")
print()
```


---------------

## rev-basic-6



lại thêm  1 bài input đúng sai nữa

![image](https://hackmd.io/_uploads/BkTEyvdSJg.png)

- ta tham chiếu đến chuỗi "wrong thì sẽ thấy đoạn sau" , ở đây ta thấy ```sub_140001210``` có lẽ là hàm ```scanf``` , nhập xong thì lưu chuỗi input vào rcx và gọi hàm ```sub_140001000``` , kết thúc hàm nó sẽ dùng instruction ```test``` , lệnh này sẽ dùng phép ```and``` để check xem giá trị ```rax``` có bằng 0 không , nếu bằng thì đặt cờ ZF thành 1 nếu kết quả là 0 , instruction tiếp theo ```jz``` sẽ check cờ ZF , nếu 1 thì nhảy đến lable chứa chuỗi "wrong"

![image](https://hackmd.io/_uploads/SJ4wJPuS1l.png)

- đọc C cho dễ chứ tới khúc này đọc asm chắc lú người luôn :<

đây sẽ là 1 vòng loop 18 lần , nó sẽ check từng byte của  2 mảng này như sau:
- ```byte_140003020[input+i] ``` = ```byte_140003000```

![image](https://hackmd.io/_uploads/rkt9bDurkg.png)

- nó sẽ là cái mớ hỗn độn này 

![image](https://hackmd.io/_uploads/HyKY7POrJl.png)

- vậy tóm lại thứ ta cần tìm sẽ là idx+i thõa mãn giá trị của  2 mảng trên bằng nhau 

```
array_1 = [0x00, 0x4D, 0x51, 0x50, 0xEF, 0xFB, 0xC3, 0xCF, 0x92, 0x45, 
           0x4D, 0xCF, 0xF5, 0x04, 0x40, 0x50, 0x43, 0x63]

array_2 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 
           0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
           0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 
           0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
           0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 
           0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
           0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 
           0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
           0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 
           0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
           0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 
           0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
           0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 
           0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
           0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 
           0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
           0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 
           0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
           0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 
           0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
           0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 
           0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
           0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 
           0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
           0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 
           0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

# Tạo dictionary ánh xạ giá trị -> chỉ số
value_to_index = {value: index for index, value in enumerate(array_2)}

# Duyệt qua array_1 và tra cứu chỉ số từ dictionary
result = ""
for value in array_1:
    result += chr(value_to_index.get(value, 0))  #get dùng để lấy giá trị

print(result)
```

![image](https://hackmd.io/_uploads/Syrk3wOHyx.png)

1 solution khác : 

thằng a sẽ dò với mỗi giá trị của b[i] tương ứng với index nào trong a

```
a=[0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]
b=[0x00, 0x4D, 0x51, 0x50, 0xEF, 0xFB, 0xC3, 0xCF, 0x92, 0x45, 0x4D, 0xCF, 0xF5, 0x04, 0x40, 0x50, 0x43, 0x63]
print( ''.join(chr(a.index(b[i])) for i in range(len(b))))

```

code đơn giản nhất tuy nhiên độ phức tạp cao : 

```
array_1 = [  0x00, 0x4D, 0x51, 0x50, 0xEF, 0xFB, 0xC3, 0xCF, 0x92, 0x45, 
                0x4D, 0xCF, 0xF5, 0x04, 0x40, 0x50, 0x43, 0x63]

array_2 = [0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 
  0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76, 0xCA, 0x82, 0xC9, 0x7D, 
  0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 
  0x72, 0xC0, 0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 
  0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15, 0x04, 0xC7, 
  0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 
  0xEB, 0x27, 0xB2, 0x75, 0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 
  0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84, 
  0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 
  0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF, 0xD0, 0xEF, 0xAA, 0xFB, 
  0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 
  0x9F, 0xA8, 0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 
  0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2, 0xCD, 0x0C, 
  0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 
  0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 
  0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 
  0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 
  0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37, 0x6D, 
  0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 
  0xAE, 0x08, 0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 
  0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 
  0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 
  0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 
  0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 
  0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 
  0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16]

for i in array_1:
    input_ = 0
    for j in array_2:
        if(i==j):
            break
        else:
            input_ +=1
    print(chr(input_),end="")
print()

```
- cái này dễ hiểu hơn 1 tí : 

chỉ đơn giản là 2 vòng lặp lồng nhau , check từng giá trị của b với a và lấy idx ra nếu nó đúng 
```
a=[0x63,0x7C,0x77,0x7B,0xF2,0x6B,0x6F,0xC5,0x30,0x01,0x67,0x2B,0xFE,0xD7,0xAB,0x76,0xCA,0x82,0xC9,0x7D,0xFA,0x59,0x47,0xF0,0xAD,0xD4,0xA2,0xAF,0x9C,0xA4,0x72,0xC0,0xB7,0xFD,0x93,0x26,0x36,0x3F,0xF7,0xCC,0x34,0xA5,0xE5,0xF1,0x71,0xD8,0x31,0x15,0x04,0xC7,0x23,0xC3,0x18,0x96,0x05,0x9A,0x07,0x12,0x80,0xE2,0xEB,0x27,0xB2,0x75,0x09,0x83,0x2C,0x1A,0x1B,0x6E,0x5A,0xA0,0x52,0x3B,0xD6,0xB3,0x29,0xE3,0x2F,0x84,0x53,0xD1,0x00,0xED,0x20,0xFC,0xB1,0x5B,0x6A,0xCB,0xBE,0x39,0x4A,0x4C,0x58,0xCF,0xD0,0xEF,0xAA,0xFB,0x43,0x4D,0x33,0x85,0x45,0xF9,0x02,0x7F,0x50,0x3C,0x9F,0xA8,0x51,0xA3,0x40,0x8F,0x92,0x9D,0x38,0xF5,0xBC,0xB6,0xDA,0x21,0x10,0xFF,0xF3,0xD2,0xCD,0x0C,0x13,0xEC,0x5F,0x97,0x44,0x17,0xC4,0xA7,0x7E,0x3D,0x64,0x5D,0x19,0x73,0x60,0x81,0x4F,0xDC,0x22,0x2A,0x90,0x88,0x46,0xEE,0xB8,0x14,0xDE,0x5E,0x0B,0xDB,0xE0,0x32,0x3A,0x0A,0x49,0x06,0x24,0x5C,0xC2,0xD3,0xAC,0x62,0x91,0x95,0xE4,0x79,0xE7,0xC8,0x37,0x6D,0x8D,0xD5,0x4E,0xA9,0x6C,0x56,0xF4,0xEA,0x65,0x7A,0xAE,0x08,0xBA,0x78,0x25,0x2E,0x1C,0xA6,0xB4,0xC6,0xE8,0xDD,0x74,0x1F,0x4B,0xBD,0x8B,0x8A,0x70,0x3E,0xB5,0x66,0x48,0x03,0xF6,0x0E,0x61,0x35,0x57,0xB9,0x86,0xC1,0x1D,0x9E,0xE1,0xF8,0x98,0x11,0x69,0xD9,0x8E,0x94,0x9B,0x1E,0x87,0xE9,0xCE,0x55,0x28,0xDF,0x8C,0xA1,0x89,0x0D,0xBF,0xE6,0x42,0x68,0x41,0x99,0x2D,0x0F,0xB0,0x54,0xBB,0x16]
b=[0x00,0x4D,0x51,0x50,0xEF,0xFB,0xC3,0xCF,0x92,0x45,0x4D,0xCF,0xF5,0x04,0x40,0x50,0x43,0x63,0x00]
result = ""

for i in range(len(b)):
    for j in range(len(a)):
        if a[j] == b[i]:
            result += chr(j)
            break
print(result)
```

-------------

## Inject ME!!!



link chall  : 

![image](https://hackmd.io/_uploads/rkp5o2FSJx.png)


- ở bài này ta được cho 1 file ```.dll``` , ta sẽ thử tìm hiểu xem định dạng file này là gì : 

File DLL (Dynamic Link Library) là một tệp tin chứa mã nguồn và tài nguyên (resources) mà các chương trình khác có thể sử dụng. Tệp DLL thường được dùng trong hệ điều hành Windows để chia sẻ chức năng giữa nhiều ứng dụng mà không cần phải sao chép toàn bộ mã lệnh.

tóm gọn lại : file .dll giống như libc trong linux , mục đích để giảm kích thước của file exe (dùng chung các thư viện thay vì nhúng trực tiếp mã nguồn vào mỗi chương trình)

- đây sẽ là hàm main của dll : 

![image](https://hackmd.io/_uploads/HkSEn3trke.png)

sẽ có 3 điểm mà ta cần chú ý : 

- thứ nhất là hàm ```GetModuleFileNameA``` , nhìn vào tên thì nó lẽ là  1 hàm lấy tên file , để rõ hơn thì vào link này : https://learn.microsoft.com/en-us/windows/win32/api/libloaderapi/nf-libloaderapi-getmodulefilenamea , nó sẽ là 1 hàm thuộc Window API dùng để lấy đường dẫn đầy đủ đến tệp thực thi của 1 module đang được chạy load vào bộ nhớ và nó sẽ lấy 3 đối số  : 

```
DWORD GetModuleFileName(
    HMODULE hModule,   // Handle đến module (NULL nếu muốn lấy đường dẫn của tệp thực thi chính)
    LPSTR lpFilename,  // Bộ đệm để nhận đường dẫn của tệp
    DWORD nSize        // Kích thước tối đa của bộ đệm (tính bằng ký tự)
);

```

ví dụ : 

```
#include <windows.h>
#include <iostream>

int main() {
    char path[MAX_PATH]; // MAX_PATH là hằng số định nghĩa kích thước tối đa của đường dẫn
    DWORD size = GetModuleFileName(NULL, path, MAX_PATH);
    
    if (size > 0) {
        std::cout << "Executable Path: " << path << std::endl;
    } else {
        std::cerr << "Failed to get executable path. Error: " << GetLastError() << std::endl;
    }

    return 0;
}

```

vậy tóm lại là nó sẽ lấy path của ctrinh đang chạy và lưu vào ```Filename``` 

- tiếp theo sẽ là hàm ```PathFindFileName``` ,  nó cũng là 1 hàm API trong Window , nó sẽ lấy đối số là 1 path đến 1 file hoặc là 1 thư mục và trả về 1 con trỏ đến tên tệp

![image](https://hackmd.io/_uploads/HkrX0ntHkl.png)


vậy ở đây ta có tể thấy là nó sẽ dùng ```Strncmp``` để check xem thằng Str1 (là con trỏ tới file này) và chuỗi ```dreamhack.exe``` có giống nhau không

- nếu có thì nó sẽ in flag ra cho ta , bên dưới là hàm xử lí decode flag 

![image](https://hackmd.io/_uploads/ryrF0nKSye.png)


- vậy ta sẽ thử tạo 1 file dreamhack.exe và load dll vào thử như thế này  : 

```
#include <stdio.h>
#include <windows.h>

int main()
{
	LoadLibrary("prob_rev.dll");
	return 0;
}
```


flag sẽ hiện ra 
![image](https://hackmd.io/_uploads/r1ksgaFrJx.png)


## Check Return Value



description : 
```
This problem is given by a program that calls a function from the main function.

This function returns the address of a string containing flags. However, it doesn't print that string.

Obtain flags by checking the function's return value through dynamic debugging!

The flag format isDH{...}.
```

- tên bài và description như 1 lời gợi ý cho ta -> ta cần check giá trị trả về của các hàm xem sao 

- chạy thử thì nó sẽ in ra như thế này , và strings cũng không tìm thấy dữ liệu gì

![image](https://hackmd.io/_uploads/rkqmGJhS1g.png)

- ta sẽ thử tìm địa chỉ in chuõi đó ra và dùng gdb để debug

![image](https://hackmd.io/_uploads/HJ6BMy3rJl.png)

- flag ở ```rax``` 

![image](https://hackmd.io/_uploads/HkIdf1hrJe.png)




## rev-basic-8


- lại là 1 bài input đúng sai tương tự các bài basic khác , ta sẽ cùng xem điều kiện thõa mãn của nó là gì? 



- loop 21 lần , check xem input nhập vào nhân với -5 có bằng ```byte_140003000[i]``` không?

```input[i] * -5 == byte_140003000[i]``` thì sẽ thõa điều kiện , vậy ở bài này ta sẽ tìm input[i] , 
tuy nhiên có 1 vấn đề nữa là nó sẽ ép kiểu về ```unsigned __int8```
![image](https://hackmd.io/_uploads/rkKB1Nnrkg.png)

- vậy bài toán sẽ chuyển thành : 

```(c⋅(−5))mod256=a[i]``` , vậy muốn tìm được c thì c sẽ bằng
```c=(a[i]⋅nghịch đảo modular của −5mod256)mod256``` tuy nhiên tính toán quá trình này khá phức tạp nên ta sẽ làm cách khác đó là brute_force 

- ở đây nó sẽ lấy input của ta nhân với 0xFb và & 0xff -> những kí tự của flag nhập từ bàn phím là 0x21 -> 0x7E 

![image](https://hackmd.io/_uploads/H1uGlShS1l.png)

script 

```
lst = [0xAC, 0xF3, 0x0C, 0x25, 0xA3, 0x10, 0xB7, 0x25, 0x16, 0xC6, 
  0xB7, 0xBC, 0x07, 0x25, 0x02, 0xD5, 0xC6, 0x11, 0x07, 0xC5]
flag = ""
for i in range(len(lst)):
    for j in range(0x21,0x7F):
        if (j*0xFb) & 0xff == lst[i]:
            flag += chr(j)
            break
print(flag)
        
```

- hoặc đơn giản là ta sẽ dùng numpy  để ép kiểu và bruteforce như ở trên:

```
import numpy as np

lst = [0xAC, 0xF3, 0x0C, 0x25, 0xA3, 0x10, 0xB7, 0x25, 0x16, 0xC6, 
  0xB7, 0xBC, 0x07, 0x25, 0x02, 0xD5, 0xC6, 0x11, 0x07, 0xC5]
flag = ""
for i in range(len(lst)):
    for j in range(255):
        if np.uint8(-5*j) == lst[i]:
            flag += chr(j)
            break
print(flag)
            
    
    
```

## reverse basic 7


- bài này giống với các bài trước nên ta chỉ cần biết cách nó mã hóa dữ liệu

![image](https://hackmd.io/_uploads/ry6Ayz_Ukg.png)


lần này nó loop 31 lần , tuy nhiên ta thấy ở đây nó dùng ```ROL``` , đây là phép dịch vòng lấy 2 tham số , tham số đầu tiên là dữ liệu của ta và tham số thứ 2 là số bit cần dịch , tóm tắt nó sẽ như sau : 

```i ^ ROL(a[i],i&7) = byte[i]``` , nếu thõa mãn điều kiện này thì ta có flag , ở đây ta sẽ tìm a , ta có thể đổi lại nó như thế này : 


```a[i] = ROR(i^byte[i] , i&7)``` , ta sẽ dùng phép ```ROR``` để thực hiện tìm ```input```

ta sẽ tìm lại dữ liệu bằng cách sau: 

```
ví dụ : 
10101101 xoay phải 7 bit 01011011  , bây giờ muốn tìm lại dữ liệu cũ thì ta xoay trái 7 bit : 

đầu tiên dịch trái n bit (trong trường hợp này là 7 ) :

01011011 -> 10000000  

tiếp theo dịch phải (8-n) bit ( trong trường hợp này là 7 ) :

01011011 -> 00101101

- cuối cùng ta ```or``` 2 kết quả lại với nhau sẽ ra kết quả ban đầu 


10000000 | 00101101 = 10101101 ( và đây là kết quả ban đâu của ta)

đây là phép dịch trái , dịch phải thì cứ làm ngược lại
```

script 

```
array = [0x52, 0xDF, 0xB3, 0x60, 0xF1, 0x8B, 0x1C, 0xB5, 0x57, 0xD1, 
         0x9F, 0x38, 0x4B, 0x29, 0xD9, 0x26, 0x7F, 0xC9, 0xA3, 0xE9, 
        0x53, 0x18, 0x4F, 0xB8, 0x6A, 0xCB, 0x87, 0x58, 0x5B, 0x39, 0x1E]

def ror(x,y):
    shift = x >> y
    left = x << (8-y)
    left &= 255
    return shift | left

for i in range(len(array)):
    print(chr(ror(i^array[i],i&7)),end='')
print()
```

![image](https://hackmd.io/_uploads/HJpjrfu8kg.png)


## Small Counter

- description :  gọi hàm flag_gen() và get flag ....

![image](https://hackmd.io/_uploads/BkfeBF-Jyx.png)



phân tích :

sẽ có 1 vòng lặp 10 lần , nếu i = 3 thì in chuỗi kia ra 

sau vòng lặp mà i vẫn = 5 thì có flag 


![image](https://hackmd.io/_uploads/B14Ert-Jkl.png)


- đơn giản là ta sẽ dùng gdb để set giá trị cho i
![image](https://hackmd.io/_uploads/rkaKSYZk1g.png)


- đặt breakpoint ở main+278
![image](https://hackmd.io/_uploads/Bk4eIYZk1x.png)


bumpppp , lấy flag thôi :)))
![image](https://hackmd.io/_uploads/HyYZIFWJJx.png)

## Recover

- ta được cho  2 file , 1 file chall và 1 file encrypted

- chạy thử thì nó bảo fopen() thất bại 

![image](https://hackmd.io/_uploads/rJBKP6_ikx.png)


- ta sẽ mở IDA lên thử 


```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  char ptr; // [rsp+Bh] [rbp-25h] BYREF
  int v5; // [rsp+Ch] [rbp-24h]
  _BYTE *v6; // [rsp+10h] [rbp-20h]
  FILE *stream; // [rsp+18h] [rbp-18h]
  FILE *s; // [rsp+20h] [rbp-10h]
  unsigned __int64 v9; // [rsp+28h] [rbp-8h]

  v9 = __readfsqword(0x28u);
  v6 = &unk_2004;
  stream = fopen("flag.png", "rb");
  if ( !stream )
  {
    puts("fopen() error");
    exit(1);
  }
  s = fopen("encrypted", "wb");
  if ( !s )
  {
    puts("fopen() error");
    fclose(stream);
    exit(1);
  }
  v5 = 0;
  while ( fread(&ptr, 1uLL, 1uLL, stream) == 1 )
  {
    ptr ^= v6[v5 % 4];
    ptr += 19;
    fwrite(&ptr, 1uLL, 1uLL, s);
    ++v5;
  }
  fclose(stream);
  fclose(s);
  return 0LL;
}
```

- 1 bài khá ngắn , ta thấy đầu tiên nó sẽ mở file `flag.png` với mode 'rb' và tiếp theo là mở `encrypted` với mode 'wb' , tiếp theo là 1 loop 
- nó sẽ đọc từng byte của flag.png vào `ptr` , tiếp theo sẽ xor với v6[v5%4]  với mảng v6 chứa 4  key và tiếp theo là trừ đi 19 , cuối cùng là ghi byte đó vào `encrypted`
![image](https://hackmd.io/_uploads/BJevuadsJl.png)


- vậy ở bài này việc ta cần làm là đọc các byte từ encrypted và đảo ngược lại quá trình mã hóa để có được flag.png 


```python
# key = [0xDE, 0xAD, 0xBE, 0xEF]
# with open("encrypted","rb") as f,open("flag.png","wb") as h:
#     data = f.read()
#     i = 0
#     decrypt_data = bytearray()
#     for j in data:
#         decrypt_ogi = ((j-19) ^ (key[i%4])) & 0xff
#         decrypt_data.append(decrypt_ogi)
#     h.write(decrypt_data)
        
        
key = [0xDE, 0xAD, 0xBE, 0xEF]
with open("encrypted","rb") as f,open("flag.png","wb") as z:
    data_encrypt = bytearray()
    data = f.read()
    for i, j in enumerate(data):
        nothing = (((j  - 19) ^ key[i%4]) & 0xff)
        data_encrypt.append(nothing)
    z.write(data_encrypt)
             
```

![flag](https://hackmd.io/_uploads/HkdIESFoye.png)

## legacyopt


- chạy thử thì nó cho ta input cái gì đó , nhập đại thì nó trả về 1 nùi số 

![image](https://hackmd.io/_uploads/BJ1EwHtsyg.png)

- ngoài ra ta cũng được cho 1 file output.txt với nội dung

`220c6a33204455fb390074013c4156d704316528205156d70b217c14255b6ce10837651234464e`

- ở đây ta có thể để ý , nếu ta nhập 1 kí tự thì nó sẽ trả về 1 số , vậy ta có thể biết được độ dài flag luôn và có thể brute_force , tuy nhiên mình không thích làm theo cách này 


- ta sẽ mở IDA và cùng phân tích 


đầu tiên là malloc() 1 vùng heap , sau đó nhập dữ liệu vào và truyền vào hàm `encrypted`

```c
__int64 __fastcall main(int a1, char **a2, char **a3)
{
  unsigned int v3; // eax
  int i; // [rsp+4h] [rbp-8Ch]
  char *ptr; // [rsp+8h] [rbp-88h]
  char buf[104]; // [rsp+10h] [rbp-80h] BYREF
  unsigned __int64 v8; // [rsp+78h] [rbp-18h]

  v8 = __readfsqword(0x28u);
  ptr = (char *)malloc(0x64uLL);
  fgets(buf, 100, stdin);
  buf[strcspn(buf, "\n")] = 0;
  v3 = strlen(buf);
  encrypted(ptr, buf, v3);
  for ( i = 0; i < strlen(buf); ++i )
    printf("%02hhx", ptr[i]);
  free(ptr);
  return 0LL;
}
```

- encrypted: 

    -    đầu tiên ta thấy rằng nó cộng độ dài input của ta thêm 7 và check xem nó có bé hơn 0 không , tiếp theo là dịch phải  bit -> tương đương với chia cho 2^3 và nó sẽ lấy phần nguyên , tiếp theo là chia lấy dư độ dài input và gán vào result  
    -    vậy đơn giản là đầu tiên nó sẽ mã hóa phần dư trước , sau đó mã hóa 8 byte theo thứ tự 







```c
unsigned __int64 __fastcall encrypted(_BYTE *ptr, char *buf, int lenght)
{
  int v3; // eax
  int v4; // edx
  unsigned __int64 result; // rax
  char *v6; // rax
  char v7; // cl
  _BYTE *v8; // rax
  char *v9; // rax
  char v10; // cl
  _BYTE *v11; // rax
  char *v12; // rax
  char v13; // cl
  _BYTE *v14; // rax
  char *v15; // rax
  char v16; // cl
  _BYTE *v17; // rax
  char *v18; // rax
  char v19; // cl
  _BYTE *v20; // rax
  char *v21; // rax
  char v22; // cl
  _BYTE *v23; // rax
  char *v24; // rax
  char v25; // cl
  _BYTE *v26; // rax
  char *v27; // rax
  char v28; // cl
  int v32; // [rsp+20h] [rbp-4h]

  v3 = lenght + 7;
  v4 = lenght + 14;
  if ( v3 < 0 )
    v3 = v4;
  v32 = v3 >> 3;
  result = (unsigned int)(lenght % 8);
  switch ( (int)result )
  {
    case 0:
      goto LABEL_4;
    case 1:
      goto LABEL_11;
    case 2:
      goto LABEL_10;
    case 3:
      goto LABEL_9;
    case 4:
      goto LABEL_8;
    case 5:
      goto LABEL_7;
    case 6:
      goto LABEL_6;
    case 7:
      while ( 1 )
      {
        v9 = buf++;
        v10 = *v9;
        v11 = ptr++;
        *v11 = v10 ^ 0x66;
LABEL_6:
        v12 = buf++;
        v13 = *v12;
        v14 = ptr++;
        *v14 = v13 ^ 0x44;
LABEL_7:
        v15 = buf++;
        v16 = *v15;
        v17 = ptr++;
        *v17 = v16 ^ 0x11;
LABEL_8:
        v18 = buf++;
        v19 = *v18;
        v20 = ptr++;
        *v20 = v19 ^ 0x77;
LABEL_9:
        v21 = buf++;
        v22 = *v21;
        v23 = ptr++;
        *v23 = v22 ^ 0x55;
LABEL_10:
        v24 = buf++;
        v25 = *v24;
        v26 = ptr++;
        *v26 = v25 ^ 0x22;
LABEL_11:
        v27 = buf++;
        v28 = *v27;
        result = (unsigned __int64)ptr++;
        *(_BYTE *)result = v28 ^ 0x33;
        if ( --v32 <= 0 )
          break;
LABEL_4:
        v6 = buf++;
        v7 = *v6;
        v8 = ptr++;
        *v8 = v7 ^ 0x88;
      }
      break;
    default:
      return result;
  }
  return result;
}
```

- vậy tóm lại input của ta phải là 39 kí tự có format là DH{.....}  -> 39 % 8 = 7 và nó sẽ xor flag theo thứ tự `0x66->0x44->0x11->0x77->0x55->0x22->0x33->0x88`


exp: 

```python
from Crypto.Util.number import *

string_val = "220c6a33204455fb390074013c4156d704316528205156d70b217c14255b6ce10837651234464e"
key_val = "6644117755223388"

flag = bytearray()
string_val_byte = bytes.fromhex(string_val)
key_val_byte = bytes.fromhex(key_val)

for i,j in enumerate(string_val_byte):
    flag.append(j ^ key_val_byte[i % len(key_val_byte)])
print("this is flag: ",flag.decode())
```

`DH{Duffs_Device_but_use_memcpy_instead}`

- sau khi tham khảo writeup thì ta sẽ còn 3 cách nữa (  byte brute-force (pwntools) , 1 byte brute-force (gdb script)  , Cách chuyển đổi đầu ra thành đầu vào)

-  byte of bandwidth (pwntools)

- đầu tiên ý tưởng sẽ là đọc tất cả các bytes của `output.txt` , tiếp theo là gửi từng kí tự in được và check xem output[idx] có khớp với output.txt[idx] không , nếu có thì đó sẽ là flag đúng 

exp: 

```python
#!/usr/bin/python3
from pwn import *
from string import printable

flag = ""
output = bytes.fromhex(open('output.txt',"r").read())
for i in range(len(output)):
    for j in printable:
        input = (flag + j).ljust(len(output),'a')
        p = process('./legacyopt')
        p.sendline(input.encode())
        recv = bytes.fromhex((p.recv(2*len(output))).decode())
        p.close()
        if recv[i] == output[i]:
            flag += j
            break
print(flag)
```

script gdb

```python
# gdb -q -x 1byte-bf-gdbscript.py
import gdb

white_list = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ{_}0123456789"

ge = gdb.execute
gp = gdb.parse_and_eval

ge("file ./legacyopt")

out = bytes.fromhex(open("output.txt", "r").read())

pie_base = 0x555555554000
gdb.Breakpoint(f"*{pie_base + 0x140E}")

with open("log", "w") as f:
    f.write("")

flag = ""
while len(flag) != len(out):
    for c in white_list:
        inp = (flag + c).ljust(len(out), "A")

        with open("input.txt", "w") as f:
            f.write(inp)
        
        ge("run < input.txt", to_string=True)

        target = int(gp("$rdi"))
        ge("ni", to_string=True)
        inferior = gdb.selected_inferior()
        res = bytes(inferior.read_memory(target, len(out)))

        if res[len(flag)] == out[len(flag)]:
            flag += c
            with open("log", "a") as f:
                f.write(flag + "\n")
            print(f"flag found {flag}")
            break

print(flag)
```


## please, please, please


- bài này mở IDA + shift f12 :v



## reverse-basic-7

- ta thấy khi thử chạy file thì nó yêu cầu ta nhập input , nhập xong thì nó cũng thoát chương trình

![image](https://hackmd.io/_uploads/rJjdDncjJe.png)

- check IDA: 

nhìn sơ qua thì đoán đây có lẽ là 1 bài check đúng sai password

![image](https://hackmd.io/_uploads/H1vjvn9jyl.png)


- đây sẽ là hàm mà ta cần xử lí , code rất ngắn gọn , có 1 loop và nó sẽ xor `i` với dữ liệu đã được `ROL` , ở đây `ROL` chính là dịch vòng với 2 tham số , tham số thứ nhất là dữ liệu và tham số thứ hai sẽ là số bit cần dịch và ở đây nó giới hạn trong 8 bit 



```c
__int64 __fastcall sub_140001000(__int64 a1)
{
  int i; // [rsp+0h] [rbp-18h]

  for ( i = 0; (unsigned __int64)i < 0x1F; ++i )
  {
    if ( (i ^ (unsigned __int8)__ROL1__(*(_BYTE *)(a1 + i), i & 7)) != byte_140003000[i] )
      return 0LL;
  }
  return 1LL;
}
```

- vậy ta có thể tưởng tượng nó như sau: 

`i ^ ROL(a[i],i&7) != arr[i]` , `a[i]` là cái cần được tìm ở bài này  -> `a[i] ^ i == ROL(a[i],i&7)`  , ở đây ta có thể brute_force byte của a[i] 

exp

```python
def rol(val,r_bit):
    return ((val << r_bit) & 0xff) | (val >> (8-r_bit))
array = [0x52, 0xDF, 0xB3, 0x60, 0xF1, 0x8B, 0x1C, 0xB5, 0x57, 0xD1, 0x9F, 0x38, 0x4B, 0x29, 0xD9, 0x26, 0x7F, 0xC9, 0xA3, 0xE9, 0x53, 0x18, 0x4F, 0xB8, 0x6A, 0xCB, 0x87, 0x58, 0x5B, 0x39, 0x1E]
flag = "DH{"
for i in range(len(array)):
    for j in range(256):
        if rol(j,i&7) == array[i] ^ i:
            flag += chr(j)
            break
print(flag + "}")
            
            
```

- còn 1 cách khác để không phải brute_force đó là ta sẽ dùng `ROR` 


`i ^ ROL(a[i], i & 7) = byte[i]` -> ta sẽ xor với i cả 2 vế : 

`ROL(a[i], i & 7) = byte[i] ^ i` -> bây giờ ta sẽ muốn tìm a[i] , vậy a[i] sẽ bằng: 

`a[i] = ROR(byte[i] ^ i, i & 7)
`

exp2 : 

```python
array = [0x52, 0xDF, 0xB3, 0x60, 0xF1, 0x8B, 0x1C, 0xB5, 0x57, 0xD1, 
         0x9F, 0x38, 0x4B, 0x29, 0xD9, 0x26, 0x7F, 0xC9, 0xA3, 0xE9, 
        0x53, 0x18, 0x4F, 0xB8, 0x6A, 0xCB, 0x87, 0x58, 0x5B, 0x39, 0x1E]

def ror(val,bit):
    return (val >> bit) | ((val << (8-bit)) & 0xff)

flag = "DH{"
# a[i] = ROR(array[i] ^ i, i & 7)
for i in range(len(array)):
    flag += (chr(ror(array[i] ^ i,i & 7)))
print(flag + "}") 

```


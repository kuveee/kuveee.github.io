--- 
title: Reversing.kr 
date: 2025-02-16 00:00:00 +0800
categories: [reversing]
tags: [reversing]
author: "kuvee"
layout: post
---

# Easy Crack

check file này thì thấy đây là file PE 32bit

![image](/assets/images/reversing_kr/1.png)

- ta được nhập password vào và tất nhiên nó sẽ không đúng

![image](/assets/images/reversing_kr/2.png)

- trước hết ta thấy WinMain sẽ gọi hàm ```DialogBoxParamA``` và mình có khá ít kinh nghiệm với rev window nên ta đi search thôi :))

![image](/assets/images/reversing_kr/3.png)

[here](https://learn.microsoft.com/en-us/windows/win32/api/winuser/nf-winuser-dialogboxparama) 

```c
INT_PTR DialogBoxParamA(
  HINSTANCE hInstance,
  LPCSTR lpTemplateName,
  HWND hWndParent,
  DLGPROC lpDialogFunc,
  LPARAM dwInitParam
);

```

- nói đơn giản là hàm này giúp hiển thị một hộp thoại trong Windows mà người dùng phải tương tác trước khi quay lại cửa sổ chính.

- đây có lẽ là hàm xử lí chính của bài

![image](/assets/images/reversing_kr/4.png)

- giải thích về ```GetDlgItemTextA```

```
UINT GetDlgItemTextA(
  HWND hDlg,      // Handle của hộp thoại
  int nIDDlgItem, // ID của control cần lấy văn bản
  LPSTR lpString, // Bộ đệm để lưu văn bản
  int cchMax      // Kích thước tối đa của bộ đệm
);

```
vậy ta sẽ được input 100 số vào , tiếp theo là 1 đoạn check , check graph ta có thể thấy được ```Congratulation``` ở bên dưới

![image](/assets/images/reversing_kr/5.png)

- tuy nhiên nó sẽ trãi qua hàng loạt lệnh check qua từng giai đoạn , đầu tiên sẽ là string+1 với 'a' -> ascii của nó là 97  , tiếp theo ta thấy nó push ecx , mà ecx là địa chỉ chứa kí tự thứ ba của ta và nó gọi hàm ```_strncmp``` nhìn qua thì cũng đoán được là nó sẽ check byte thứ ba và thứ 4 với '5y' , kết quả của hàm sẽ trả về eax  và nếu eax khác 0 thì sẽ end chương trình  
- 

![image](/assets/images/reversing_kr/6.png)

- tiếp theo nữa là đưa địa chỉ chứa string+4 vào eax và esi cũng chứa địa chỉ chứa chuỗi ```R3versing```  và gọi hàm ```loc_4010DA``` , ta thấy hàm đó sẽ check từng byte của string+4 với từng kí tự của chuỗi ```R3versing```

![image](/assets/images/reversing_kr/7.png)

- ta có thể thấy 1 điều nữa là ở hàm ```loc_401102``` sử dụng lệnh ```sbb     eax, 0FFFFFFFFh``` , lệnh này sẽ tương tự như inc eax nếu CF flag không được đặt và sẽ giữ nguyên nếu CF được đặt , có nghĩa là đoạn cmp ở trên nếu dl < bl -> nó sẽ mượn và CF sẽ được đặt , nói chung khá rắc rối nhưng ta sẽ cần tránh nhảy vào đây



![image](/assets/images/reversing_kr/8.png)


- cuối cùng là check kí tự đầu với 'E'

![image](/assets/images/reversing_kr/9.png)

- vậy tóm lại chuỗi cần input vào là 'Ea5yR3versing'


1 bài khá hay để đọc code asm :D


![image](/assets/images/reversing_kr/10.png)



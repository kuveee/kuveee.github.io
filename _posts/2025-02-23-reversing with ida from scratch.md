---
title: REVERSING WITH IDA FROM SCRATCH
date: 2025-02-10 00:00:00 +0800
categories: [rev]
tags: [rev]
author: "kuvee"
layout: post
hidden: true
---

- ở IDA ta có thể setting như hình để mọi thứ dễ nhìn hơn , ta sẽ chọn options -> general  và chọn các option tùy thích (number of opcode bytes đôi lúc sẽ có ích)

![here](https://miro.medium.com/v2/resize:fit:640/format:webp/1*l2Aehow7WoCigk9M926CLQ.png)

- ở đây ta cũng cần biết các hệ thống số hoạt động thế nào , có rất nhiều tuy nhiên ta chỉ làm việc với (dec , hex , bin) là chính , như đã biết , số 0 và 1 sẽ là cách máy tính hiểu và xử lí nhưng nó lại rất nhiều số và phức tạp , đó là lí do hex được thay thế 

- ngoài ra ta cũng cần hiểu về số âm trong hệ 16 , cũng giống như lúc ta code , khi ta khai báo 1 biến kiểu ```int``` thì lúc này máy tính được yêu cầu phải biểu diễn theo số âm và sẽ bỏ qua bit có trọng số cao nhất (MSB) , ta sẽ xem nó như là bit dấu . nếu nó là 0 thì số đó là dương và ngược lại 

ví dụ : 

-0x45 sẽ được biểu diễn là ```0xffffffbb``` và bit đầu tiên là 1 
![here](https://miro.medium.com/v2/resize:fit:640/format:webp/1*EViuzELNBjtooV-ah_Zfvg.png)

## mã ascii

- đây là 1 vấn đề khác cũng quan trọng không kém , những kí tự được in trên màn hình sẽ được gán tương ứng với 1 giá trị hex , chúng có thể là chữ cái , chữ số , hay biểu tượng

- Bảng mã ASCII được đùng để hiển thị văn bản trong máy tính và các thiết bị thông tin khác, nó cũng được dùng bởi các thiết bị điều khiển làm việc với văn bản

![here](https://miro.medium.com/v2/resize:fit:640/format:webp/0*ZVsmVF4-PIq7ahSr)


## Search Immediate Value — Search Next Immediate Value

- lệnh này tìm kiếm lệnh đầu tiên hoặc byte dữ liệu có giá tri hằng số được chỉ định 

![here](https://miro.medium.com/v2/resize:fit:546/format:webp/1*aialbNqy17aBAX_N0ckuZA.png)
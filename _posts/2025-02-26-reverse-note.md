---
title: note reverse
date: 2025-02-12 00:00:00 +0800
categories: [rev]
tags: [rev]
author: "kuvee"
layout: post
published: false
---


1 số note trong quá trình học reverse

## ngôn ngữ lập trình

- có rất nhiều ngôn ngữ lập trình khác nhau như C++ , java , python , php , lua ..... , các ngôn ngữ có cấp độ càng cao thì càng xa phần cứng thì con người càng dễ đọc và viết . vd : C# là ngôn ngữ cấp rất cao và asm là ngôn ngữ cấp thấp

- mỗi ngôn ngữ điều có nhiệm vụ thực hiện chính khác nhau , javascript dc sử dụng trong các ứng dung web , c/c++ được sử dụng cho phần mềm ....
- có 2 loại ngôn ngữ chính : ngôn ngữ biên dịch và ngôn ngữ thông dịch :
  - ngôn ngữ biên dịch: được biên dịch trực tiếp thành mã máy . bất kì máy tính nào được biên dịch đều có thể chạy trực tiếp chương trình và chúng không cần chương trình bổ sung để chạy , Ví dụ, nếu bạn muốn chạy chương trình Java, trước tiên bạn cần cài đặt Java Runtime Environment (JRE) . Tuy nhiên, để chạy chương trình C++, bạn không cần bất kỳ thứ gì giống như JRE. Mặc dù bạn có thể cần tải xuống và cài đặt thư viện mã.
  - ngôn ngữ thông dịch:  không được biên dịch trực tiếp thành mã máy  mà thay vào đó được thông dịch/dịch gián tiếp từ mã nguồn của chúng thành mã máy ,  Việc thông dịch này có thể được thực hiện bằng cách biên dịch các phần hoặc thậm chí các dòng mã riêng lẻ rồi thực thi phần đó . vd: khi ta chạy 1 chương trình python , về cơ bản mỗi dòng được biên dịch rồi thực thi riêng lẻ . ưu điểm của việc này là chương trình không cần phải được viết lại hoặc biên dịch cho các hệ thống cụ thể . Thay vào đó, người dùng chỉ cần cài đặt phần mềm bổ sung phù hợp để chạy phần mềm của bạn. Nhược điểm lớn nhất của việc này là chúng có xu hướng chậm hơn đáng kể so với các ngôn ngữ được biên dịch.
- ngôn ngữ trung gian: 

Việc nói về các ngôn ngữ trung gian là cực kỳ quan trọng. Hãy lấy Java làm ví dụ. Một chương trình được viết bằng Java được biên dịch thành cái gọi là Java Bytecode , đây cũng là tệp nhị phân/thực thi sẽ được phân phối. Bạn có thể coi bytecode này là mã máy/mã biên dịch của ngôn ngữ lập trình. Lưu ý rằng đây không phải là mã máy gốc thực sự. Hệ thống không thể hiểu được bytecode này nên cần có thứ gì đó để dịch bytecode đó thành mã máy. Để chạy chương trình Java, bạn phải "cài đặt Java" (cụ thể là Java Runtime Environment (JRE) ), sau đó cung cấp trình biên dịch cho bytecode. Trình biên dịch này sẽ dịch bytecode thành mã máy. Khi chương trình được thực thi, bytecode được Java Virtual Machine (JVM) diễn giải , đây là một phần của JRE. Khi JVM diễn giải bytecode, nó sẽ dịch bytecode thành mã máy, sau đó có thể được thực thi gốc. Trình biên dịch thực hiện kiểu biên dịch và thực thi này được coi là trình biên dịch Just-In-Time (JIT) . Những loại ngôn ngữ này có lợi thế là có thể di chuyển được vì miễn là người dùng cài đặt trình thông dịch, họ có thể chạy nó trên bất kỳ kiến ​​trúc nào. Tất nhiên, bản thân trình thông dịch sẽ dành riêng cho kiến ​​trúc đó.

- .NET tương tự như Java. Lưu ý nhanh, .NET bao gồm nhiều ngôn ngữ, nhưng C# là ngôn ngữ "chính" của .NET. .NET được biên dịch thành Microsoft Intermediate Language (MSIL), chỉ là mã byte. Mã byte này sau đó được chạy bởi một phần của .NET Framework. Phần của .NET Framework mà tôi đang đề cập là Common Language Runtime (CLR). CLR bao gồm thu gom rác, các vấn đề bảo mật và trình biên dịch JIT. Trình biên dịch JIT đó sẽ diễn giải mã byte thành mã máy giống như Java Runtime Environment (JRE) làm. Như tôi đã nói, .NET rất giống Java về cách biên dịch và thực thi.

- Một lợi thế lớn khác của những loại ngôn ngữ này là bảo mật. Mọi thứ đều chạy qua một loại máy ảo nào đó có thể thực hiện tất cả các loại kiểm tra và quản lý bảo mật. Thu gom rác là một lợi thế lớn xứng đáng được nhắc lại. Thu gom rác giúp công việc của các lập trình viên dễ dàng hơn trong khi cũng tự động xử lý quản lý bộ nhớ, điều này tốt cho bảo mật.



## IDA loader

- khi ta mở 1 file thực thi trong ida , nó sử dụng bộ phân tích tĩnh để phân tích file hay còn được gọi là loader . ở chế độ loader , chương trình kh được thực thi nhưng nó được ida phân tích và tạo ra 1 file .idb (csdl lưu thông tin phan tích) , bao gồm đổi tên biến , comment nó là tổng hợp của 5 files(.id0 , .id1, .nam , .id2 ) được sinh ra trong quá trình phân tích  , nói chung trong quá trình ta phân tích ta thay đổi thì nó sẽ lưu ở database và không tác động lên file binary gốc , ta có thể xác nhận bằng cách mở task manager lên xem 


## các instruction asm
phần này sẽ là các lệnh tính toán và logic.
### add

trường hợp này ecx có giá trị là 0x10000 , nó sẽ được cộng thêm 4 , kết quả thu được là 0x10004 lưu vào thanh ghi ecx
![here](https://miro.medium.com/v2/resize:fit:720/format:webp/1*ws7YtNJI0JFfm97IRDb7mg.png0)

trường hợp này , lệnh add cộng giá trị 0xffffffff vào giá trị có được tại địa chỉ ecx+30 , và nếu nó có quyền ghi -> nó sẽ cộng thêm và lưu kết quả ở đó

![here](https://miro.medium.com/v2/resize:fit:720/format:webp/1*qs2D4k4vmCRLCMtNfpvirQ.png)

phép sub ngược lại tương tự 

###  IMUL

Đây là lệnh thực hiện phép tính nhân số có dấu và có hai dạng như sau:

IMUL A, B ; A = A * B

IMUL A, B, C ; A = B * C


Bên lề: Tại sao lại là câu lệnh imul (signed multiply) mà không phải là câu lệnh mul (unsigned multiply)? Đó là bởi trình Visual Studio dường như có một sự ưa thích đối với lệnh imul. Kể cả khi bạn khai báo biến có kiểu unsigned trong chương trình, khi compile code và chuyển qua assembly thì sẽ thấy chương trình sử dụng câu lệnh imul.

### div/idiv

Trong câu lệnh này, A được hiểu là số chia. Số bị chia và thương số không được chỉ định bởi vì chúng luôn giống nhau. Tức là có 3 dạng như sau:

Nếu A có kiểu byte, lấy giá trị của thanh ghi AX chia cho A, kết quả thương số lưu vào thanh ghi AL, phần dư lưu vào thanh ghi AH.
Nếu A có kiểu word, lấy giá trị của cặp thanh ghi DX:AX chia cho A, kết quả thương số lưu vào thanh ghi AX, phần dư lưu vào thanh ghi DX.
Nếu A có kiểu dword, lấy giá trị của cặp thanh ghi EDX:EAX chia cho A, kết quả thương số lưu vào thanh ghi EAX, phần dư lưu vào thanh ghi EDX.


### điều khiển luồng thực thi chương trình

- như đã biết EIP luôn trỏ vào lệnh tiếp theo được thực hiện và ta cũng có thể control điều này trong IDA

#### Lệnh nhảy không điều kiện

- jmp : lệnh này giống như lệnh goto trong lập trình bậc cao , nó không phụ thuộc vào điều kiện 

![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*NYVqS-eaE05wVIR_)


JMP SHORT là một lệnh nhảy ngắn gồm có 2 bytes, có khả năng nhảy về phía trước và ngược lại. Hướng nhảy được chỉ định bởi giá trị của byte thứ hai vì byte đầu tiên là opcode (0xEB) của lệnh. Lệnh này không thể nhảy quá xa.

![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*zN5VlfIvA6Ty17Fy)

opcode EB tương ứng với lẹnh jmp và lệnh này sẽ nhảy 5 bước về phía trước kể từ vị trí kết thúc lệnh

![here](https://miro.medium.com/v2/resize:fit:482/format:webp/1*zKd2SsoEXUj90wGhHfKJ1Q.png)

- lấy địa chỉ bắt đầu cộng với 2 là số byte chiếm bởi lệnh và 5 bytes (byte thứ hai) , rõ ràng lệnh nhảy cao nhất ở đây là 0x7f

- nếu ta không muốn phá vỡ cấu trúc của hàm , thì ta cần snapshot csdl giúp ta quay trở lại trạng thái trước khi thay đổi

![here](https://miro.medium.com/v2/resize:fit:720/format:webp/1*UhJVwmHdrUZgb0Im1rXFSA.png)

- Hãy xem điều gì sẽ xảy ra nếu tôi thay 5 thành 7F:

![here](https://miro.medium.com/v2/resize:fit:720/format:webp/1*s8L_YdNaGgobjG_AI2hD6w.png)

- ta có thể thấy lúc này nó nhảy đến nơi xa hơn

![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*mmqp94O3K5SRjaI9)

- nếu ta thay bằng 0x80 thì nó là số âm nên đơn giản là nhảy ngược lại
![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*hPvN4iGQhD6272Lh)

- Trong trường hợp này, do ta thực hiện bước nhảy lùi, để đảm bảo cho công thức tính toán và bởi Python không biết được đây là bước nhảy tiến hay nhảy lùi từ giá trị này, ta phải sử dụng giá trị -0x80 (được biểu diễn bằng một dword ở hệ thập lục phân là 0xFFFFFF80) và sau đó thực hiện AND kết quả tính toán được với 0xFFFFFFFF nhằm xóa toàn bộ các bit lớn hơn một số 32 bit. Kết quả ta có được địa chỉ nhảy đến là 0x4012a6

![here](https://miro.medium.com/v2/resize:fit:640/format:webp/1*T8jP4RRC0j2oZDPRCm3ulA.png)

- Nếu chúng ta tiếp tục với một giá trị khác, ví dụ 0xFE, tức là nhảy ngược -2, vậy theo công thức sẽ cộng thêm 0xFFFFFFFE.

![here](https://miro.medium.com/v2/resize:fit:640/format:webp/1*23IokyVX3eZThlby3ydplw.png)


![here](https://miro.medium.com/v2/resize:fit:750/format:webp/1*IRiVauwtF-WFZdQqkfimlQ.png)

- Với giá trị này thì lệnh nhảy sẽ nhảy tới chính câu lệnh đó hay còn được gọi là Infinite Loop, bởi vì nó luôn luôn lặp đi lặp lại chính nó và không thể thoát được.

- 2 bytes “0xEB 0xFE” được gọi là 2 bytes “thần thánh”. Chúng được sử dụng trong quá trình Unpacking, Debug Malware. Thông thường malware sẽ tạo ra các thread hoặc bằng các kĩ thuật Process Hollowing/ RunPE để thực thi malicious code, lúc này ta sẽ tìm cách patch bytes tại entry point thành 0xEB 0xFE để tạo infinite loop (lưu ý nhớ lại byte gốc của EP), sau khi patch xong để process thực thi bình thường và rơi vào vòng lặp vô tận, tiến hành attach tiến trình mới vào một trình debugger khác để debug tiếp.

- vì vậy so với jmp_short thì jmp nhảy xa hơn nhiều 

- Khoảng cách sẽ được tính bằng công thức lấy địa chỉ cuối cùng — địa chỉ ban đầu — 5 (là chiều dài của lệnh) (Final address — start address — 5), kết quả có được là 0x300. Đó chính là dword đứng cạnh opcode của bước nhảy dài 0xe9.

![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*S6gojHx3HsxhXakS)

#### lệnh nhảy có điều kiện

- Thông thường, các chương trình phải đưa ra các quyết định rẽ nhánh thực thi chương trình, điều này sẽ căn cứ vào việc so sánh các giá trị để chuyển hướng thực hiện chương trình sang một điểm khác.

- CMP A, B; so sánh toán hạng thứ nhất với toán hạng thứ hai và bật các cờ trên thanh ghi EFLAGS dựa theo kết quả tính toán (việc tính toán tương tự như lệnh SUB, nhưng khác ở chỗ kết quả tính toán không được lưu lại).


Các lệnh nhảy Above / Below được sử dụng cho so sánh số không dấu (unsinged comparison)
Các lệnh nhảy Greater than / Less than được sử dụng cho so sánh số có dấu (singed comparison)


![here](https://miro.medium.com/v2/resize:fit:786/format:webp/0*87PI5Qy_fl8l9ER6)

![here](https://miro.medium.com/v2/resize:fit:486/format:webp/1*bYvlcSKptKzRWYPZSlQR9Q.png)

![here](https://miro.medium.com/v2/resize:fit:1100/format:webp/1*7kcweeFc9otUaO2iarOWsg.png)

- Bên lề: bên cạnh việc so sánh sử dụng câu lệnh CMP, một câu lệnh khác cũng rất hay được sử dụng là TEST. Bản chất của lệnh TEST là tính toán logic thông qua việc AND hai toán hạng, căn cứ trên kết quả để bật cờ. Kết quả tính toán sẽ không được lưu lại.

#### call và ret

- lệnh CALL, dùng để gọi một hàm và lệnh RET, dùng để trở quay trở về lệnh tiếp theo sẽ được thực hiện sau lệnh Call.

![here](https://miro.medium.com/v2/resize:fit:640/format:webp/1*8AGqE2Oz-xKkG2CWhqWnIg.png)

- ta thấy hình trên call 2 hàm 

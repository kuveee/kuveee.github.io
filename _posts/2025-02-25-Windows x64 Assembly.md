---
title: Windows x64 Assembly
date: 2025-02-24 00:00:00 +0800
categories: [tryhackme]
tags: [tryhackme]
author: "kuvee"
layout: post
published: false
---



## Number Systems

- con nguời chúng ta sử dụng cơ số 10  (0-10) , đây là 243 trong cơ số 10 : 

243 = (10^2 * 2) + (10^1 *4) + (10^0 *3) = 200 + 40 +3

nếu biểu diễn dưới dạng thấp phân nó sẽ có dạng hậu tố "d" như 12d

ngoài ra còn hệ thập lục phân  , nhị phân và ta sẽ làm việc rất nhiều với chúng



## Binary Operations

- True/false : false có giá trị là 0 và True sẽ có giá trị là 1 số khác 0 

NOT (hiện thị là !) : đơn giản là nó sẽ lật bit , not1 = 0 -> not0 = 1

ngoài ra còn and , or , xor


## register

- có 2 cú pháp khác nhau cho asm : itel và AT&T , ta sẽ tập trung vào intel đẻ dễ đọc , đối với linux thì at&t sử dụng phổ biến hơn

assembly code so với C : 

```cc
if(x ==4) {
    func1();
}else{
    return
}
```
nó sẽ gần giống với : 
```asm
mov rax,x
cmp rax,4
jne 5
call func1
ret
```

- ngooài ra ta còn có các thanh ghi khác (GPR) , nó được sử dụng dể truy xuất dữ liệu nhanh hơn đối với CPU do truy cập vào bộ nhớ RAM lâu hơn truy cập vào các thanh ghi 

- và mỗi thanh ghi cũng sẽ có 1 nhiệm vụ được giao , tuy nhiên cũng có 1 số trường hợp nó sẽ không có 1 khuôn mẫu nhất định  , tuy nhiên bất kể thế nào thì ta cũng cần biết nhiệm vụ của chúng để xử lí đúng cách: 

```cs
RAX - Known as the accumulator register. Often used to store the return value of a function.
RBX - Sometimes known as the base register, not to be confused with the base pointer. Sometimes used as a base pointer for memory access.
RDX - Sometimes known as the data register.
RCX - Sometimes known as the counter register. Used as a loop counter.
RSI - Known as the source index. Used as the source pointer in string operations.
RDI - Known as the destination index. Used as the destination pointer in string operations.
RSP - The stack pointer. Holds the address of the top of the stack.
RBP - The base pointer. Holds the address of the base (bottom) of the stack.
```

- các loại dữ liệu khác nhau 

giá trị dấu phẩy động : float và double

giá trị số nguyên : int , boolean , char , pointer

không thể đặt các kiểu dữ liệu khác nhau vào bất kì thanh ghi nào . float được biểu thị khác với int . do đó nó có các thanh ghi đặc biệt , bao gồm (YMM0 - YMM15 64 bit) và (XMM0 - XMM15 32 bit) và XMM chính là nửa dưới của YMM một điểm độc đáo là chúng có thể được coi như các mảng. Nói cách khác, chúng có thể chứa nhiều giá trị. Ví dụ, mỗi thanh ghi YMM# rộng 256 bit và có thể chứa 4 giá trị 64 bit hoặc 8 giá trị 32 bit. Tương tự như vậy, các thanh ghi XMM# rộng 128 bit và có thể chứa 2 giá trị 64 bit hoặc 4 giá trị 32 bit. Cần có hướng dẫn đặc biệt để sử dụng các thanh ghi này làm vectơ.


## instruction

- khả  năng đọc asm là rất quan trọng đối với 1 reverser . có khoảng 1500 lệnh , tuy nhiên phần lớn không được sử dụng phổ biến hoặc là các biến thể của lệnh khác 

- ta cần biết 3 thậut ngữ khác nhau :  ```immediate , register và memory .```

    - immediate  : là 1 thứ gì đó giống như số 12 , nó không phải là địa chỉ hay thanh ghi , hãy vào đó nó giống như 1 dạng dữ liệu hằng số
    - 1 thanh ghi tham chiếu tới 1 cái gì đó như RAX,RBX,R12,AL, v.v..
    - memory đề cập đến 1 vị chỉ trong bộ nhớ  như 0x7FFF842B.
```(Instruction/Opcode/Mnemonic) <Destination Operand>, <Source Operand>```

- MOV được sử dụng để di chuyển/lưu trữ toán hạng nguồn vào đích. Nguồn không nhất thiết phải là giá trị tức thời như trong ví dụ sau. Trong ví dụ sau, giá trị tức thời là 5 đang được di chuyển vào RAX.

```cs
mov rax,5
```

- LEA là viết tắt của Load Effective Address. Về cơ bản thì giống MOV ngoại trừ địa chỉ. Sự khác biệt chính giữa MOV và LEA là LEA không giải tham chiếu. Nó cũng thường được sử dụng để tính toán địa chỉ. Trong ví dụ sau, RAX sẽ chứa địa chỉ/vị trí bộ nhớ của num1.

```asm
lea RAX,num1
lea RAX,[struct+8]

mov rbx,5
lea RAX,[RBX+1]
```

- Trong ví dụ đầu tiên, RAX được đặt thành địa chỉ của num1. Trong ví dụ thứ hai, RAX được đặt thành địa chỉ của thành viên trong một cấu trúc cách 8 byte từ đầu cấu trúc. Đây thường là thành viên thứ hai. Ví dụ thứ ba RBX được đặt thành 5, sau đó LEA được sử dụng để đặt RAX thành RBX + 1. RAX sẽ là 6.

- ngoài ra còn pop , push  , inc , dec , sub , add , mul  , div....

- RET  là viết tắt của return. Lệnh này sẽ trả về lệnh thực thi cho hàm đã gọi hàm đang thực thi, hay còn gọi là hàm gọi. Như bạn sẽ sớm biết, một trong những mục đích của RAX là giữ các giá trị trả về. 

- Con trỏ : asm có cách làm việc với con trỏ và địa chỉ giống như C/C++ , ta  có thể tham chiếu để lấy giá trị bên trong địa chỉ bộ nhớ: 

```c
int main() {
    int num = 10;
    int *ptr = &num
    return(*ptr+5)
}
```

- chương trình trả về tổng là 15

- Hai trong số những điều quan trọng nhất cần biết khi làm việc với con trỏ và địa chỉ trong Assembly là LEA và dấu ngoặc vuông .

    - dấu ngoặc vuông : [var] là địa chỉ trỏ tới bởi var , nói cách khác , khi sử dụng[var] chúng ta muốn truy cập vào địa chỉ bộ nhớ ```var``` đang giữ
    - LEA - Bỏ qua mọi thứ về dấu ngoặc vuông khi làm việc với LEA. LEA là viết tắt của Load Effective Address và được sử dụng để tính toán và tải địa chỉ.
- Điều quan trọng cần lưu ý là khi làm việc với lệnh LEA, dấu ngoặc vuông không hủy tham chiếu.

✔ Dấu ngoặc vuông ([]) = Truy xuất dữ liệu tại địa chỉ.
✔ LEA bỏ qua dấu ngoặc vuông ([]) = Chỉ tính toán địa chỉ, không truy xuất dữ liệu.

ví dụ dưới đây , địa chỉ của var được tải vào rax , sau đó giá trị 12 được đưa vào địa chỉ rax đang nắm giữ

```cs
lea RAX, [var]
mov [RAX], 12
```

- đây là ví dụ vừa nãy
```cs
mov num,10   ; giá trị 10 lưu vào num
lea ptr,[num]   ; tải địa chỉ num vào ptr
mov rax,[ptr] ;lưu giá trị ptr vào rax
add rax,5 ; cộng giá trị rax với 5
ret  ; ret
```

dưới đây là 1 vd khác: 

```
lea RAX, [RCX+8] ;cộng thêm 8 vào địa chỉ rcx và lưu nó vào rax
mov RAX, [RCX+8] ;nó sẽ cộng 8 vào địa chỉ rcx và lưu giá trị tại địa chỉ+8 vô rax
```

## flags

- flags được sử dụng để biểu thị kết quả của phép toán hoặc phép so sánh . nếu 2 số so sánh với nhau thì flags sẽ phản ánh kết quả như chúng là số chẵn . flags được chứa trong 1 thannh ghi có tên là ```EFLAGS``` 32 bit hoặc ```RFLAGS``` 64 bit . 

- cờ trạng thái
  - đây là 1 số flags cần biết :
    - Zero Flag (ZF) - sẽ đặt nếu kết quả của phép toán là số 0 và ngược lạilại
    - Carry Flag (CF) - được đặt nếu hoạt động số học không dấu cuối cùng được thực hiện bổ sung (mượn hoặc trừ) một chút ngoài thanh ghi . nó cũng được đặt khi 1 hoạt động sẽ âm 
    - Overflow Flag (OF) - đặt nếu 1 hoạt động nào đó quá lớn để thanh ghi có thể chứa
    - Sign Flag (SF) - đặt nếu kqua của 1 phép toán là âm 
    - Adjust/Auxiliary Flag (AF) - Same as the carry flag but for Binary Coded Decimal (BCD) operations.
    - Parity Flag (PF) - Set to 1 if the number of bits set in the last 8 bits is even. (10110100, PF=1; 10110101, PF=0)
    - Trap Flag (TF) 
## calling covention


- có rất nhiều quy ước được sử dụng trên window x64 , tuy nhiên ta chỉ cần hiểu 1 cái thôi -> mấy cái còn lại   

- khi một hàm được gọi . về mặt lý thuyết , ta có thể truyền tham số qua thanh ghi , stack hoặc là trên disk . ta chỉ cần  chắc chắn rằng hàm ta đang gọi biết ta đang đặt tham số ở đâu . tuy nhiên nó trở nên lộn xộn khi ta dùng thư viện , vì vậy mà các quy ước gọi hàm được ra đời để xác định các tham số truyền cho 1 hàm 

- Calle là hàm được gọi là caller là hàm thực hiện lệnh gọi

- Có một số quy ước gọi khác nhau bao gồm cdecl, syscall, stdcall, fastcall, v.v. Vì tôi đã chọn tập trung vào Windows x64 để đơn giản hóa, chúng ta sẽ làm việc với x64 fastcall.

- FASTCALL : là calling convention for x64 Windows . window sử dụng quy ước gọi fastcall bốn thanh ghi theo mặc mặc định . khi nói về calling convention , bạn sẽ nghe về "Application Binary Interface" (ABI) . ABI định nghĩa nhiều quy tắc khác nhau cho cac chương trình như calling convention , xử lí tham số

- bốn tham số đầu tiên được truyền vào các thanh ghi theo thứ tự từ trái sang phải . các tham số không phải giá trị dấu phẩy động như số nguyên , con trỏ và kí tự , sẽ được truyền qua RCX,RDX,R8,R9 và các giá trị dấu phẩy động được truyền qua XMM0,XMM1,XMM2...

- nếu 2 thứ đó kết hợp thì thứ tự vẫn tương tự , ví dụ (fun(1,3.14,6,7.26)) thì tham số đầu tiên truyền qua RCX thứ hai là XMM0 và cứ thế tiếp tục

- Luôn luôn có không gian được phân bổ trên ngăn xếp cho 4 tham số, ngay cả khi không có tham số nào. Không gian này không bị lãng phí hoàn toàn vì trình biên dịch có thể và thường sẽ sử dụng nó. Thông thường, nếu đó là bản dựng gỡ lỗi, trình biên dịch sẽ đặt một bản sao của các tham số vào không gian.

- 1 số quy tắc khác của calling convention: 
  - giá trị trả về được truyền qua RAX nếu đó là số nguyên , bool , char hoặc XMM0 nếu đó là số thực 
  - Người gọi có trách nhiệm phân bổ không gian cho các tham số cho người được gọi . Người gọi phải luôn phân bổ không gian cho 4 tham số ngay cả khi không có tham số nào được truyền.
  - Các thanh ghi RAX, RCX, RDX, R8, R9, R10, R11 và XMM0-XMM5 được coi là không ổn định và phải được coi là bị hủy khi gọi hàm.
  - Các thanh ghi RBX, RBP, RDI, RSI, RSP, R12, R13, R14, R15 và XMM6-XMM15 được coi là không mất dữ liệu và cần được lưu và khôi phục bằng hàm sử dụng chúng.
- Truy cập stack
  - trên x64 , RSP được sử dụng phổ biến thay vì RBP để truy cập các tham số . mặc dù 4 tham số đầu tiên được truyền qua các thanh ghi nhưng vẫn có không gian cho chúng trong stack . không gian sẽ là 0x20 bytes
  - 1-4 tham số:
    - Các đối số sẽ được đẩy qua các thanh ghi tương ứng của chúng, từ trái sang phải. Trình biên dịch có thể sẽ sử dụng RSP+0x0 đến RSP+0x18 cho các mục đích khác.
  - hơn 4 tham số:
    - Bốn đối số đầu tiên được truyền qua thanh ghi, từ trái sang phải, và phần còn lại được đẩy vào ngăn xếp bắt đầu từ offset RSP+0x20, từ phải sang trái. Điều này làm cho RSP+0x20 trở thành đối số thứ năm và RSP+0x28.
ví dụ :

```cs
function(1,2,3,4,5,6,7,8)
```
tương đương
```cs
MOV RCX 0x1 ; Going left to right.
MOV RDX 0x2
MOV R8 0x3
MOV R9 0x4
PUSH 0x8 ; Now going right to left.
PUSH 0x7
PUSH 0x6
PUSH 0x5
CALL function
```

- ngoài ra còn các calling convention khác mà ta cũng cần biết thêm 

## bố trí bộ nhớ

- Memory Segments
  - stack : chứa các biến cục bộ khong tĩnh
  - heap : chứa dữ liệu phân bổ động
  - .data : chứa dữ liệu toàn cục và dữ liệu tĩnh được khởi tạo thành giá trị khác không
  - .bss : chứa dữ liệu toàn cục và tĩnh chưa được khởi tạo hoặc khởi tạo bằng không
  - .text : chứa mã thực thi của chương trình

![here](https://raw.githubusercontent.com/0xZ0F/Z0FCourse_ReverseEngineering/master/Chapter%203%20-%20Assembly/%5Bignore%5D/WindowsMemoryLayoutRF.png)

- stack : Khu vực trong bộ nhớ có thể được sử dụng nhanh chóng để phân bổ dữ liệu tĩnh. Hãy tưởng tượng ngăn xếp có địa chỉ thấp ở trên cùng và địa chỉ cao ở dưới cùng. Điều này giống hệt với danh sách số thông thường. Dữ liệu được đọc và ghi theo kiểu "vào sau ra trước" (LIFO) . Cấu trúc LIFO của ngăn xếp thường được biểu diễn bằng một chồng đĩa. Bạn không thể chỉ cần lấy đĩa thứ ba từ trên cùng ra, bạn phải lấy từng đĩa một để lấy được đĩa đó. Bạn chỉ có thể truy cập vào phần dữ liệu ở trên cùng của ngăn xếp, vì vậy để truy cập dữ liệu khác, bạn cần di chuyển phần ở trên cùng ra khỏi đường đi. Khi tôi nói rằng ngăn xếp chứa dữ liệu tĩnh, tôi đang đề cập đến dữ liệu có độ dài đã biết như số nguyên. Kích thước của số nguyên được xác định tại thời điểm biên dịch, kích thước thường là 4 byte, vì vậy chúng ta có thể đưa số đó vào ngăn xếp. Trừ khi chỉ định độ dài tối đa, dữ liệu đầu vào của người dùng phải được lưu trữ trên heap vì dữ liệu có kích thước thay đổi. Tuy nhiên , địa chỉ/vị trí của dữ liệu đầu vào có thể sẽ được lưu trữ trên ngăn xếp để tham khảo trong tương lai. Khi bạn đặt dữ liệu lên trên cùng của ngăn xếp, bạn đẩy nó vào ngăn xếp. Khi dữ liệu được đẩy vào ngăn xếp, ngăn xếp sẽ tăng lên, hướng tới các địa chỉ bộ nhớ thấp hơn. Khi bạn loại bỏ một phần dữ liệu khỏi đầu ngăn xếp, bạn sẽ bật nó ra khỏi ngăn xếp. Khi dữ liệu được bật ra khỏi ngăn xếp, ngăn xếp sẽ co lại, hướng tới các địa chỉ cao hơn. Tất cả những điều đó có vẻ kỳ lạ nhưng hãy nhớ rằng, nó giống như một danh sách số bình thường trong đó 1, số thấp hơn, ở trên cùng. 10, số cao hơn, ở dưới cùng. Hai thanh ghi được sử dụng để theo dõi ngăn xếp. Con trỏ ngăn xếp (RSP/ESP/SP) được sử dụng để theo dõi đầu ngăn xếp và con trỏ cơ sở (RBP/EBP/BP) được sử dụng để theo dõi đáy/đáy của ngăn xếp. Điều này có nghĩa là khi dữ liệu được đẩy vào ngăn xếp, con trỏ ngăn xếp sẽ giảm vì ngăn xếp tăng lên hướng tới các địa chỉ thấp hơn. Tương tự như vậy, con trỏ ngăn xếp sẽ tăng lên khi dữ liệu được bật ra khỏi ngăn xếp. Con trỏ cơ sở không có lý do gì để thay đổi khi chúng ta đẩy hoặc bật thứ gì đó vào/ra khỏi ngăn xếp. Chúng ta sẽ nói nhiều hơn về cả con trỏ ngăn xếp và con trỏ cơ sở khi thời gian trôi qua.
- heap : tương tự như stack nhưng được sử dụng để phân bổ đọng và truy cập chậm hơn 1 chút Khi bạn thêm dữ liệu vào heap, nó sẽ tăng lên theo các địa chỉ cao hơn.
- TEB - Khối môi trường luồng (TEB) lưu trữ thông tin về luồng đang chạy.
-  PEB - Khối môi trường quy trình (PEB) lưu trữ thông tin về quy trình và các mô-đun được tải. Một thông tin mà PEB chứa là "BeingDebugged" có thể được sử dụng để xác định xem quy trình hiện tại có đang được gỡ lỗi hay không

![here](https://raw.githubusercontent.com/0xZ0F/Z0FCourse_ReverseEngineering/master/Chapter%203%20-%20Assembly/%5Bignore%5D/StackHeapRelationRF.png)

- STACK FRAMEs 

là các khối dữ liệu cho các hàm . dữ liệu này gồm các biến cuc bộ , the saved base pointer ,  the return address of the caller, and function parameters. 

```c
int Square(int x){
    return x*x;
}
int main(){
    int num = 5;
    Square(5);
}
```

- ở ví dụ này , main() được gọi đầu tiên và nó sẽ có 1 frame riêng cho main() , khi main() gọi square() , con trỏ cơ sở (RBP) và địa chỉ trả về đều được lưu . nó được lưu vì khi được gọi , con trỏ cơ sở được cập nhật để trỏ đến cơ sở của frame đó , khi function đó trở lại , con trỏ cơ sở được khôi phục để trỏ đến cơ sở của frame của người gọi 
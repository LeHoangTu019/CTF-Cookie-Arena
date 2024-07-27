# CTF-Cookie-Arena

<h1>Baby SQLite With Filter</h1>

Đây là source code xử lý chính:
![image](https://github.com/user-attachments/assets/60bb88f1-e770-4213-bedc-19178f891431)

Đầu tiên, ta chú ý thấy dòng code 57,58. Trình duyệt sẽ trả lại kết quả flag cho chúng ta nếu biến uid trùng chuỗi kí tự "admin".

Vậy GOAL của chúng ta ở bài là làm cách nào gán được chuỗi kí tự "admin" vào biến uid !!!

Từ dòng 37 đến dòng 44 được dùng để lọc các kí tự trong các chuỗi uid, upw và level.

Đây là ví dụ khi ta nhập chuỗi "admin" vào trường uid trong login
![image](https://github.com/user-attachments/assets/8bd1a700-d327-4019-a66b-4d56eebbfecb)

Kết quả trả như chúng ta dự kiến: No Hack!

Sử dụng công cụ BurpSuite để bắt lại gói tin sau khi ta submit để kiểm tra
![image](https://github.com/user-attachments/assets/340041e8-b705-4035-98d2-d2695e767801)

Trong gói tin, thứ ta gửi đi chỉ có 2 trường uid, upw và nhớ lại xem nào chúng ta có bỏ sót gì không. 
![image](https://github.com/user-attachments/assets/eee55518-7eb3-4349-a704-55c4778ce9fb)

Chú ý ở 2 dòng được khoanh đỏ, chúng ta có 1 biến "level" cũng nhận dữ liệu từ web như "uid" và "upw". Và dòng khoanh đỏ còn lại câu lệnh SQL có chứa cả Untrusted Data "level".

Từ dòng 52 đến dòng 58, chuỗi SQL sẽ được xử lý ở dòng 52 bởi hàm execute() và kết quả gán vào biến "req". Sau đó lại sử dụng thêm hàm fetchone() để lấy 1 bản ghi đơn lẻ từ kết quả SQL.
Nếu kết quả tồn tại thì lấy phần tử đầu tiên của "result" gán vào "uid".

ta đã kiếm được lỗ hỏng: Untrusted Data (level) + Unsafe method (execute).

<h2>Tiến hành giải mã</h2>
Mảnh ghép đầu tiên ta cần là: Đưa giá trị gì vào biến "level"

Đến đây mình sử dụng 1 web sandbox SQL để kiểm tra cú pháp: https://sqliteonline.com/. Đầu tiên ta xem lại các kí tự bị lọc đi trong đó có bao gồm kí tự space.

Vậy nên ta cần 1 kí tự hoặc 1 chuỗi kí tự khác có chức năng tương tự như space để thay thế nó. Thử sử dụng các kí tự ASCII đều không có khả năng, chúng ta dùng chuỗi kí tự /**/.

Vấn đề tiếp theo là làm sao khi thực thi câu lệnh SQL, thì giá trị "admin" sẽ được gán vào biến "result" nếu chúng ta không thể nhập "admin" vì chúng sẽ bị lọc. 

Lúc này ta sẽ đặt câu hỏi rằng thứ gì có thể thay thế chuỗi "admin" và đây sẽ là câu trả lời - Bảng mã ASCII: https://www.asciitable.com/

char(97)||char(100)||char(109)||char(105)||char(110)

Vấn đề cuối cùng: Sau khi thực thi lệnh SQL, làm sao kết quả trả về phải là "admin". Câu lệnh SQL "SELECT uid FROM users WHERE uid='123' and upw='123' and level=7" sẽ trả về cho chúng ta rỗng vì không tồn tại bất kì 1 uid nào như thế trong table users. Vậy sẽ ra sao nếu đoạn code SQL ta chèn thêm phía sau có khả năng tạo ra kết quả trả lại là "admin"? Vì SELECT bị lọc đi mất nên cùng tìm hiểu xem liệu có method nào trả lại giá trị không. Sau khi tìm hiểu, Hàm VALUES('input') sẽ tạo ra 1 hàng 1 cột chứa giá trị "input". Nếu ta để VALUES(1) sẽ trả giá trị 1. Vậy nếu ta để chuỗi "admin" trên vào thì sao?
![image](https://github.com/user-attachments/assets/df66dbbb-4f1e-4001-9057-0763cb41a646)

=> Ta đã có đầy đủ các mảnh ghép cần thiết!!!

Bây giờ ta sử dụng BurpSuite,repeat gói tin đầu tiên gửi đi, tìm đến dòng có chứa biến "uid" và "upw" thêm vào: &level=7/**/union/**/values(char(97)||char(100)||char(109)||char(105)||char(110))

![image](https://github.com/user-attachments/assets/f7f6cf47-4c6f-48a5-861b-103a9fb2548a)

---
<h1>SQL Truncation Attack</h1>
https://battle.cookiearena.org/challenges/web/sql-truncation-attack

Bài này cung cấp cho chúng ta source code chính login.php và register.php

![image](https://github.com/user-attachments/assets/14c27ced-70b7-49f2-8e9d-8744e280f74f)
![image](https://github.com/user-attachments/assets/162810e5-7d54-4cc7-99db-0abe692d5c1a)

GOAL: Đăng nhập được vào tài khoản admin!!!

Đọc code xử lý chính file login.php, ta thấy rằng câu lệnh SQL được đưa vào biến "stmt" và bằng việc sử dụng hàm bind_param để định dạng thuộc tính chuõi cho 2 biến "username" và "password". Việc sử dụng hàm bind_param này đã phần này nâng tính bảo mật của việc xử lý code vì tất cả những giá trị ta đưa vào biến "username" và biến "password" đều bị định dạng thành string => Không thể sử dụng những phương pháp chèn thêm UNION SELECT, kí tự "\'",... được (Hoặc có nếu mình chưa tìm ra :< )

Nhưng chúng ta chỉ mới nhìn qua form login mà thôi, vậy còn form đăng ký thì sao? Trong form đăng ký, có đoạn code kiểm tra tính độc nhất của user (chỉ tồn tại duy nhất 1 tài khoản cùng tên) => Vậy nên ta không thể tạo ra thêm 1 tài khoản "admin" khác được. Và như ta thấy các đoạn code trước khi đưa dữ liệu vào xử lý câu lệnh SQL đều được anh lập trình viên sử dụng hàm bind_param định dạng thành chuỗi hết => Vậy thì cũng chẳng tồn tại lỗ hỏng SQL nào. 

Để ý kĩ ta sẽ thấy 1 đoạn code nhỏ góc phải bên dưới là các câu lệnh SQL trong việc tạo tài khoản người dùng cho table users. Tìm hiểu 1 tí ta sẽ nhận ra rằng có tồn tại 1 lỗi mà anh lập trình viên quên ngăn chặn. <strong> Đó là SQL Truncation Attack (Tấn công SQL cắt cụt). </strong>

Giải thích: Những ai có lập trình php web qua sẽ đều biết rằng khi tạo 1 cơ sở dữ liệu ta thường sẽ phải định dạng cho dữ liệu ấy thuộc kiểu dữ liệu nào và độ dài của dữ liệu.

![image](https://github.com/user-attachments/assets/4f0e1ab8-7c75-4d42-8ccf-64bab6907384)
Minh họa việc tạo cột trong 1 bảng trong phpadmin.

Vậy ta thử đăng ký với giá trị username là "admin                 123" và password = "123" và đảm bảo rằng username có hơn 20 kí tự thì khi dữ liệu được đưa vào hệ thống xử lý phần sau giới hạn sẽ tự động bị cắt bỏ đi và như thế sẽ trở thành "admin                      " tổng cộng 20 kí tự gồm 5 kí tự admin và 15 kí tự khoảng trắng. Lúc này trong table users đã có 1 tài khoản mới username = "admin" và password = "123" tồn tại song song.

![image](https://github.com/user-attachments/assets/2fe61375-a528-42b3-b1ee-3ad67016eb94)
Sau khi đăng nhập vào tài khoản admin, ta sẽ được chuyển hướng tới flag.php
---
<h1>Baby HTTP Method</h1>



![image](https://github.com/user-attachments/assets/318ebdb3-8f3c-4acd-be24-b2ff3984936f)![image](https://github.com/user-attachments/assets/5eeb1ea4-2c79-48fb-a474-755faa5f92cd)![image](https://github.com/user-attachments/assets/a4f2135c-2945-4295-8626-53e31dacdd36)![image](https://github.com/user-attachments/assets/8499b860-5356-4bad-ab97-ac57bcaf1791)# CTF-Cookie-Arena

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

Nhấp vào "click me for the flag" trong trang sẽ hiện về kết quả như thế này

![image](https://github.com/user-attachments/assets/4386643d-c542-4f77-961c-25a7f3788764)

Có vẻ trang web cũng không có gì cho chúng ta để tìm. Vậy chúng ta sử dụng tool recon ffuf để tìm các directories và thứ mà mình tìm được là "src"

![image](https://github.com/user-attachments/assets/007be3a5-a259-497f-8081-454d1cde5a62)

Vào trong /src sẽ hiện chúng ta nội dung như sau

![image](https://github.com/user-attachments/assets/71738cee-a2e0-4d98-8f53-5973358a24a3)

Đọc kỹ nội dung bên trong ta sẽ tìm được 1 dòng khá "khả nghi" "/super-secret-route-nobody-will-guess'". Quả thật không ai có thể đoán được và thì chúng ta truy cập thử vào sẽ xuất hiện web như thế này

![image](https://github.com/user-attachments/assets/ea067db4-495a-4cd0-9195-8a34d12a668c)

Chúng ta không thể truy cập được, liệu chúng ta có bỏ sót ở đâu không, cùng xem lại thử nào. 

![image](https://github.com/user-attachments/assets/116cc83c-d92d-4cac-8b0c-1f575dd74833)

Chúng ta đã bỏ quên method "PUT". Thứ chúng ta chạy chính là trên method "GET". Vậy thử lại với burpSuite thay đổi method nào.

![image](https://github.com/user-attachments/assets/6a853757-987e-4ac5-b8ae-9056f9081ed2)

Và chúng ta đã thành công giải được bài này !!! 

---

<h1>Baby Simple Go CURL</h1>

GOAL: tìm đến /flag để lấy flag!!!

Đây là trang web xử lý:

![image](https://github.com/user-attachments/assets/574873e3-82b0-4b3b-8348-b6aedf16a917)

Test thử chức năng "CURL" của trang web:

![image](https://github.com/user-attachments/assets/0c3516ae-c359-41ec-863a-24734bc62e83)

Đoạn code xử lý chính của bài này sẽ được mình upload lên với tên file là main.go. Tìm hiểu code, ta cần chú ý vào các dòng 18,55,95. Những dòng code này đều đề cập đến địa chỉ IP 127.0.0.1 (đây là địa chỉ IP từ máy host)

=> Vậy ta có thể nhận định rằng đây là lỗi SSRF (Server-Side Request Furgery)

Đối với dạng bài SSRF này, ta không thể truy cập trực tiếp vào dir /flag được vì hệ thống sẽ chỉ cho phép chính host (127.0.0.1) truy cập vào. Và đây là ảnh minh họa khi ta cố gắng truy cập từ địa chỉ IP không phải host.

![image](https://github.com/user-attachments/assets/c23694c3-f286-4a19-8b0d-63a571e30a0c)

Vậy phương pháp để giải dạng này dùng chính khả năng "gọi URL" của web (cụ thể ở đây là lệnh CURL) để gọi chính host chạy đến dir "/flag" và trả lại kết quả cho chúng ta. Hoàn thành bước 1: Nhận định lỗi và lên ý tưởng.

![image](https://github.com/user-attachments/assets/f0ea9db2-dc4b-48f4-af53-a63327bd10d2)

Đến bước tiếp theo, ta cần phải lên kế hoạch khai thác các lỗ hỏng, kiểm tra qua code ta nhận thấy rằng ta không thể đưa payload "http://127.0.0.1:1337/flag" vì kí tự "flag" "curl" "%" đã bị chặn. (Không thể sử dụng cả dạng mã hóa)

![image](https://github.com/user-attachments/assets/68936b77-8b8d-41bc-b519-0b7b148b3387)

Nhận định rằng ta không thể truy cập vào /flag bằng cách đó => Tìm những lỗ hỏng khác để hỗ trợ. Ta chú ý rằng chúng ta chỉ mới tìm lỗ hỏng ở trường URL nhưng còn Header_Key và Header_Value thì sao. Tìm hiểu 1 chút trên mạng để xem có cách nào để sử dụng Header có thể chuyển hướng gói tin chúng ta đến  dir /flag vượt qua bước kiểm tra. Ở đây mình tìm ra được các cụm từ Header: X-Forwarded-Host, X-Forwarded-Proto, X-Forwarded-Prefix,... Ở đây ta cần điều chỉnh URL để đến với dir /flag nên Header_key ta cần dùng là "X-Forwarded-Prefix"

Thử ý tưởng và ta sẽ lấy được đáp án:

![image](https://github.com/user-attachments/assets/d32f3284-64cb-4dfa-b3f8-4406845b5963)

ở đây mình có thêm 1 dấu slash "/" vào thành 127.0.0.1:1337// vì nếu URL được truyền trong tham số truy vấn url bắt đầu bằng dấu gạch chéo đơn (/), hàm http.NewRequest sẽ coi nó là đường dẫn tương đối và nối nó vào đường dẫn cơ sở hiện tại, dẫn đến một đường dẫn không chính xác. Bằng cách sử dụng dấu gạch chéo kép (//), mã đảm bảo rằng đường dẫn được coi là đường dẫn tuyệt đối, và hàm http.NewRequest có thể tạo một yêu cầu HTTP mới chính xác.

---

<h1>Where do you come from</h1>

GOAL: Bạn chỉ có thể lấy được flag nếu bạn truy cập trang web từ web của https://cookiearena.org/

Đơn giản là ta thêm vào trường Referer với value là web "https://cookiearena.org/"

![image](https://github.com/user-attachments/assets/47ffbc71-d26b-4604-93c7-71be6fcba89a)

Và thế ta là đã lấy được flag

---
<h1>COOKIE CRAWLER ENGINE</h1>

<h3>Cơ chế hoạt động:</h3>
Lỗi XXE dựa vào khả năng parser để tải hoặc chèn dữ liệu từ các nguồn bên ngoài. Điều này dẫn đến nhiều kiểu tấn công: 
<ol>
  <li>Local File Disclosure: Truy xuất các thư mục, file nội bộ trong hệ thống bằng cách tham chiếu đường dẫn file trong <b>XML Entity</b>.</li>
  <img src="https://github.com/user-attachments/assets/3ef3b936-18c5-47f9-8fc7-ec3d07be2807" alt="Local File Disclosure">
  <li>RCE: Trong trường hợp nghiêm trọng nhất, kẻ tấn công có thể lợi dụng việc parser thực thi các mã lệnh từ tệp bên ngoài.</li>
  <li>DoS: Kẻ tấn công chèn vào nhiều <b>Entity</b> lồng vào nhau để gây quá tải lên máy chủ.</li>
</ol>
Đây là 1 đoạn code mẫu XML để khai thác lỗi XXE:<br>
<img src="https://github.com/user-attachments/assets/860bdcbe-4973-407b-80b8-af0b6b8309c0" alt="Code mẫu XML"><br>

<br><h3>Step_to_ReProduce:</h3>
Truy cập vào trang web, ta sẽ nhận được đoạn thông báo như sau <code>"You have to provide a sitemap.xml URL. /?sitemap_url=http://example.com/sitemap.xml"</code><br>
<img src="https://github.com/user-attachments/assets/8f0ebcf1-80e8-45e0-a205-b5970933ca1b" alt="Thông báo"><br>
Trang web yêu cầu ta cung cấp 1 URL dẫn đến tệp <code>sitemap.xml</code> thông qua tham số <code>sitemap_url</code>. Nếu trang web này có lỗ hổng XXE thì ta có thể khai thác bằng cách chèn 1 tệp XML có chứa mã độc để tấn công hệ thống. <br>
<ol>
  <li>Mình code 1 file XML để khai thác đến /flag.txt như sau: 
    <pre>
  &lt;?xml version="1.0" encoding="UTF-8"?&gt;
  &lt;!DOCTYPE urlset [
    &lt;!ENTITY xxe SYSTEM "file:///flag.txt" &gt;&gt;
  ]&gt;
  &lt;urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9"&gt;
    &lt;url&gt;
      &lt;loc&gt;&amp;xxe;&lt;/loc&gt;
    &lt;/url&gt;
  &lt;/urlset&gt;
    </pre>
  </li>
  <li>Upload file lên 1 nơi nào đó có thể lưu file và hiển thị đầy đủ đường dẫn đến file <code>example.com/path_to_file/sitemap.xml</code>. Ở đây mình chọn upload lên <code>http://fileupload.cyberjutsu-lab.tech:12001/</code> và mình có được đường dẫn đến file như sau: <code>http://fileupload.cyberjutsu-lab.tech:12001/upload/083efb603c5314185b67448868b84b1a/sitemap.xml</code></li>
  <li>Tiếp theo, quay lại trang web và đưa đường dẫn đến file XML mà ta vừa upload cho thông số <code>sitemap_url</code><br></li>
</ol>
<img src="https://github.com/user-attachments/assets/40f93f52-8f33-4068-a849-4cf97c3419dc" alt="Upload file">

<br><h3>Hướng dẫn khắc phục lỗi XXE:</h3>
<ol>
  <li>Kiểm tra và xác thực dữ liệu đầu vào</li>
  <li>Cấu hình máy chủ, các thư viện xử lý XML như <code>libxm12</code>,<code>DOMParser</code> để tắt khả năng xử lý.</li>
</ol>

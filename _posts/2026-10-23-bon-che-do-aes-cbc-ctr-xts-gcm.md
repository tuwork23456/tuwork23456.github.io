---
title: "Cùng Là AES, Vì Sao Lại Chọn CBC, CTR, XTS Hay GCM?"
date: 2026-10-23 00:30:00 +0700
categories: [Cryptography, Applied Security]
tags: [cryptography, aes, encryption, cbc, ctr, xts, gcm, security]
description: "Một thuật toán có thể an toàn, nhưng chế độ sử dụng quyết định hệ thống có thực sự bảo mật hay không. So sánh thực nghiệm 4 chế độ mã hóa AES (CBC, CTR, XTS, GCM) trên 4 bài toán dữ liệu thực tế."
image:
  path: /assets/images/posts/aes-modes/01-bmp-cbc-vs-ecb.png
  alt: "So sánh các chế độ mã hóa AES: CBC, CTR, XTS, GCM"
toc: true
comments: true
mermaid: true
---

> **AES  /  ENCRYPTION MODES  /  GHI CHÉP TỪ MỘT PROJECT NHỎ**  
> Một thuật toán mã hóa có thể an toàn, nhưng cách sử dụng thuật toán đó chưa chắc đã an toàn. Đây là điều dễ nhận ra nhất khi thử AES trên bốn dạng dữ liệu: **ảnh BMP, log cảm biến IoT, sector ổ đĩa và bản tin JSON**. Mỗi loại có một yêu cầu khác nhau, từ che giấu nội dung, giảm dung lượng cho đến phát hiện dữ liệu bị chỉnh sửa.  
> Bài viết tập trung vào bốn chế độ **CBC, CTR, XTS và GCM**. ECB xuất hiện như một điểm đối chứng để thấy vì sao không thể chỉ chọn AES rồi coi như mọi dữ liệu đã được bảo vệ tốt.

---

## 1. AES là thuật toán, còn mode quyết định cách dùng

**AES (Advanced Encryption Standard)** là thuật toán mã hóa đối xứng với kích thước khối cố định **128 bit (16 byte)**. Các biến thể AES-128, AES-192 và AES-256 khác nhau về độ dài khóa bí mật, không phải kích thước khối.

Khi dữ liệu cần mã hóa lớn hơn 16 byte, ứng dụng bắt buộc phải quyết định cách xử lý nhiều khối liên tiếp; đó chính là vai trò của **Mode of Operation (chế độ hoạt động)**.

![4 chế độ hoạt động của AES](/assets/images/posts/aes-modes/00-so-do-4-che-do-aes.png)
_Hình 1 — Mối quan hệ giữa thuật toán mã hóa khối AES 128-bit và 4 chế độ hoạt động (CBC, CTR, XTS, GCM)._

Hiểu đơn giản:
- **AES** là phép biến đổi toán học cho một khối dữ liệu 16 byte.
- **Mode** là quy tắc kết hợp các khối dữ liệu đó với các tham số mở rộng như **IV (Initialization Vector), Nonce, Counter hoặc Tweak**.

Chọn sai mode có thể làm lộ quy luật lặp của dữ liệu, tăng chi phí lưu trữ/băng thông hoặc nghiêm trọng hơn là khiến dữ liệu bị sửa đổi mà bên nhận hoàn toàn không hay biết.

> **Ghi chú thử nghiệm:** Các thử nghiệm được viết bằng Python, sử dụng các thư viện mã hóa chuẩn để xử lý dữ liệu mẫu. Trọng tâm là giữ nguyên cùng một bản rõ (plaintext) và quan sát sự khác biệt khi thay đổi từng chế độ hoạt động.

---

## 2. CBC: Vì sao cùng một bức ảnh lại cho ra kết quả khác nhau?

Điểm bắt đầu là một bức ảnh định dạng **BMP**. Loại ảnh này rất hữu ích để kiểm tra tính bảo mật của mã hóa khối vì phần dữ liệu pixel không nén thường chứa các mảng màu đồng nhất lặp đi lặp lại. Trong thử nghiệm, phần Header (54 byte đầu) được giữ nguyên để phần mềm xem ảnh vẫn mở được file, còn vùng dữ liệu pixel bên trong mới được đưa vào mã hóa.

### 2.1. Hạn chế chết người của ECB

Khi dùng **ECB (Electronic Codebook)**, mỗi khối 16 byte được mã hóa hoàn toàn độc lập:
- Hai khối bản rõ giống nhau, khi dùng chung một khóa, sẽ luôn cho ra hai khối bản mã (ciphertext) giống hệt nhau.
- Vì thế, dù màu sắc pixel có bị xáo trộn, đường nét tổng thể và cấu trúc hình ảnh ban đầu vẫn hiện lên rõ mồn một. Đây là lý do ECB không bao giờ được chấp nhận trong các hệ thống thực tế.

### 2.2. CBC giải quyết vấn đề thế nào?

**CBC (Cipher Block Chaining)** xử lý theo một cách khác:
- Trước khi mã hóa khối hiện tại, dữ liệu bản rõ được **XOR với bản mã của khối ngay trước nó**.
- Riêng khối đầu tiên không có khối trước, nên bắt buộc phải dùng một vectơ khởi tạo ngẫu nhiên (**IV - Initialization Vector**).

Nhờ cơ chế móc xích liên hoàn này, hai khối dữ liệu giống nhau nằm ở hai vị trí khác nhau sẽ cho ra hai khối bản mã hoàn toàn khác nhau, xóa sạch hoàn toàn mọi mẫu hình lặp lại.

![So sánh kết quả mã hóa ảnh BMP giữa CBC và ECB](/assets/images/posts/aes-modes/01-bmp-cbc-vs-ecb.png)
_Hình 2 — Cùng một ảnh BMP: CBC (trái) che giấu cấu trúc tốt hơn hẳn so với ECB (phải)._

### 2.3. Điểm cần lưu ý về CBC
- **Padding:** Vì là mã hóa khối, CBC bắt buộc độ dài dữ liệu phải là bội số của 16 byte. Do đó, nếu dữ liệu thiếu hụt thì phải đệm thêm padding (phổ biến nhất là chuẩn **PKCS#7**).
- **Tính toàn vẹn:** CBC **chỉ giải quyết tính bí mật**, không tự đảm bảo tính toàn vẹn dữ liệu. Bản mã bị can thiệp trên đường truyền vẫn có thể giải mã ra bản rõ bị sai lệch. Hơn nữa, nếu ứng dụng xử lý thông báo lỗi padding không an toàn, hệ thống sẽ đối mặt với cuộc tấn công nguy hiểm **Padding Oracle Attack**.

---

## 3. CTR: Mã hóa những dòng log nhỏ mà không cần padding

Thử nghiệm tiếp theo sử dụng file `sensor_data.log` gồm **7 dòng nhật ký cảm biến IoT** (ghi nhận nhiệt độ, độ ẩm và trạng thái thiết bị). Mỗi dòng chỉ dài vài chục byte — kiểu dữ liệu rất phổ biến trong các hệ thống nhúng và thiết bị IoT hạn chế tài nguyên.

Nếu dùng CBC, mỗi dòng log sẽ phải chèn thêm padding PKCS#7 để làm tròn thành bội số của 16 byte, khiến tổng dung lượng dữ liệu phình to không cần thiết.

### 3.1. Cơ chế biến Block Cipher thành Stream Cipher

**CTR (Counter Mode)** biến thuật toán mã hóa khối AES thành một mã hóa dòng (Stream Cipher):
1. AES không mã hóa trực tiếp bản rõ. Thay vào đó, AES mã hóa một giá trị bộ đếm kết hợp với số ngẫu nhiên dùng một lần (**Nonce + Counter**) để tạo thành một chuỗi dòng khóa (**Keystream**).
2. Dòng Keystream này sau đó được **XOR trực tiếp với bản rõ** để tạo ra bản mã:
   $$\text{Ciphertext} = \text{Plaintext} \oplus \text{Keystream}$$

Nhờ vậy, CTR có những ưu thế vượt trội:
- **Xử lý độ dài tùy ý:** Bản mã có độ dài chính xác bằng bản rõ, hoàn toàn **không cần padding**.
- **Tính toán song song:** Vì giá trị Counter của từng khối là xác định độc lập, hệ thống có thể mã hóa hoặc giải mã nhiều khối cùng lúc trên CPU đa nhân.

### 3.2. So sánh dung lượng thực tế

Trong thử nghiệm với 7 dòng log có tổng dung lượng gốc là **153 byte**:
- **AES-CTR:** Tạo ra đúng **153 byte** ciphertext (giữ nguyên kích thước gốc).
- **AES-CBC:** Tăng lên **208 byte** do phải chèn padding riêng cho từng bản ghi.
- Chi phí lưu trữ của CBC lớn hơn tới **35,9%** so với dữ liệu gốc!

![So sánh dung lượng ciphertext giữa CTR và CBC trên log cảm biến IoT](/assets/images/posts/aes-modes/02-iot-log-ctr-vs-cbc.png)
_Hình 3 — Bảy dòng log IoT: CTR giữ nguyên 153 byte ciphertext, trong khi CBC tạo ra 208 byte khi padding riêng từng bản ghi._

> [!WARNING]
> **Ràng buộc sinh tử của CTR:** Tuyệt đối không bao giờ được tái sử dụng cùng một cặp **(Key, Nonce/Counter)** cho hai thông điệp khác nhau. Nếu tái sử dụng, kẻ tấn công có thể XOR hai bản mã để loại bỏ keystream, từ đó suy đoán trực tiếp ra quan hệ giữa các bản rõ:
> $$C_1 \oplus C_2 = (P_1 \oplus K) \oplus (P_2 \oplus K) = P_1 \oplus P_2$$
> Ngoài ra, CTR **không cung cấp khả năng xác thực dữ liệu**.

---

## 4. XTS: Mã hóa ổ đĩa cần quan tâm đến vị trí dữ liệu

Mã hóa ổ đĩa lưu trữ (**Data-at-Rest / Full Disk Encryption**) lại là một bài toán hoàn toàn khác biệt. Dữ liệu trên đĩa cứng thường được tổ chức theo các đơn vị cố định gọi là **Sector (thông dụng là 512 byte hoặc 4096 byte)**.

Một ổ đĩa trắng hoặc mới khởi tạo thường chứa rất nhiều sector toàn các byte `0x00`. Nếu mã hóa các sector này bằng ECB, các sector giống nhau sẽ cho ra kết quả giống hệt nhau, để lộ cấu trúc phân vùng và dữ liệu nhạy cảm.

### 4.1. Tweak gắn liền với vị trí vật lý

**XTS (XEX-based Tweaked-codebook mode with ciphertext Stealing)** được sinh ra chuyên biệt cho lưu trữ khối:
- Ngoài khóa chính, XTS sử dụng một tham số gọi là **Tweak** — được gắn trực tiếp với vị trí địa chỉ của Sector trên đĩa (Sector Number / LBA).
- Nhờ có Tweak phụ thuộc vị trí, hai sector có nội dung hoàn toàn giống nhau (kể cả sector toàn số 0) khi nằm ở hai vị trí khác nhau trên ổ đĩa sẽ tạo ra hai bản mã hoàn toàn khác biệt.

![Kết quả mã hóa sector 512 byte giữa ECB và XTS](/assets/images/posts/aes-modes/03-sector-ecb-vs-xts.png)
_Hình 4 — Kết quả mã hóa sector 512 byte: ECB lộ các khối lặp, còn XTS tạo ra bản mã ngẫu nhiên thay đổi theo vị trí sector._

### 4.2. Khả năng truy cập ngẫu nhiên (Random Access)

Khi đọc hoặc ghi một file trên ổ đĩa, hệ điều hành chỉ đọc/ghi một vài sector cụ thể mà không thể đọc tuần tự từ đầu ổ đĩa. 
- XTS cho phép giải mã hoặc mã hóa độc lập từng sector chỉ dựa vào vị trí của sector đó mà không phụ thuộc vào trạng thái của sector liền trước.
- Kỹ thuật **Ciphertext Stealing (CTS)** được tích hợp sẵn giúp XTS xử lý các sector có kích thước lẻ mà không làm tăng dung lượng sector trên đĩa.

> **Lưu ý:** XTS bảo vệ tính bí mật của dữ liệu tĩnh trên ổ đĩa, nhưng không đi kèm chữ ký xác thực toàn vẹn. Nếu cần chống việc ghi đè sector độc hại, hệ thống cần bổ sung kiểm tra tính toàn vẹn (integrity check) ở tầng filesystem.

---

## 5. GCM: Khi bản mã bị sửa, hệ thống có nhận ra không?

Trong kịch bản cuối cùng, hệ thống truyền nhận một bản tin JSON cấu hình phân quyền người dùng:
```json
{
  "user_id": 1024,
  "role": "user"
}
```
Với loại dữ liệu này, che giấu nội dung là chưa đủ. Nếu kẻ đứng giữa (Man-in-the-Middle) có thể can thiệp sửa đổi giá trị `"role": "user"` thành `"role": "root"`, hậu quả bảo mật sẽ vô cùng nghiêm trọng. Bên nhận bắt buộc phải phát hiện ra sự can thiệp này và lập tức từ chối thông điệp.

### 5.1. Cuộc tấn công lật bit (Bit-flipping Attack) trên CTR

Nếu sử dụng CTR thuần túy, kẻ tấn công biết vị trí của chuỗi `"user"` trong bản rõ có thể thực hiện phép toán lật bit:
$$C' = C \oplus \text{"user"} \oplus \text{"root"}$$

Khi bên nhận giải mã bản mã bị sửa đổi này:
$$P' = C' \oplus \text{Keystream} = \text{"root"}$$

Do CTR chỉ đơn thuần XOR với Keystream mà không có cơ chế xác thực, phép giải mã vẫn diễn ra bình thường và hệ thống chấp nhận tài khoản với quyền `root` giả mạo!

### 5.2. Giải pháp toàn diện: AEAD với AES-GCM

**GCM (Galois/Counter Mode)** là chế độ mã hóa có xác thực (**AEAD - Authenticated Encryption with Associated Data**):
1. Dữ liệu được mã hóa bằng Counter Mode để đảm bảo tốc độ và không cần padding.
2. Song song với quá trình mã hóa, thuật toán băm Galois (GHASH) tính toán trên bản mã và dữ liệu liên kết bổ sung (AAD) để tạo ra một **Authentication Tag (thường dài 128 bit)** đi kèm bản mã.
3. Khi bên nhận giải mã, hệ thống tính toán lại Tag. Nếu dữ liệu bị thay đổi dù chỉ 1 bit, Tag sẽ không khớp và hàm giải mã lập tức ném ra ngoại lệ, **từ chối hoàn toàn dữ liệu**.

![Thử nghiệm sửa trường role: CTR bị giải mã sai thành root, GCM phát hiện tag không khớp](/assets/images/posts/aes-modes/04-json-tamper-ctr-vs-gcm.png)
_Hình 5 — Thử nghiệm sửa trường role: CTR giải mã ra root, còn GCM phát hiện Tag không hợp lệ và lập tức từ chối bản tin._

> [!IMPORTANT]
> **Điểm cần chú ý khi triển khai GCM:**
> - Nonce trong GCM (thường là 96 bit) tuyệt đối không được tái sử dụng với cùng một khóa.
> - Authentication Tag không tự chống lại tấn công phát lại (Replay Attack). Ứng dụng vẫn cần bổ sung số thứ tự gói tin (Sequence Number) hoặc Timestamp nếu kẻ tấn công có thể gửi lại bản tin cũ hợp lệ.

---

## 6. So sánh nhanh bốn chế độ mã hóa

| Chế độ | Điểm mạnh | Điểm cần chú ý | Tình huống phù hợp |
|:---:|---|---|---|
| **CBC** | Ẩn mẫu lặp tốt hơn nhiều so với ECB; thuật toán chuẩn mực lâu đời. | Bắt buộc padding PKCS#7; không có xác thực; dễ dính Padding Oracle nếu code sai. | Hệ thống kế thừa (Legacy systems), đối chiếu chuẩn mã hóa cũ. |
| **CTR** | Không cần padding; hỗ trợ tính toán song song; giữ nguyên độ dài ciphertext. | Tuyệt đối không được tái sử dụng Nonce/Counter; không có xác thực dữ liệu. | Luồng dữ liệu streaming, bản ghi nhỏ, thiết bị IoT hạn chế RAM/CPU. |
| **XTS** | Hỗ trợ đọc/ghi sector độc lập (Random Access); xử lý kích thước lẻ qua CTS; Tweak theo vị trí. | Không xác thực nội dung sector; chỉ thiết kế cho lưu trữ tĩnh. | Mã hóa ổ đĩa cứng, USB, BitLocker, dm-crypt/LUKS. |
| **GCM** | Mã hóa tích hợp xác thực toàn vẹn (AEAD); hiệu năng phần cứng rất cao. | Bắt buộc Nonce duy nhất; phải kiểm tra Tag nghiêm ngặt; cần cơ chế chống Replay riêng. | Bản tin mạng, REST API, JSON Web Encryption (JWE), TLS 1.3. |

---

## 7. Điều rút ra sau khi thử nghiệm trên bốn kiểu dữ liệu

Phần thú vị nhất của mật mã học ứng dụng không nằm ở những công thức toán học trừu tượng hay số vòng lặp AES. Cùng một thuật toán mã hóa 128 bit, nhưng mỗi loại dữ liệu lại đặt ra một bài toán thực tế riêng:
- Với **ảnh BMP**, thách thức là triệt tiêu mẫu lặp (Pattern Hiding).
- Với **log cảm biến IoT**, ưu tiên hàng đầu là loại bỏ Padding để tiết kiệm từng byte băng thông.
- Với **sector ổ đĩa**, đòi hỏi quan trọng là truy cập ngẫu nhiên và phân biệt vị trí vật lý.
- Với **bản tin JSON / API**, yêu cầu sống còn là khả năng phát hiện dữ liệu bị chỉnh sửa (Authentication).

Không có một chế độ mã hóa nào là vạn năng cho mọi tình huống. 

Nếu có một nguyên tắc quan trọng nhất cần ghi nhớ cho mọi dự án bảo mật, đó là: **Đừng bao giờ dừng lại ở câu nói "Dữ liệu của chúng tôi đã được mã hóa bằng AES". Hãy luôn hỏi tiếp: Mã hóa theo chế độ nào (Mode)? IV/Nonce được quản lý và sinh ra ra sao? Và tính toàn vẹn của dữ liệu được đảm bảo ở đâu?** Chính những chi tiết triển khai đó mới quyết định hệ thống của bạn có thực sự an toàn hay không.

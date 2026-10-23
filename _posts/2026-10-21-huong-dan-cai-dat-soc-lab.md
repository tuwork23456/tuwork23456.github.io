---
title: "Dựng SOC Home Lab và Lần Theo Một Cảnh Báo SSH"
permalink: /posts/soc-home-lab-ssh-investigation/
redirect_from:
  - /posts/huong-dan-cai-dat-soc-lab/
date: 2026-10-22 22:00:00 +0700
categories: [Security Operations, SOC Lab]
tags: [soc, elk-stack, elasticsearch, kibana, logstash, sysmon, winlogbeat, ssh-bruteforce, detection-rules, alert-triage]
description: "Hành trình tự dựng SOC Home Lab với ELK Stack 9.5.5, Sysmon, Winlogbeat và thực hành điều tra một cảnh báo SSH Brute-Force từ Detection đến Alert Triage."
image:
  path: /assets/images/posts/soc-lab/06-dashboard-truoc-kiem-thu.png
  alt: "Dựng SOC Home Lab và lần theo một cảnh báo SSH"
toc: true
comments: true
---

> **ELK Stack 9.5.5 | Windows Logs | Detection & Alert Triage**  
> Khi học về SOC, mình muốn hiểu một chuyện khá đơn giản: một lần đăng nhập sai trên Windows sẽ đi qua những đâu trước khi trở thành cảnh báo? Thay vì chỉ đọc tài liệu, mình dựng một hệ thống nhỏ tại nhà, cho máy Host kết nối vào Windows VM và theo dõi toàn bộ dấu vết trên Kibana.  
> Dự án không cố mô phỏng một SOC doanh nghiệp. Mục tiêu là nối được log từ đầu đến cuối, nhìn thấy điều gì đang xảy ra và tự kiểm tra xem Detection Rule có phát hiện đúng hay không.

---

## 1. Bắt đầu từ ELK Stack

### 1.1. Vì sao chọn ELK?

SIEM (Security Information and Event Management) là nơi tập trung log, tìm kiếm sự kiện và hỗ trợ phát hiện bất thường. Splunk, IBM QRadar hay Microsoft Sentinel là những nền tảng thường gặp; mỗi lựa chọn có cách triển khai và chi phí khác nhau.

Với một máy cá nhân, ELK Stack là lựa chọn phù hợp hơn: có thể tự triển khai bằng các tính năng Basic miễn phí, tài liệu phong phú và tự cấu hình từng mắt xích. Quan trọng nhất là nhìn rõ log đi từ Windows tới nơi lưu trữ và thành cảnh báo như thế nào. ELK không phải gói SIEM đầy đủ tính năng chỉ cần cài là dùng; phần thu thập dữ liệu và Detection Rule vẫn phải thiết lập.

Lưu ý nhỏ về giấy phép: theo mình tìm hiểu bản phân phối Elastic có những tính năng miễn phí lẫn trả phí; vì vậy không nên coi toàn bộ bộ sản phẩm hiện nay là “mã nguồn mở hoàn toàn”.

### 1.2. Ba thành phần chính

| Thành phần | Vai trò |
|---|---|
| **Elasticsearch** | Lưu trữ, đánh chỉ mục và tìm kiếm log. |
| **Logstash** | Nhận log, xử lý rồi chuyển vào Elasticsearch. |
| **Kibana** | Giao diện để tìm log, dựng Dashboard, tạo rule và xử lý Alerts. |

Ở Windows, Sysmon ghi thêm chi tiết về tiến trình và kết nối mạng. Winlogbeat lấy Windows Event Logs rồi gửi về Logstash. Hai công cụ này không nằm trong bộ ba ELK, nhưng lại là phần bắt buộc để SOC nhìn thấy máy đích.

### 1.3. Mô hình triển khai

Lab dùng hai máy ảo VMware và một máy Windows thật. Host kiêm vai trò tạo kết nối SSH, không cần thêm Kali VM, vừa gọn vừa tiết kiệm tài nguyên.

| Máy | Vai trò và địa chỉ |
|---|---|
| **socserver – Ubuntu Server 24.04** | `192.168.10.129` · Elasticsearch, Logstash, Kibana 9.5.5 |
| **pc01 – Windows 10 VM** | `192.168.10.128` · Sysmon, Winlogbeat 9.5.5, OpenSSH Server |
| **Windows Host** | `192.168.10.1` · SSH Client, Python |

![Hình 1. Luồng dữ liệu trong SOC Home Lab](/assets/images/posts/soc-lab/01-luong-du-lieu-soc-lab.png)
_Hình 1. Luồng dữ liệu trong SOC Home Lab._

Các máy trao đổi trong mạng VMware Host-only. SSH dùng TCP 22; Winlogbeat gửi về Logstash qua TCP 5044; Elasticsearch nhận dữ liệu từ Logstash qua HTTPS 9200; Kibana mở tại cổng 5601. Trước khi thay đổi Firewall hay cấu hình lớn, nên chụp snapshot để có thể quay lại trạng thái ổn định.

---

## 2. Nối các thành phần lại với nhau

### 2.1. Cài và kiểm tra ELK trên Ubuntu

Trên `socserver`, mình cài ba gói từ APT repository Elastic 9.x. Để bài không quá dài, phần dưới mình chỉ giữ những lệnh chính; điều quan trọng là phiên bản các thành phần đồng bộ với nhau.

```bash
wget -qO - https://artifacts.elastic.co/GPG-KEY-elasticsearch | sudo gpg --dearmor -o /usr/share/keyrings/elasticsearch-keyring.gpg
echo "deb [signed-by=/usr/share/keyrings/elasticsearch-keyring.gpg] https://artifacts.elastic.co/packages/9.x/apt stable main" | sudo tee /etc/apt/sources.list.d/elastic-9.x.list
sudo apt update
sudo apt install elasticsearch kibana logstash
```

```bash
dpkg-query -W -f='${Package} ${Version}\n' elasticsearch kibana logstash
```

![Hình 2. Cả ba thành phần được cài ở phiên bản 9.5.5](/assets/images/posts/soc-lab/02-phien-ban-elk-9-5-5.png)
_Hình 2. Cả ba thành phần được cài ở phiên bản 9.5.5._

Elasticsearch được bật trước. Lab giữ HTTPS và cơ chế xác thực mặc định thay vì tắt TLS cho nhanh:

```bash
sudo systemctl enable --now elasticsearch
curl --cacert /etc/elasticsearch/certs/http_ca.crt -u elastic https://localhost:9200
```

Khi API trả về thông tin node và cluster, có thể chuyển sang ghép Kibana với Elasticsearch bằng enrollment token và khởi động Kibana:

```bash
sudo /usr/share/elasticsearch/bin/elasticsearch-create-enrollment-token -s kibana
sudo systemctl enable --now kibana
```

![Hình 3. Kibana đã truy cập được từ Windows Host](/assets/images/posts/soc-lab/03-kibana-windows-host.png)
_Hình 3. Kibana đã truy cập được từ Windows Host._

Giao diện mở được ở `http://192.168.10.129:5601` là một mốc tốt, nhưng vẫn chưa có nghĩa dữ liệu Windows đã được thu thập. Phần đó nằm ở bước tiếp theo.

### 2.2. Logstash là điểm nhận log

Logstash lắng nghe cổng 5044 qua Beats input, sau đó đẩy dữ liệu sang Elasticsearch bằng HTTPS. Ở phía output, lab sử dụng CA certificate và API key riêng; khóa bí mật không nên đưa vào blog hay GitHub.

```conf
input {
  beats { port => 5044 }
}
# Output Elasticsearch: HTTPS + CA + API key (được bảo vệ)
```

```bash
sudo systemctl enable --now logstash
sudo ss -lntp | grep 5044
```

![Hình 4. Logstash đang lắng nghe cổng 5044](/assets/images/posts/soc-lab/04-logstash-port-5044.png)
_Hình 4. Logstash đang lắng nghe cổng 5044._

Ở bước này mình có từng gặp phải lỗi Logstash không đọc được CA của Elasticsearch. Và cách giải quyết là sửa quyền truy cập, và mình rút ra kinh nghiệm rằng trạng thái Running của từng dịch vụ chưa đủ để khẳng định cả pipeline hoạt động.

### 2.3. Đưa log từ pc01 về server

Trên `pc01`, Sysmon ghi nhận hoạt động như tạo tiến trình (Event ID 1), kết nối mạng (ID 3) hay DNS query (ID 22). Winlogbeat lấy các kênh log cần thiết rồi chuyển về Logstash. Phần cấu hình chính trong `winlogbeat.yml`:

```yaml
winlogbeat.event_logs:
  - name: Security
  - name: Microsoft-Windows-Sysmon/Operational
  - name: Microsoft-Windows-PowerShell/Operational

output.logstash:
  hosts: ["192.168.10.129:5044"]
```

Khi các sự kiện bắt đầu xuất hiện ở index `winlogbeat-*`, mình có thể đọc log của `pc01` ngay trên Kibana, không phải mở Event Viewer ở máy Windows mỗi lần cần kiểm tra.

![Hình 5. Windows Events đã xuất hiện trong Kibana Discover](/assets/images/posts/soc-lab/05-windows-events-discover.png)
_Hình 5. Windows Events đã xuất hiện trong Kibana Discover._

---

## 3. Từ những dòng log đến Dashboard

Discover là nơi xem từng sự kiện. Chẳng hạn, muốn tìm các lần tạo tiến trình trên `pc01`, chỉ cần lọc:

```kql
agent.hostname: "pc01" and event.code: "1"
```

Mỗi Event ID mang thông tin khác nhau: Sysmon ID 1 thường có Image, CommandLine và ParentImage; còn Windows Security Event 4625 lại nói về xác thực thất bại. Vì vậy, cùng một bảng log nhưng không phải trường nào cũng có giá trị ở mọi dòng.

Để không phải đọc từng log ngay từ đầu, mình dựng Dashboard gồm năm phần: **Total Events**, **Events Over Time**, **Top Sysmon Event IDs**, **Detection & Alerts** và **Recent Security Events**. Bảng log cuối chỉ hiển thị sáu cột quan trọng; khi cần chi tiết mới mở Discover.

![Hình 6. Dashboard tổng quan trước khi chạy kiểm thử SSH](/assets/images/posts/soc-lab/06-dashboard-truoc-kiem-thu.png)
_Hình 6. Dashboard tổng quan trước khi chạy kiểm thử SSH._

Cách chia này giúp tách hai việc: Dashboard để nhận ra có điều gì cần chú ý, Discover và Alerts để tìm câu trả lời.

---

## 4. Từ SSH thất bại đến High Alert

### 4.1. Tạo một chuỗi đăng nhập sai có kiểm soát

Để xem rule có hoạt động không, Windows Host dùng Python và Paramiko gửi năm yêu cầu xác thực SSH bằng tài khoản không tồn tại. Script không thử nhiều mật khẩu hay dùng wordlist; mọi lần đều cố ý thất bại, cách nhau ba giây. Đoạn dưới là phần chính của script (Host Key được xác minh trước khi chạy).

```python
import time
from pathlib import Path
import paramiko

for i in range(1, 6):
    with paramiko.SSHClient() as ssh:
        ssh.load_host_keys(str(Path.home() / ".ssh" / "known_hosts"))
        ssh.set_missing_host_key_policy(paramiko.RejectPolicy())
        try:
            ssh.connect("192.168.10.128", port=22,
                        username="soc_test_invalid",
                        password="SOC_LAB_WrongPassword_123!",
                        look_for_keys=False, allow_agent=False)
            break
        except paramiko.AuthenticationException:
            print(f"[{i}/5] Xac thuc that bai")
    if i < 5:
        time.sleep(3)
```

![Hình 7. Python trả về năm lần xác thực thất bại](/assets/images/posts/soc-lab/07-python-ssh-that-bai.png)
_Hình 7. Python trả về năm lần xác thực thất bại._

### 4.2. Đọc log trong Kibana

Dùng Discover để lọc Event ID 4625 thay vì tìm ngay trong Event Viewer. Sau lần chạy đầu tiên, các sự kiện xuất hiện vào khoảng 21:37:52–21:38:04 ngày 22/10/2026, cách nhau gần ba giây, trùng với khoảng nghỉ trong code.

```kql
agent.hostname: "pc01" and
 event.code: "4625" and
 winlog.event_data.LogonType: "8" and
 winlog.event_data.TargetUserName: "NOUSER"
```

![Hình 8. Năm sự kiện 4625 xuất hiện gần như đúng nhịp ba giây](/assets/images/posts/soc-lab/08-su-kien-4625.png)
_Hình 8. Năm sự kiện 4625 xuất hiện gần như đúng nhịp ba giây._

Trong log có `TargetUserName = NOUSER`, `LogonType = 8` và `FailureReason` cho biết sai tài khoản hoặc mật khẩu.

### 4.3. Viết rule và kiểm chứng

Một lần đăng nhập sai là chuyện bình thường; nhiều lần liên tiếp mới đáng xem xét. Vì vậy mình dùng **Threshold Rule**, thay vì để mỗi event tạo một cảnh báo riêng.

| Thiết lập | Giá trị |
|---|---|
| **Loại rule / dữ liệu** | Threshold · `winlogbeat-*` |
| **Điều kiện** | Event 4625 + LogonType 8 + NOUSER trên pc01 |
| **Nhóm / Ngưỡng** | `agent.hostname` · ít nhất 5 sự kiện |
| **Lịch chạy** | Mỗi 1 phút, look-back 4 phút |
| **Mức độ / MITRE** | High · Risk 73 · T1110 Brute Force |

![Hình 9. Threshold Rule đã được bật với ngưỡng năm sự kiện](/assets/images/posts/soc-lab/09-threshold-rule.png)
_Hình 9. Threshold Rule đã được bật với ngưỡng năm sự kiện._

Sau khi chạy lại script, Dashboard xuất hiện High Alert và trang **Security → Alerts** ghi nhận cảnh báo lúc 22:13:22.329. Trong chi tiết alert, `kibana.alert.threshold_result.count = 5` và `terms.value = pc01`. Nghĩa là rule đã đếm đủ năm sự kiện cùng nhóm; không phải năm cảnh báo riêng lẻ.

![Hình 10. Dashboard xuất hiện một High Alert](/assets/images/posts/soc-lab/10-dashboard-high-alert.png)
_Hình 10. Dashboard xuất hiện một High Alert._

![Hình 11. Cảnh báo SSH Brute-force trên trang Security → Alerts](/assets/images/posts/soc-lab/11-canh-bao-ssh-bruteforce.png)
_Hình 11. Cảnh báo SSH Brute-force trên trang Security → Alerts._

Đây là kết quả cần nhất của project: hành vi tạo trên Host đã đi qua Windows Events, Winlogbeat, Logstash, Elasticsearch và cuối cùng kích hoạt đúng Detection Rule.

---

## 5. Khi đã có cảnh báo, xử lý thế nào?

Có alert chưa phải là kết thúc. Theo mình, phần quan trọng tiếp theo là đọc lại bằng chứng và quyết định cảnh báo có cần xử lý thêm hay không.

Mình chuyển alert từ **Open** sang **Acknowledged**, đối chiếu với thời điểm chạy script và log 4625, sau đó lưu **Investigation Notes**. Kết luận được ghi là *True Positive – Authorized Security Testing*: hành vi được phát hiện là thật, nhưng nó được tạo có chủ đích trong môi trường lab nên không cần cô lập máy.

![Hình 12. Ghi chú điều tra được lưu cùng alert](/assets/images/posts/soc-lab/12-ghi-chu-dieu-tra.png)
_Hình 12. Ghi chú điều tra được lưu cùng alert._

Cuối cùng đổi trạng thái sang **Closed** và lọc danh sách cảnh báo đã đóng để chắc rằng lịch sử vẫn còn. Đây là bước ghi nhận đã xử lý, không phải lệnh chặn IP hay ngắt dịch vụ SSH.

![Hình 13. Cảnh báo ở trạng thái Closed, kèm ghi chú điều tra](/assets/images/posts/soc-lab/13-canh-bao-closed.png)
_Hình 13. Cảnh báo ở trạng thái Closed, kèm ghi chú điều tra._

---

## 6. Nhìn lại

Phần hữu ích nhất của SOC Home Lab này không nằm ở số lượng log. Nó nằm ở việc có thể lần theo một sự kiện nhỏ từ máy Windows, qua hệ thống thu thập, tới cảnh báo và cuối cùng là một kết luận điều tra có căn cứ.

Dự án hiện dừng ở Monitoring, Detection, Alert Triage và Closure. Việc chặn IP tự động, SOAR hay mở rộng nhiều endpoint vẫn là những hướng phát triển sau. Với mục tiêu học SOC và chuẩn bị ứng tuyển Intern, mình muốn nắm chắc luồng xử lý này trước khi thêm công cụ mới. Cảm ơn bạn đã đọc bài blog này của mình, chúc bạn có một ngày mới vui vẻ và hẹn gặp lại bạn với các blog tiếp theo của mình hehe.

### Tài liệu tham khảo

- [Elastic Documentation](https://www.elastic.co/docs)
- [Winlogbeat Logstash Output](https://www.elastic.co/docs/reference/beats/winlogbeat/logstash-output)
- [Elastic Threshold Rules](https://www.elastic.co/docs/solutions/security/detect-and-alert/threshold)
- [Microsoft Sysmon](https://learn.microsoft.com/en-us/sysinternals/downloads/sysmon)
- [MITRE ATT&CK: Brute Force (T1110)](https://attack.mitre.org/techniques/T1110/)

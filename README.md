# WiFi Security Checker 🔒

Công cụ kiểm tra bảo mật WiFi - Giúp bạn kiểm tra xem password WiFi của mình có đủ mạnh không.

## ✨ Tính năng

1. **📡 Quét WiFi** - Hiển thị tất cả các mạng WiFi xung quanh với thông tin:
   - Tên mạng (SSID)
   - Cường độ tín hiệu
   - Loại bảo mật (WPA2, WPA3, etc.)

2. **🔑 Kiểm tra Password** - Phân tích password của bạn:
   - Kiểm tra trong các wordlist phổ biến
   - Đánh giá độ mạnh
   - Gợi ý cải thiện

## 🚀 Cài đặt

### Yêu cầu
- Windows 10/11
- Python 3.8+

### Bước 1: Cài đặt dependencies
```batch
install.bat
```
hoặc
```bash
pip install -r requirements.txt
```

### Bước 2: Chạy ứng dụng
```batch
run.bat
```
hoặc
```bash
python wifi_scanner.py
```

## 📖 Hướng dẫn sử dụng

### Quét WiFi
1. Click nút **"🔄 Quét"** ở panel bên trái
2. Đợi vài giây để quét xong
3. Xem danh sách các mạng WiFi được tìm thấy

### Kiểm tra Password
1. Nhập password WiFi của bạn vào ô input
2. Click **"🔍 Kiểm tra Password"**
3. Xem kết quả:
   - **Đánh giá tổng quan**: Rất yếu → Rất mạnh
   - **Chi tiết phân tích**: Độ dài, chữ hoa/thường, số, ký tự đặc biệt
   - **Kiểm tra Wordlist**: Password có nằm trong danh sách phổ biến không
   - **Gợi ý cải thiện**: Cách làm password mạnh hơn

## 📁 Cấu trúc thư mục

```
Wifi Scanner/
├── wifi_scanner.py      # Ứng dụng chính
├── requirements.txt     # Dependencies
├── install.bat         # Script cài đặt
├── run.bat            # Script chạy ứng dụng
├── README.md          # Hướng dẫn
└── wordlists/         # Thư mục chứa wordlists
    └── common_passwords.txt
```

## 🔧 Thêm Wordlist

Bạn có thể thêm wordlist của riêng mình:

1. Tạo file `.txt` trong thư mục `wordlists/`
2. Mỗi dòng là một password
3. Khởi động lại ứng dụng

**Wordlist phổ biến:**
- [RockYou](https://github.com/brannondorsey/naive-hashcat/releases/download/data/rockyou.txt)
- [SecLists](https://github.com/danielmiessler/SecLists)

## ⚠️ Lưu ý quan trọng

- Công cụ này **chỉ dùng để kiểm tra password WiFi của chính bạn**
- Không sử dụng để tấn công mạng của người khác
- Việc truy cập trái phép vào mạng WiFi là **bất hợp pháp**

## 💡 Tips bảo mật WiFi

1. Sử dụng password dài ít nhất **12 ký tự**
2. Kết hợp chữ HOA, chữ thường, số và ký tự đặc biệt
3. Tránh sử dụng thông tin cá nhân (tên, ngày sinh)
4. Không sử dụng các password phổ biến
5. Đổi password định kỳ (3-6 tháng/lần)
6. Sử dụng **WPA3** nếu router hỗ trợ

---

Made with ❤️ for WiFi Security

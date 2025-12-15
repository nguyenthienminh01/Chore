"""
WiFi Scanner & Password Strength Checker
=========================================
Công cụ kiểm tra bảo mật WiFi - Quét mạng WiFi và kiểm tra độ mạnh password

Author: WiFi Security Tool
Purpose: Kiểm tra password WiFi của bạn có nằm trong wordlist phổ biến không
"""

import customtkinter as ctk
from tkinter import messagebox, filedialog
import threading
import subprocess
import re
import os
import hashlib
from datetime import datetime


class WifiScanner:
    """Class để quét các mạng WiFi xung quanh sử dụng netsh (Windows native)"""
    
    def scan(self):
        """Quét và trả về danh sách các mạng WiFi"""
        networks = []
        try:
            # Sử dụng netsh để quét WiFi trên Windows
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'networks', 'mode=bssid'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output = result.stdout
            current_network = {}
            
            for line in output.split('\n'):
                line = line.strip()
                
                if line.startswith('SSID') and ':' in line and 'BSSID' not in line:
                    if current_network.get('ssid'):
                        networks.append(current_network.copy())
                    ssid = line.split(':', 1)[1].strip()
                    current_network = {'ssid': ssid, 'signal': 0, 'auth': 'Unknown', 'bssid': ''}
                    
                elif 'Signal' in line or 'Tín hiệu' in line:
                    match = re.search(r'(\d+)%', line)
                    if match:
                        current_network['signal'] = int(match.group(1))
                        
                elif 'Authentication' in line or 'Xác thực' in line:
                    auth = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                    current_network['auth'] = auth
                    
                elif 'BSSID' in line:
                    bssid = line.split(':', 1)[1].strip() if ':' in line else ''
                    current_network['bssid'] = bssid
            
            # Thêm network cuối cùng
            if current_network.get('ssid'):
                networks.append(current_network)
                
        except Exception as e:
            print(f"Lỗi khi quét WiFi: {e}")
            
        return networks
    
    def get_saved_networks(self):
        """Lấy danh sách các mạng WiFi đã lưu"""
        saved = []
        try:
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'profiles'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            for line in result.stdout.split('\n'):
                if 'All User Profile' in line or 'Tất cả người dùng' in line:
                    match = re.search(r':\s*(.+)', line)
                    if match:
                        saved.append(match.group(1).strip())
                        
        except Exception as e:
            print(f"Lỗi khi lấy mạng đã lưu: {e}")
            
        return saved


class PasswordChecker:
    """Class để kiểm tra độ mạnh password"""
    
    def __init__(self, wordlist_dir="wordlists"):
        self.wordlist_dir = wordlist_dir
        self.wordlists = {}
        self.load_wordlists()
        
    def load_wordlists(self):
        """Load tất cả wordlists từ thư mục"""
        if not os.path.exists(self.wordlist_dir):
            os.makedirs(self.wordlist_dir)
            return
            
        for filename in os.listdir(self.wordlist_dir):
            if filename.endswith('.txt'):
                filepath = os.path.join(self.wordlist_dir, filename)
                try:
                    with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                        passwords = set(line.strip().lower() for line in f if line.strip())
                        self.wordlists[filename] = passwords
                        print(f"Đã load {len(passwords)} passwords từ {filename}")
                except Exception as e:
                    print(f"Lỗi load {filename}: {e}")
    
    def check_in_wordlist(self, password):
        """Kiểm tra password có trong wordlist không"""
        results = []
        password_lower = password.lower()
        
        for wordlist_name, passwords in self.wordlists.items():
            if password_lower in passwords:
                results.append({
                    'found': True,
                    'wordlist': wordlist_name,
                    'message': f"⚠️ Password được tìm thấy trong {wordlist_name}"
                })
            else:
                results.append({
                    'found': False,
                    'wordlist': wordlist_name,
                    'message': f"✅ Không tìm thấy trong {wordlist_name}"
                })
                
        return results
    
    def analyze_strength(self, password):
        """Phân tích chi tiết độ mạnh password"""
        analysis = {
            'length': len(password),
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>]', password)),
            'score': 0,
            'rating': '',
            'suggestions': []
        }
        
        # Tính điểm
        if analysis['length'] >= 8: analysis['score'] += 1
        if analysis['length'] >= 12: analysis['score'] += 1
        if analysis['length'] >= 16: analysis['score'] += 1
        if analysis['has_upper']: analysis['score'] += 1
        if analysis['has_lower']: analysis['score'] += 1
        if analysis['has_digit']: analysis['score'] += 1
        if analysis['has_special']: analysis['score'] += 2
        
        # Trừ điểm nếu có pattern dễ đoán
        if re.search(r'(.)\1{2,}', password):  # Ký tự lặp
            analysis['score'] -= 1
            analysis['suggestions'].append("Tránh ký tự lặp liên tiếp (ví dụ: 'aaa')")
            
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            analysis['score'] -= 1
            analysis['suggestions'].append("Tránh dãy số liên tiếp")
            
        if re.search(r'(abc|bcd|cde|def|qwe|wer|ert|asd|sdf|zxc)', password.lower()):
            analysis['score'] -= 1
            analysis['suggestions'].append("Tránh dãy chữ cái liên tiếp trên bàn phím")
        
        # Rating
        if analysis['score'] <= 2:
            analysis['rating'] = 'Rất yếu'
            analysis['color'] = '#FF4444'
        elif analysis['score'] <= 4:
            analysis['rating'] = 'Yếu'
            analysis['color'] = '#FF8844'
        elif analysis['score'] <= 6:
            analysis['rating'] = 'Trung bình'
            analysis['color'] = '#FFBB33'
        elif analysis['score'] <= 7:
            analysis['rating'] = 'Mạnh'
            analysis['color'] = '#99CC00'
        else:
            analysis['rating'] = 'Rất mạnh'
            analysis['color'] = '#00C851'
            
        # Gợi ý cải thiện
        if not analysis['has_upper']:
            analysis['suggestions'].append("Thêm chữ HOA (A-Z)")
        if not analysis['has_lower']:
            analysis['suggestions'].append("Thêm chữ thường (a-z)")
        if not analysis['has_digit']:
            analysis['suggestions'].append("Thêm số (0-9)")
        if not analysis['has_special']:
            analysis['suggestions'].append("Thêm ký tự đặc biệt (!@#$%...)")
        if analysis['length'] < 12:
            analysis['suggestions'].append(f"Tăng độ dài (hiện tại: {analysis['length']}, nên >= 12)")
            
        return analysis


class WifiSecurityApp(ctk.CTk):
    """Ứng dụng chính"""
    
    def __init__(self):
        super().__init__()
        
        # Cấu hình cửa sổ
        self.title("🔒 WiFi Security Checker - Kiểm tra bảo mật WiFi")
        self.geometry("1100x750")
        self.minsize(900, 600)
        
        # Cấu hình theme
        ctk.set_appearance_mode("dark")
        ctk.set_default_color_theme("blue")
        
        # Khởi tạo components
        self.wifi_scanner = WifiScanner()
        self.password_checker = PasswordChecker(
            os.path.join(os.path.dirname(__file__), "wordlists")
        )
        
        self.create_ui()
        
    def create_ui(self):
        """Tạo giao diện người dùng"""
        # Header
        self.create_header()
        
        # Main container với 2 panels
        self.main_container = ctk.CTkFrame(self, fg_color="transparent")
        self.main_container.pack(fill="both", expand=True, padx=20, pady=(10, 20))
        self.main_container.grid_columnconfigure(0, weight=1)
        self.main_container.grid_columnconfigure(1, weight=1)
        self.main_container.grid_rowconfigure(0, weight=1)
        
        # Left panel - WiFi Scanner
        self.create_scanner_panel()
        
        # Right panel - Password Checker
        self.create_checker_panel()
        
    def create_header(self):
        """Tạo header"""
        header = ctk.CTkFrame(self, height=80, fg_color=("#1a1a2e", "#1a1a2e"))
        header.pack(fill="x", padx=20, pady=(20, 10))
        header.pack_propagate(False)
        
        # Title
        title = ctk.CTkLabel(
            header,
            text="🔒 WiFi Security Checker",
            font=ctk.CTkFont(size=28, weight="bold"),
            text_color="#00D4FF"
        )
        title.pack(side="left", padx=30, pady=20)
        
        # Subtitle
        subtitle = ctk.CTkLabel(
            header,
            text="Kiểm tra độ mạnh password WiFi của bạn",
            font=ctk.CTkFont(size=14),
            text_color="#888888"
        )
        subtitle.pack(side="left", pady=20)
        
        # Status indicator
        self.status_label = ctk.CTkLabel(
            header,
            text="● Sẵn sàng",
            font=ctk.CTkFont(size=12),
            text_color="#00C851"
        )
        self.status_label.pack(side="right", padx=30, pady=20)
        
    def create_scanner_panel(self):
        """Tạo panel quét WiFi"""
        panel = ctk.CTkFrame(self.main_container, fg_color=("#16213e", "#16213e"), corner_radius=15)
        panel.grid(row=0, column=0, sticky="nsew", padx=(0, 10), pady=0)
        
        # Title
        title_frame = ctk.CTkFrame(panel, fg_color="transparent")
        title_frame.pack(fill="x", padx=20, pady=(20, 15))
        
        ctk.CTkLabel(
            title_frame,
            text="📡 Quét WiFi",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#FFFFFF"
        ).pack(side="left")
        
        # Scan button
        self.scan_btn = ctk.CTkButton(
            title_frame,
            text="🔄 Quét",
            width=100,
            height=35,
            fg_color="#0077B6",
            hover_color="#005F8A",
            command=self.start_scan
        )
        self.scan_btn.pack(side="right")
        
        # Networks list
        list_frame = ctk.CTkFrame(panel, fg_color=("#0d1b2a", "#0d1b2a"), corner_radius=10)
        list_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        # Scrollable frame for networks
        self.networks_scroll = ctk.CTkScrollableFrame(
            list_frame,
            fg_color="transparent",
            scrollbar_button_color="#0077B6"
        )
        self.networks_scroll.pack(fill="both", expand=True, padx=10, pady=10)
        
        # Placeholder
        self.no_networks_label = ctk.CTkLabel(
            self.networks_scroll,
            text="Nhấn 'Quét' để tìm các mạng WiFi xung quanh",
            font=ctk.CTkFont(size=13),
            text_color="#666666"
        )
        self.no_networks_label.pack(pady=50)
        
    def create_checker_panel(self):
        """Tạo panel kiểm tra password"""
        panel = ctk.CTkFrame(self.main_container, fg_color=("#16213e", "#16213e"), corner_radius=15)
        panel.grid(row=0, column=1, sticky="nsew", padx=(10, 0), pady=0)
        
        # Title
        ctk.CTkLabel(
            panel,
            text="🔑 Kiểm tra Password",
            font=ctk.CTkFont(size=20, weight="bold"),
            text_color="#FFFFFF"
        ).pack(pady=(20, 15), padx=20, anchor="w")
        
        # Password input frame
        input_frame = ctk.CTkFrame(panel, fg_color=("#0d1b2a", "#0d1b2a"), corner_radius=10)
        input_frame.pack(fill="x", padx=20, pady=(0, 15))
        
        ctk.CTkLabel(
            input_frame,
            text="Nhập password WiFi của bạn:",
            font=ctk.CTkFont(size=13),
            text_color="#AAAAAA"
        ).pack(anchor="w", padx=15, pady=(15, 5))
        
        # Password entry with show/hide
        entry_container = ctk.CTkFrame(input_frame, fg_color="transparent")
        entry_container.pack(fill="x", padx=15, pady=(0, 15))
        
        self.password_entry = ctk.CTkEntry(
            entry_container,
            height=45,
            font=ctk.CTkFont(size=14),
            placeholder_text="Nhập password...",
            show="•",
            fg_color=("#1a1a2e", "#1a1a2e"),
            border_color="#0077B6"
        )
        self.password_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        self.show_password = False
        self.toggle_btn = ctk.CTkButton(
            entry_container,
            text="👁",
            width=45,
            height=45,
            fg_color="#333344",
            hover_color="#444455",
            command=self.toggle_password_visibility
        )
        self.toggle_btn.pack(side="right")
        
        # Check button
        self.check_btn = ctk.CTkButton(
            panel,
            text="🔍 Kiểm tra Password",
            height=45,
            font=ctk.CTkFont(size=15, weight="bold"),
            fg_color="#00C851",
            hover_color="#00A843",
            command=self.check_password
        )
        self.check_btn.pack(fill="x", padx=20, pady=(0, 15))
        
        # Results frame
        results_frame = ctk.CTkFrame(panel, fg_color=("#0d1b2a", "#0d1b2a"), corner_radius=10)
        results_frame.pack(fill="both", expand=True, padx=20, pady=(0, 20))
        
        ctk.CTkLabel(
            results_frame,
            text="📊 Kết quả phân tích",
            font=ctk.CTkFont(size=15, weight="bold"),
            text_color="#FFFFFF"
        ).pack(anchor="w", padx=15, pady=(15, 10))
        
        # Scrollable results
        self.results_scroll = ctk.CTkScrollableFrame(
            results_frame,
            fg_color="transparent",
            scrollbar_button_color="#0077B6"
        )
        self.results_scroll.pack(fill="both", expand=True, padx=10, pady=(0, 10))
        
        # Placeholder
        self.results_placeholder = ctk.CTkLabel(
            self.results_scroll,
            text="Nhập password và nhấn 'Kiểm tra' để xem kết quả",
            font=ctk.CTkFont(size=13),
            text_color="#666666"
        )
        self.results_placeholder.pack(pady=30)
        
    def toggle_password_visibility(self):
        """Toggle hiển thị password"""
        self.show_password = not self.show_password
        self.password_entry.configure(show="" if self.show_password else "•")
        self.toggle_btn.configure(text="🙈" if self.show_password else "👁")
        
    def start_scan(self):
        """Bắt đầu quét WiFi trong thread riêng"""
        self.scan_btn.configure(state="disabled", text="⏳ Đang quét...")
        self.status_label.configure(text="● Đang quét...", text_color="#FFBB33")
        
        # Chạy scan trong thread riêng
        thread = threading.Thread(target=self.perform_scan, daemon=True)
        thread.start()
        
    def perform_scan(self):
        """Thực hiện quét WiFi"""
        networks = self.wifi_scanner.scan()
        
        # Update UI trong main thread
        self.after(0, lambda: self.display_networks(networks))
        
    def display_networks(self, networks):
        """Hiển thị kết quả quét"""
        # Clear existing widgets
        for widget in self.networks_scroll.winfo_children():
            widget.destroy()
            
        if not networks:
            self.no_networks_label = ctk.CTkLabel(
                self.networks_scroll,
                text="Không tìm thấy mạng WiFi nào.\nĐảm bảo WiFi adapter đang bật.",
                font=ctk.CTkFont(size=13),
                text_color="#FF4444"
            )
            self.no_networks_label.pack(pady=50)
        else:
            # Sort by signal strength
            networks.sort(key=lambda x: x.get('signal', 0), reverse=True)
            
            for network in networks:
                self.create_network_card(network)
                
        self.scan_btn.configure(state="normal", text="🔄 Quét")
        self.status_label.configure(
            text=f"● Tìm thấy {len(networks)} mạng",
            text_color="#00C851"
        )
        
    def create_network_card(self, network):
        """Tạo card hiển thị thông tin mạng"""
        card = ctk.CTkFrame(
            self.networks_scroll,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=8,
            height=70
        )
        card.pack(fill="x", pady=5, padx=5)
        card.pack_propagate(False)
        
        # Left side - Info
        info_frame = ctk.CTkFrame(card, fg_color="transparent")
        info_frame.pack(side="left", fill="both", expand=True, padx=15, pady=10)
        
        ssid = network.get('ssid', 'Unknown')
        if not ssid:
            ssid = "(Hidden Network)"
            
        ctk.CTkLabel(
            info_frame,
            text=f"📶 {ssid}",
            font=ctk.CTkFont(size=14, weight="bold"),
            text_color="#FFFFFF"
        ).pack(anchor="w")
        
        auth = network.get('auth', 'Unknown')
        ctk.CTkLabel(
            info_frame,
            text=f"🔐 {auth}",
            font=ctk.CTkFont(size=11),
            text_color="#888888"
        ).pack(anchor="w")
        
        # Right side - Signal
        signal = network.get('signal', 0)
        signal_color = "#00C851" if signal >= 70 else "#FFBB33" if signal >= 40 else "#FF4444"
        
        signal_frame = ctk.CTkFrame(card, fg_color="transparent", width=80)
        signal_frame.pack(side="right", padx=15)
        signal_frame.pack_propagate(False)
        
        ctk.CTkLabel(
            signal_frame,
            text=f"{signal}%",
            font=ctk.CTkFont(size=18, weight="bold"),
            text_color=signal_color
        ).pack(pady=10)
        
    def check_password(self):
        """Kiểm tra password"""
        password = self.password_entry.get()
        
        if not password:
            messagebox.showwarning("Cảnh báo", "Vui lòng nhập password để kiểm tra!")
            return
            
        self.check_btn.configure(state="disabled", text="⏳ Đang kiểm tra...")
        
        # Run in thread
        thread = threading.Thread(target=lambda: self.perform_check(password), daemon=True)
        thread.start()
        
    def perform_check(self, password):
        """Thực hiện kiểm tra password"""
        # Phân tích độ mạnh
        strength = self.password_checker.analyze_strength(password)
        
        # Kiểm tra trong wordlists
        wordlist_results = self.password_checker.check_in_wordlist(password)
        
        # Update UI
        self.after(0, lambda: self.display_results(strength, wordlist_results))
        
    def display_results(self, strength, wordlist_results):
        """Hiển thị kết quả kiểm tra"""
        # Clear existing
        for widget in self.results_scroll.winfo_children():
            widget.destroy()
            
        # Overall rating card
        rating_card = ctk.CTkFrame(
            self.results_scroll,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=10
        )
        rating_card.pack(fill="x", pady=(0, 15), padx=5)
        
        # Rating header
        ctk.CTkLabel(
            rating_card,
            text="Đánh giá tổng quan",
            font=ctk.CTkFont(size=12),
            text_color="#888888"
        ).pack(anchor="w", padx=15, pady=(15, 5))
        
        rating_text = f"💪 {strength['rating']}"
        ctk.CTkLabel(
            rating_card,
            text=rating_text,
            font=ctk.CTkFont(size=24, weight="bold"),
            text_color=strength['color']
        ).pack(padx=15, pady=(0, 5))
        
        # Strength bar
        bar_frame = ctk.CTkFrame(rating_card, fg_color="#333344", height=8, corner_radius=4)
        bar_frame.pack(fill="x", padx=15, pady=(0, 15))
        bar_frame.pack_propagate(False)
        
        fill_width = min(1.0, strength['score'] / 8)
        fill_bar = ctk.CTkFrame(
            bar_frame,
            fg_color=strength['color'],
            corner_radius=4
        )
        fill_bar.place(relwidth=fill_width, relheight=1.0)
        
        # Details card
        details_card = ctk.CTkFrame(
            self.results_scroll,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=10
        )
        details_card.pack(fill="x", pady=(0, 15), padx=5)
        
        ctk.CTkLabel(
            details_card,
            text="📋 Chi tiết phân tích",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF"
        ).pack(anchor="w", padx=15, pady=(15, 10))
        
        details = [
            (f"Độ dài: {strength['length']} ký tự", strength['length'] >= 8),
            (f"Chữ hoa (A-Z)", strength['has_upper']),
            (f"Chữ thường (a-z)", strength['has_lower']),
            (f"Số (0-9)", strength['has_digit']),
            (f"Ký tự đặc biệt", strength['has_special']),
        ]
        
        for text, passed in details:
            icon = "✅" if passed else "❌"
            color = "#00C851" if passed else "#FF4444"
            ctk.CTkLabel(
                details_card,
                text=f"  {icon} {text}",
                font=ctk.CTkFont(size=12),
                text_color=color
            ).pack(anchor="w", padx=15, pady=2)
            
        # Padding bottom
        ctk.CTkFrame(details_card, fg_color="transparent", height=10).pack()
        
        # Wordlist results card
        wordlist_card = ctk.CTkFrame(
            self.results_scroll,
            fg_color=("#1a1a2e", "#1a1a2e"),
            corner_radius=10
        )
        wordlist_card.pack(fill="x", pady=(0, 15), padx=5)
        
        ctk.CTkLabel(
            wordlist_card,
            text="📚 Kiểm tra Wordlist",
            font=ctk.CTkFont(size=13, weight="bold"),
            text_color="#FFFFFF"
        ).pack(anchor="w", padx=15, pady=(15, 10))
        
        found_in_any = False
        for result in wordlist_results:
            if result['found']:
                found_in_any = True
                color = "#FF4444"
            else:
                color = "#00C851"
                
            ctk.CTkLabel(
                wordlist_card,
                text=f"  {result['message']}",
                font=ctk.CTkFont(size=12),
                text_color=color
            ).pack(anchor="w", padx=15, pady=2)
            
        if found_in_any:
            warning = ctk.CTkLabel(
                wordlist_card,
                text="\n⚠️ PASSWORD CỦA BẠN DỄ BỊ TẤN CÔNG!\nHacker có thể đoán được password này trong vài giây.",
                font=ctk.CTkFont(size=12, weight="bold"),
                text_color="#FF4444"
            )
            warning.pack(padx=15, pady=(5, 15))
        else:
            safe = ctk.CTkLabel(
                wordlist_card,
                text="\n✅ Password không nằm trong các wordlist phổ biến",
                font=ctk.CTkFont(size=12),
                text_color="#00C851"
            )
            safe.pack(padx=15, pady=(5, 15))
            
        # Suggestions card
        if strength['suggestions']:
            suggest_card = ctk.CTkFrame(
                self.results_scroll,
                fg_color=("#1a1a2e", "#1a1a2e"),
                corner_radius=10
            )
            suggest_card.pack(fill="x", pady=(0, 15), padx=5)
            
            ctk.CTkLabel(
                suggest_card,
                text="💡 Gợi ý cải thiện",
                font=ctk.CTkFont(size=13, weight="bold"),
                text_color="#FFFFFF"
            ).pack(anchor="w", padx=15, pady=(15, 10))
            
            for suggestion in strength['suggestions']:
                ctk.CTkLabel(
                    suggest_card,
                    text=f"  • {suggestion}",
                    font=ctk.CTkFont(size=12),
                    text_color="#FFBB33"
                ).pack(anchor="w", padx=15, pady=2)
                
            ctk.CTkFrame(suggest_card, fg_color="transparent", height=10).pack()
            
        self.check_btn.configure(state="normal", text="🔍 Kiểm tra Password")


def main():
    app = WifiSecurityApp()
    app.mainloop()


if __name__ == "__main__":
    main()

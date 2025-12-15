# 🔓 WIFISEC - Matrix Edition

<div align="center">

```
██╗    ██╗██╗███████╗██╗    ███████╗███████╗ ██████╗
██║    ██║██║██╔════╝██║    ██╔════╝██╔════╝██╔════╝
██║ █╗ ██║██║█████╗  ██║    ███████╗█████╗  ██║     
██║███╗██║██║██╔══╝  ██║    ╚════██║██╔══╝  ██║     
╚███╔███╔╝██║██║     ██║    ███████║███████╗╚██████╗
 ╚══╝╚══╝ ╚═╝╚═╝     ╚═╝    ╚══════╝╚══════╝ ╚═════╝
```

**Professional WiFi Penetration Testing Framework**

[![Python](https://img.shields.io/badge/Python-3.8+-green?style=for-the-badge&logo=python)](https://python.org)
[![Flask](https://img.shields.io/badge/Flask-2.0+-green?style=for-the-badge&logo=flask)](https://flask.palletsprojects.com)
[![Platform](https://img.shields.io/badge/Platform-Windows-green?style=for-the-badge&logo=windows)](https://www.microsoft.com/windows)
[![License](https://img.shields.io/badge/License-Educational-green?style=for-the-badge)](LICENSE)

</div>

---

## ⚡ Features

### 🎯 Core Features
- **� Network Scanner** - Discover all nearby WiFi networks with signal strength
- **🔓 Bruteforce Attack** - Dictionary attack against WPA/WPA2 networks
- **📊 Password Analyzer** - Check password strength against known wordlists
- **📝 Multiple Wordlists** - 28,000+ passwords from various sources

### 🎨 Matrix UI
- **Matrix Rain Background** - Authentic falling Japanese katakana
- **CRT Flicker Effect** - Retro monitor simulation
- **Terminal Aesthetic** - Professional hacker interface
- **Real-time Logging** - Live attack progress display
- **Neon Green Theme** - Classic Matrix color scheme

---

## 📸 Screenshots

### Main Interface
```
┌─────────────────────────────────────────────────────┐
│  ██╗    ██╗██╗███████╗██╗    ███████╗███████╗ ██████╗│
│  WIFISEC - Matrix Edition                           │
│                                                     │
│  [📡 NETWORK_SCANNER]          [💻 SYSTEM_LOG]      │
│  ├─ NETWORK_1 [80%] ████       [SYS] Initialized... │
│  ├─ NETWORK_2 [65%] ███        [ATK] Starting...    │
│  └─ NETWORK_3 [40%] ██         [OK] Password found! │
│                                                     │
│  [ INITIATE_BRUTEFORCE ]                            │
└─────────────────────────────────────────────────────┘
```

---

## 🚀 Quick Start

### Prerequisites
- Python 3.8 or higher
- Windows 10/11 (for WiFi scanning features)
- Administrator privileges (for network commands)

### Installation

```bash
# 1. Clone the repository
git clone https://github.com/nguyenthienminh01/Chore.git
cd Chore

# 2. Create virtual environment
python -m venv venv

# 3. Activate virtual environment
# Windows:
.\venv\Scripts\activate

# 4. Install dependencies
pip install -r requirements.txt

# 5. Run the application
python app.py
```

### Or use the batch files:
```bash
# First time setup
install.bat

# Run the app
run.bat
```

### Access the Web Interface
Open your browser and navigate to:
```
http://127.0.0.1:5000
```

---

## � Project Structure

```
WIFISEC/
├── app.py                 # Flask backend & API
├── requirements.txt       # Python dependencies
├── run.bat               # Quick start script
├── install.bat           # Installation script
├── templates/
│   ├── index.html        # Main Matrix UI
│   └── bruteforce.html   # Legacy bruteforce page
└── wordlists/
    ├── 00_wifi_passwords.txt    # WiFi-specific passwords
    ├── 10k_most_common.txt      # Top 10,000 passwords
    ├── common_passwords.txt     # Common passwords
    ├── generated_patterns.txt   # Pattern-based passwords
    ├── keyboard_patterns.txt    # Keyboard walk patterns
    ├── names_dates.txt          # Names & dates
    ├── numeric_passwords.txt    # Numeric patterns
    ├── phone_numbers_vn.txt     # Vietnamese phone numbers
    ├── rockyou_mini.txt         # RockYou breach subset
    ├── vietnamese_passwords.txt # Vietnamese words
    └── wpa_top4800.txt          # WPA-specific passwords
```

---

## 🔧 API Endpoints

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/` | GET | Main interface |
| `/api/scan` | GET | Scan nearby networks |
| `/api/wordlists` | GET | Get wordlist info |
| `/api/check` | POST | Check password strength |
| `/api/bruteforce/start` | POST | Start bruteforce attack |
| `/api/bruteforce/stop` | POST | Stop bruteforce attack |
| `/api/bruteforce/status` | GET | Get attack status |

---

## � How Bruteforce Works

1. **Target Selection** - Choose a WiFi network from detected list
2. **Disconnect** - Tool disconnects from current network
3. **Profile Deletion** - Removes saved credentials for target
4. **Dictionary Attack** - Tries each password from wordlists
5. **Connection Test** - Attempts to connect with each password
6. **Success Detection** - Identifies when correct password is found

### Attack Flow:
```
[SCAN] → [SELECT] → [DISCONNECT] → [DELETE PROFILE] → [TRY PASSWORDS] → [SUCCESS]
```

---

## 📊 Wordlists

| Wordlist | Count | Description |
|----------|-------|-------------|
| 10k_most_common | 10,000 | Most common passwords globally |
| generated_patterns | 4,292 | Algorithmically generated patterns |
| wpa_top4800 | 4,800 | WPA-specific common passwords |
| rockyou_mini | 200 | Famous breach subset |
| vietnamese_passwords | 100 | Vietnamese-specific |
| wifi_passwords | 137 | Router default passwords |

**Total: ~28,000+ unique passwords**

---

## ⚠️ Legal Disclaimer

```
╔═══════════════════════════════════════════════════════════════╗
║  THIS TOOL IS FOR EDUCATIONAL AND AUTHORIZED TESTING ONLY!   ║
║                                                               ║
║  • Only use on networks you OWN or have WRITTEN PERMISSION   ║
║  • Unauthorized access to networks is ILLEGAL                 ║
║  • The developer is NOT responsible for misuse               ║
║  • Always follow local laws and regulations                  ║
╚═══════════════════════════════════════════════════════════════╝
```

---

## �️ Security Tips

To protect your WiFi network:

1. **Use Strong Passwords** - Minimum 12 characters, mixed case, numbers, symbols
2. **Avoid Common Words** - Don't use dictionary words or patterns
3. **No Personal Info** - Avoid names, birthdays, phone numbers
4. **WPA3 if Available** - Use the latest security protocol
5. **Change Default Passwords** - Router defaults are public knowledge
6. **Regular Updates** - Keep router firmware updated
7. **Hide SSID** - Optional, but adds obscurity
8. **MAC Filtering** - Whitelist known devices

---

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## 📜 License

This project is for **educational purposes only**. Use responsibly and ethically.

---

## 👤 Author

**Nguyen Thien Minh**
- GitHub: [@nguyenthienminh01](https://github.com/nguyenthienminh01)

---

<div align="center">

**⚡ WIFISEC v3.0 | Matrix Edition ⚡**

*"There is no spoon."* - The Matrix

</div>

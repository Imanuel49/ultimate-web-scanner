# 📱 Panduan Install Scanner v5.2 di Termux (Android)

## 🚀 Quick Start

### Step 1: Install Termux
1. Download Termux dari **F-Droid** (BUKAN Google Play Store)
   - Link: https://f-droid.org/en/packages/com.termux/
   - Google Play version sudah deprecated!

2. Buka Termux setelah install

### Step 2: Setup Environment
```bash
# Update packages
pkg update && pkg upgrade -y

# Install Python dan dependencies
pkg install python git -y

# Install pip packages
pip install requests dnspython urllib3 colorama
```

### Step 3: Clone/Download Scanner
```bash
# Download ZIP dari GitHub (ganti URL sesuai repo Anda)
curl -L -o scanner.zip https://github.com/yourrepo/scanner/archive/main.zip

# Extract
unzip scanner.zip
cd scanner-main

# Atau clone via git
git clone https://github.com/yourrepo/scanner.git
cd scanner
```

### Step 4: Run Scanner!
```bash
# Basic scan
python scanner.py -t example.com

# Full scan verbose
python scanner.py -t https://target.com -v 2

# Recon only
python scanner.py -t target.com -m recon
```

## 🎯 Complete Installation Guide

### Detailed Step-by-Step

#### 1. Install Termux (5 menit)
```bash
# Setelah install Termux dari F-Droid, buka dan jalankan:
termux-setup-storage
# Ini akan meminta permission untuk akses storage
```

#### 2. System Update (10-15 menit)
```bash
# Update repositories
apt update && apt upgrade -y

# Install essential tools
pkg install python python-pip git wget curl unzip -y
```

#### 3. Install Python Dependencies (5 menit)
```bash
# Install required libraries
pip install --upgrade pip

pip install requests
pip install dnspython
pip install urllib3
pip install colorama

# Verify installation
python -c "import requests; import dns.resolver; print('✓ All modules OK')"
```

#### 4. Download Scanner (2 menit)
```bash
# Method 1: Via Git
cd ~
git clone https://github.com/yourrepo/scanner.git
cd scanner

# Method 2: Direct Download
cd ~
wget https://github.com/yourrepo/scanner/archive/main.zip
unzip main.zip
mv scanner-main scanner
cd scanner

# Method 3: Manual Upload
# - Copy ZIP file ke Download folder Android
# - Di Termux:
cp ~/storage/downloads/scanner_v5.2_ultimate.zip ~
unzip scanner_v5.2_ultimate.zip
cd scanner_v5.2
```

#### 5. First Run Test (1 menit)
```bash
# Test installation
python scanner.py --help

# Quick scan
python scanner.py -t example.com -m recon -v 1
```

## 🔧 Troubleshooting Termux

### Issue: "pkg: command not found"
```bash
# Install dari source
apt update
apt install apt -y
```

### Issue: "pip: command not found"
```bash
# Install pip
pkg install python-pip -y

# Atau manual:
curl https://bootstrap.pypa.io/get-pip.py -o get-pip.py
python get-pip.py
```

### Issue: "Module not found"
```bash
# Reinstall dependencies
pip install -r requirements.txt --force-reinstall

# Atau satu per satu:
pip install requests --force-reinstall
pip install dnspython --force-reinstall
```

### Issue: "Permission Denied"
```bash
# Fix permissions
chmod +x scanner.py
chmod +x modules/*.py

# Atau run dengan python explicitly
python scanner.py -t target.com
```

### Issue: "SSL Certificate Error"
```bash
# Update certificates
pkg install ca-certificates -y

# Atau disable SSL verification (sudah built-in di scanner)
```

## 📂 File Structure Termux
```
/data/data/com.termux/files/home/
├── scanner/                    # Scanner directory
│   ├── scanner.py             # Main script
│   ├── modules/
│   │   ├── recon_module.py
│   │   └── enum_module.py
│   ├── requirements.txt
│   └── README.md
├── storage/                   # Android storage access
│   ├── downloads/            # Downloads folder
│   ├── dcim/                 # Camera
│   └── shared/               # Shared storage
```

## 🎓 Usage Examples di Termux

### Basic Scans
```bash
# Simple recon
python scanner.py -t target.com -m recon

# Full scan
python scanner.py -t https://target.com

# Verbose mode
python scanner.py -t target.com -v 2
```

### Save Results
```bash
# Export to JSON
python scanner.py -t target.com -o ~/storage/downloads/report.json

# View results
cat ~/storage/downloads/report.json | python -m json.tool
```

### Multiple Targets
```bash
# Create target list
echo "target1.com" > targets.txt
echo "target2.com" >> targets.txt
echo "target3.com" >> targets.txt

# Scan all targets
while read target; do
    python scanner.py -t "$target" -o "report_$target.json"
done < targets.txt
```

### Background Scanning
```bash
# Install tmux for background sessions
pkg install tmux -y

# Create new session
tmux new -s scan1

# Run scan
python scanner.py -t target.com -v 2

# Detach: Ctrl+B then D
# Reattach: tmux attach -t scan1
```

## ⚡ Performance Tips Termux

### Optimize untuk Mobile
```bash
# Reduce threads untuk save battery
python scanner.py -t target.com -T 10

# Reduce timeout untuk faster scan
python scanner.py -t target.com --timeout 5

# Silent mode untuk save screen time
python scanner.py -t target.com -v 0
```

### Battery Saving Mode
```bash
# Install wake lock
termux-wake-lock

# Run scan
python scanner.py -t target.com

# Release wake lock setelah selesai
termux-wake-unlock
```

### Network Optimization
```bash
# Check connection
ping -c 4 8.8.8.8

# Use mobile data atau WiFi yang stabil
# Avoid scan saat signal lemah
```

## 🔐 Security di Termux

### Protect Your Scripts
```bash
# Set password untuk Termux
pkg install termux-auth -y

# Lock screen otomatis
# (via Termux settings)
```

### Safe Storage
```bash
# Encrypt sensitive data
pkg install gnupg -y

# Encrypt reports
gpg -c report.json
# Creates report.json.gpg

# Decrypt
gpg report.json.gpg
```

## 📱 Upload to GitHub dari Termux

### Setup Git
```bash
# Configure git
git config --global user.name "YourName"
git config --global user.email "your@email.com"

# Generate SSH key
pkg install openssh -y
ssh-keygen -t rsa -b 4096 -C "your@email.com"

# Copy public key
cat ~/.ssh/id_rsa.pub

# Add key ke GitHub Settings > SSH Keys
```

### Push Scanner ke GitHub
```bash
# Initialize repo
cd ~/scanner
git init
git add .
git commit -m "Initial commit - Scanner v5.2"

# Create repo di GitHub, lalu:
git remote add origin git@github.com:yourusername/scanner.git
git push -u origin main
```

## 🎯 Pro Tips Termux

### 1. Create Aliases
```bash
# Edit .bashrc
nano ~/.bashrc

# Add aliases
alias scan="python ~/scanner/scanner.py"
alias scanfull="python ~/scanner/scanner.py -v 2 -T 20"
alias scanrecon="python ~/scanner/scanner.py -m recon"

# Reload
source ~/.bashrc

# Usage
scan -t target.com
scanfull -t target.com
```

### 2. Auto-Update Script
```bash
# Create update script
cat > ~/scanner/update.sh << 'EOF'
#!/bin/bash
cd ~/scanner
git pull origin main
pip install -r requirements.txt --upgrade
echo "✓ Scanner updated!"
EOF

chmod +x ~/scanner/update.sh

# Run update
~/scanner/update.sh
```

### 3. Scheduled Scans (Cron)
```bash
# Install cronie
pkg install cronie -y

# Start cron
crond

# Edit crontab
crontab -e

# Add daily scan at 2 AM
0 2 * * * python ~/scanner/scanner.py -t target.com -o ~/reports/daily_$(date +\%Y\%m\%d).json
```

### 4. Notification on Completion
```bash
# Install termux-api
pkg install termux-api -y

# Scan dengan notifikasi
python scanner.py -t target.com && termux-notification -t "Scan Complete" -c "Target: target.com"
```

## 🆘 Getting Help

### Common Commands
```bash
# Check Python version
python --version

# List installed packages
pip list

# Check disk space
df -h

# Check memory
free -h

# Check process
ps aux | grep python
```

### Resources
- Termux Wiki: https://wiki.termux.com
- Termux GitHub: https://github.com/termux
- Bug Reports: termux/termux-app/issues

## ⚠️ Important Notes

1. **Battery Usage**: Long scans akan drain battery
   - Charge device atau use power bank
   - Enable battery saver setelah scan

2. **Data Usage**: Scanning pakai banyak data
   - Use WiFi kalau possible
   - Monitor data usage

3. **App Killing**: Android bisa kill Termux
   - Disable battery optimization untuk Termux
   - Settings > Apps > Termux > Battery > Unrestricted

4. **Storage**: Reports bisa besar
   - Regular cleanup old reports
   - Use external storage kalau perlu

---

**Happy Scanning from Termux! 📱🚀**

Remember: Always get proper authorization before testing any targets!

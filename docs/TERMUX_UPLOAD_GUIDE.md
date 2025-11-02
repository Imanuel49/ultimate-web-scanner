# 🚀 PANDUAN LENGKAP: Upload ke GitHub via Termux

## ✅ File ZIP Sudah Dibuat!

**File**: `web_scanner_v5.1_ultimate.zip` (121 KB)
**Isi**: 29 files (semua dokumentasi + scanners)

---

## 📱 LANGKAH-LANGKAH LENGKAP (TERMUX)

### ═══════════════════════════════════════════════════════════════
### STEP 1: DOWNLOAD FILE ZIP
### ═══════════════════════════════════════════════════════════════

**Download file ZIP ini:**
- File: `web_scanner_v5.1_ultimate.zip`
- Ukuran: 121 KB (sangat kecil!)
- Lokasi: Simpan di folder Downloads HP Anda

---

### ═══════════════════════════════════════════════════════════════
### STEP 2: INSTALL GIT DI TERMUX
### ═══════════════════════════════════════════════════════════════

Buka Termux, lalu jalankan:

```bash
# Update package list
pkg update && pkg upgrade -y

# Install git
pkg install git -y

# Verifikasi instalasi
git --version
```

**Output yang diharapkan:**
```
git version 2.x.x
```

---

### ═══════════════════════════════════════════════════════════════
### STEP 3: AKSES STORAGE HP
### ═══════════════════════════════════════════════════════════════

```bash
# Beri akses Termux ke storage HP
termux-setup-storage

# Tekan "Allow" saat diminta permission
```

**Tunggu beberapa detik**, folder `storage` akan muncul.

---

### ═══════════════════════════════════════════════════════════════
### STEP 4: EXTRACT FILE ZIP
### ═══════════════════════════════════════════════════════════════

```bash
# Install unzip (jika belum ada)
pkg install unzip -y

# Masuk ke folder downloads
cd ~/storage/downloads

# Cek apakah file ZIP ada
ls -lh web_scanner_v5.1_ultimate.zip

# Extract ZIP
unzip web_scanner_v5.1_ultimate.zip

# Masuk ke folder hasil extract
cd web_scanner_v5
```

**Verifikasi:**
```bash
# Cek isi folder
ls -la

# Seharusnya ada 29 files
```

---

### ═══════════════════════════════════════════════════════════════
### STEP 5: KONFIGURASI GIT (PERTAMA KALI)
### ═══════════════════════════════════════════════════════════════

```bash
# Set nama Anda (ganti dengan nama Anda)
git config --global user.name "Nama Anda"

# Set email GitHub Anda (ganti dengan email Anda)
git config --global user.email "email@github.com"

# Verifikasi konfigurasi
git config --list
```

**Pastikan output menampilkan nama dan email Anda.**

---

### ═══════════════════════════════════════════════════════════════
### STEP 6: BUAT REPOSITORY DI GITHUB (VIA BROWSER)
### ═══════════════════════════════════════════════════════════════

**Di browser HP/PC:**

1. Buka: https://github.com
2. Login ke akun GitHub Anda
3. Klik tombol **[+]** di pojok kanan atas
4. Pilih **"New repository"**
5. Isi form:
   ```
   Repository name: ultimate-web-scanner
   Description: Professional Web Vulnerability Scanner v5.1 - Expert Pentest Edition
   Public/Private: Pilih sesuai kebutuhan
   ```
6. ❌ **JANGAN** centang "Initialize this repository with a README"
7. Klik **"Create repository"**

**Simpan URL repository:**
```
https://github.com/USERNAME/ultimate-web-scanner
```
(Ganti USERNAME dengan username GitHub Anda)

---

### ═══════════════════════════════════════════════════════════════
### STEP 7: BUAT PERSONAL ACCESS TOKEN (PENTING!)
### ═══════════════════════════════════════════════════════════════

GitHub **TIDAK MENERIMA PASSWORD BIASA** lagi!
Anda harus pakai **Personal Access Token**.

**Di browser HP/PC:**

1. Di GitHub, klik foto profil → **Settings**
2. Scroll ke bawah → **Developer settings**
3. **Personal access tokens** → **Tokens (classic)**
4. Klik **"Generate new token"** → **"Generate new token (classic)"**
5. Isi form:
   ```
   Note: Termux Upload
   Expiration: 90 days (atau sesuai kebutuhan)
   Scopes: ✅ CENTANG "repo" (semua opsi di bawahnya)
   ```
6. Klik **"Generate token"**
7. **📋 COPY TOKEN INI!** (format: `ghp_xxxxxxxxxxxx`)

⚠️ **PENTING**: Token hanya muncul sekali! Simpan di notes.

**Token terlihat seperti:**
```
ghp_1A2b3C4d5E6f7G8h9I0j1K2l3M4n5O6p7Q8r
```

---

### ═══════════════════════════════════════════════════════════════
### STEP 8: INISIALISASI GIT & UPLOAD
### ═══════════════════════════════════════════════════════════════

Kembali ke Termux:

```bash
# Pastikan masih di folder web_scanner_v5
pwd
# Output seharusnya: .../storage/downloads/web_scanner_v5

# 1. Inisialisasi git repository
git init

# 2. Tambahkan semua file
git add .

# 3. Buat commit pertama
git commit -m "Initial commit - Ultimate Web Vulnerability Scanner v5.1 Expert Pentest Edition"

# 4. Tambahkan remote repository (GANTI USERNAME!)
git remote add origin https://github.com/USERNAME/ultimate-web-scanner.git

# 5. Rename branch ke main
git branch -M main

# 6. Push ke GitHub
git push -u origin main
```

**Saat diminta credentials:**
```
Username for 'https://github.com': your-username
Password for 'https://your-username@github.com': 
```

⚠️ **PENTING**: 
- **Username** = Username GitHub Anda
- **Password** = **PASTE TOKEN** (ghp_xxxx...), BUKAN password GitHub!

---

### ═══════════════════════════════════════════════════════════════
### STEP 9: VERIFIKASI UPLOAD BERHASIL
### ═══════════════════════════════════════════════════════════════

**Di Termux, Anda akan melihat:**
```
Enumerating objects: 29, done.
Counting objects: 100% (29/29), done.
...
Writing objects: 100% (29/29), 121 KB | 1.5 MB/s, done.
Total 29 (delta 5), reused 0 (delta 0)
To https://github.com/USERNAME/ultimate-web-scanner.git
 * [new branch]      main -> main
Branch 'main' set up to track remote branch 'main' from 'origin'.
```

**Buka browser:**
```
https://github.com/USERNAME/ultimate-web-scanner
```

✅ Semua file seharusnya sudah ter-upload!

---

## 🎉 SELESAI! Repository Online!

Link repository Anda:
```
https://github.com/USERNAME/ultimate-web-scanner
```

---

## 🔄 UPDATE REPOSITORY (Setelah Ada Perubahan)

Jika Anda mengubah file di kemudian hari:

```bash
# Masuk ke folder project
cd ~/storage/downloads/web_scanner_v5

# Cek status
git status

# Tambahkan file yang diubah
git add .

# Commit dengan pesan
git commit -m "Update: deskripsi perubahan Anda"

# Push ke GitHub
git push
```

**Input credentials (sekali lagi):**
- Username: your-username
- Password: TOKEN (ghp_xxxx...)

---

## ❌ TROUBLESHOOTING

### Problem 1: "Permission denied"
```
Error: Permission denied (publickey).
```

**Solusi:**
- Pastikan menggunakan HTTPS (bukan SSH)
- URL harus: `https://github.com/USERNAME/REPO.git`

### Problem 2: "Authentication failed"
```
Error: Authentication failed
```

**Solusi:**
- Pastikan token benar
- Token harus punya scope "repo"
- Gunakan TOKEN sebagai password, BUKAN password GitHub

### Problem 3: "Repository not found"
```
Error: repository 'https://github.com/USERNAME/REPO.git' not found
```

**Solusi:**
- Pastikan repository sudah dibuat di GitHub
- Cek spelling username dan nama repository
- Pastikan Anda login dengan akun yang benar

### Problem 4: "fatal: remote origin already exists"
```
Error: fatal: remote origin already exists.
```

**Solusi:**
```bash
# Hapus remote yang ada
git remote remove origin

# Tambahkan lagi dengan benar
git remote add origin https://github.com/USERNAME/REPO.git
```

### Problem 5: Lupa Token
**Solusi:**
- Buat token baru di GitHub Settings → Developer settings
- Token lama otomatis expired, jadi buat baru

---

## 📝 CHECKLIST LENGKAP

Sebelum mulai, pastikan:

- [ ] File ZIP sudah di-download (121 KB)
- [ ] Git sudah terinstall di Termux
- [ ] Termux punya akses ke storage HP
- [ ] Repository sudah dibuat di GitHub
- [ ] Personal Access Token sudah dibuat & di-copy
- [ ] Token punya scope "repo"

Saat upload:

- [ ] File ZIP sudah di-extract
- [ ] Git sudah dikonfigurasi (name & email)
- [ ] Remote URL sudah benar
- [ ] Menggunakan TOKEN sebagai password
- [ ] Upload berhasil (cek di browser)

---

## 💡 TIPS PENTING

### 1. Simpan Token
Simpan token di tempat aman:
- Notes HP
- Password manager
- File text terenkripsi

### 2. Gunakan HTTPS (Bukan SSH)
HTTPS lebih mudah untuk pemula:
```bash
# ✅ BENAR
https://github.com/USERNAME/REPO.git

# ❌ SALAH (SSH - butuh setup tambahan)
git@github.com:USERNAME/REPO.git
```

### 3. Periksa Remote URL
```bash
# Cek remote URL
git remote -v

# Output seharusnya:
# origin  https://github.com/USERNAME/REPO.git (fetch)
# origin  https://github.com/USERNAME/REPO.git (push)
```

### 4. Buat .gitignore
Hindari upload file tidak perlu:

```bash
cat > .gitignore << 'EOF'
# Python
__pycache__/
*.pyc
*.pyo

# Reports
*.json
*.pdf
reports/
scans/

# Temporary
*.tmp
*.log
EOF

git add .gitignore
git commit -m "Add .gitignore"
git push
```

---

## 🎯 QUICK REFERENCE

### Commands Penting:
```bash
# Status
git status

# Add files
git add .

# Commit
git commit -m "message"

# Push
git push

# Pull (download changes)
git pull

# Check remote
git remote -v

# View logs
git log --oneline
```

### URLs Penting:
- GitHub: https://github.com
- Settings: https://github.com/settings
- Tokens: https://github.com/settings/tokens

---

## 📞 BUTUH BANTUAN?

### Dokumentasi:
- **QUICK_GITHUB_SETUP.txt** - Visual guide
- **UPLOAD_GITHUB_ID.md** - Panduan lengkap Indonesia
- **GITHUB_UPLOAD_GUIDE.md** - Complete English guide

### Support:
- GitHub Docs: https://docs.github.com
- Git Cheat Sheet: https://training.github.com

---

## 🎊 SELAMAT!

Repository Anda sekarang online dan bisa diakses di:
```
https://github.com/USERNAME/ultimate-web-scanner
```

Anda bisa:
✅ Share link ke teman
✅ Clone ke device lain
✅ Tambahkan ke CV/portfolio
✅ Kontribusi ke project lain

---

**Happy Coding! 🚀**

Made with ❤️ for Indonesian Cybersecurity Community

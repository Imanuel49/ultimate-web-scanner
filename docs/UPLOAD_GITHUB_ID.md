# 📤 Cara Upload ke GitHub (Termux) - Bahasa Indonesia

## 🚀 Cara Tercepat (Otomatis)

### 1. Jalankan Script Otomatis
```bash
cd /mnt/user-data/outputs/web_scanner_v5

# Beri izin eksekusi
chmod +x upload_to_github.sh

# Jalankan
bash upload_to_github.sh
```

Script akan memandu Anda step-by-step! ✨

---

## 📝 Cara Manual (Lengkap)

### Langkah 1: Install Git
```bash
pkg update && pkg upgrade -y
pkg install git -y
git --version
```

### Langkah 2: Konfigurasi Git
```bash
git config --global user.name "Nama Anda"
git config --global user.email "email@github.com"
```

### Langkah 3: Buat Repository di GitHub
1. Buka https://github.com di browser HP/PC
2. Klik tombol **"+"** → **"New repository"**
3. Isi:
   - **Repository name**: `ultimate-web-scanner`
   - **Description**: `Professional Web Security Scanner v5.1`
   - Pilih **Public** atau **Private**
   - ❌ JANGAN centang "Initialize with README"
4. Klik **"Create repository"**

### Langkah 4: Buat Personal Access Token
1. Di GitHub → Klik foto profil → **Settings**
2. Scroll bawah → **Developer settings**
3. **Personal access tokens** → **Tokens (classic)**
4. **"Generate new token"** → **"Generate new token (classic)"**
5. Isi:
   - **Note**: "Termux Upload"
   - **Expiration**: 90 days
   - **Scopes**: ✅ Centang **repo** (semua)
6. Klik **"Generate token"**
7. **COPY TOKEN!** (tidak muncul lagi)

### Langkah 5: Upload dari Termux
```bash
# Masuk ke folder project
cd /mnt/user-data/outputs/web_scanner_v5

# Atau copy dulu ke home
cp -r /mnt/user-data/outputs/web_scanner_v5 ~/web-scanner
cd ~/web-scanner

# Init git
git init

# Tambahkan semua file
git add .

# Commit
git commit -m "Initial commit - Ultimate Scanner v5.1"

# Tambahkan remote (GANTI sesuai username dan repo Anda!)
git remote add origin https://github.com/USERNAME/REPO_NAME.git

# Push ke GitHub
git branch -M main
git push -u origin main

# Masukkan:
# Username: username-github-anda
# Password: TOKEN yang tadi di-copy (BUKAN password biasa!)
```

---

## 🔑 Penting: Personal Access Token

**JANGAN pakai password biasa!** GitHub sekarang wajib pakai token.

Saat diminta password:
```
Username for 'https://github.com': username-anda
Password for 'https://username-anda@github.com': ghp_xxxxxxxxxxxx
                                                  ↑
                                          Paste token di sini
```

---

## ✅ Verifikasi

Setelah upload berhasil:
1. Buka https://github.com/USERNAME/REPO_NAME
2. Cek semua file sudah ada
3. ✓ Selesai!

---

## 🔄 Update Repository (Setelah Ada Perubahan)

```bash
cd ~/web-scanner

# Lihat status
git status

# Tambahkan file yang diubah
git add .

# Commit dengan pesan
git commit -m "Update: deskripsi perubahan"

# Push
git push
```

---

## ❌ Troubleshooting

### Error: "Permission denied"
**Solusi**: Pastikan token benar dan punya akses **repo**.

### Error: "Repository not found"
**Solusi**: 
- Pastikan repository sudah dibuat di GitHub
- Pastikan nama repository dan username benar

### Error: "fatal: remote origin already exists"
**Solusi**:
```bash
git remote remove origin
git remote add origin https://github.com/USERNAME/REPO_NAME.git
```

### Lupa Token
**Solusi**: Buat token baru di GitHub Settings → Developer settings.

---

## 📱 Tips untuk Termux

### 1. Akses Storage HP
```bash
termux-setup-storage
```

### 2. Copy dari Downloads
```bash
cp -r ~/storage/downloads/web_scanner_v5 ~/web-scanner
```

### 3. Edit File di Termux
```bash
# Install nano (editor)
pkg install nano -y

# Edit file
nano README.md
```

---

## 🎯 Checklist Upload

- [ ] Git sudah terinstall
- [ ] Git sudah dikonfigurasi (name & email)
- [ ] Repository sudah dibuat di GitHub
- [ ] Personal Access Token sudah dibuat
- [ ] Token sudah di-copy
- [ ] File project sudah siap
- [ ] Upload berhasil
- [ ] Verifikasi di GitHub

---

## 📞 Butuh Bantuan?

Baca panduan lengkap: **GITHUB_UPLOAD_GUIDE.md**

Atau jalankan script otomatis: `bash upload_to_github.sh`

---

## 🎉 Selamat!

Repository Anda sekarang online di GitHub! 🚀

Share link: `https://github.com/USERNAME/REPO_NAME`

---

**Made with ❤️ for Indonesian Cybersecurity Community**

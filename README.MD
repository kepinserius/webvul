# Scanner Vulnerability Web

Scanner Vulnerability Web adalah alat yang dikembangkan dengan Rust untuk mendeteksi berbagai kerentanan keamanan pada website. Alat ini dirancang untuk membantu pengembang dan penguji keamanan dalam mengidentifikasi potensi masalah keamanan pada aplikasi web.

## Fitur

Scanner ini dapat mendeteksi berbagai jenis kerentanan, termasuk:

- **Header HTTP yang Tidak Aman** - Memeriksa konfigurasi header keamanan seperti Content-Security-Policy, X-XSS-Protection, dll.
- **SQL Injection** - Mendeteksi kerentanan SQL injection dengan berbagai payload dan analisis respons.
- **Cross-Site Scripting (XSS)** - Menguji kerentanan XSS dengan berbagai teknik injeksi.
- **Command Injection** - Mendeteksi kemungkinan eksekusi perintah sistem melalui parameter input.
- **Directory Traversal** - Menguji akses tidak sah ke file sistem melalui manipulasi path.
- **Konfigurasi HTTPS** - Memeriksa penggunaan HTTPS untuk komunikasi aman.
- **Deteksi Form dan Input** - Menemukan form dan input field untuk pengujian otomatis.

## Persyaratan

- Rust (versi 1.50.0 atau lebih baru)
- Cargo (package manager Rust)
- Koneksi internet untuk mengunduh dependensi

## Instalasi

1. Clone repositori ini:

   ```
   git clone https://github.com/username/webvul.git
   cd webvul
   ```

2. Build proyek:

   ```
   cargo build --release
   ```

3. Jalankan scanner:

   ```
   cargo run --release
   ```

   Atau gunakan executable langsung:

   ```
   ./target/release/webvul
   ```

## Penggunaan

1. Jalankan aplikasi
2. Masukkan URL target yang ingin di-scan (contoh: https://example.com)
3. Scanner akan melakukan pemindaian dan menampilkan hasil dengan indikator visual:
   - ✅ Tidak ditemukan kerentanan
   - ⚠️ Potensi kerentanan atau konfigurasi yang kurang optimal
   - ❌ Kerentanan terdeteksi

## Contoh Output

```
=== SCANNER VULNERABILITY WEB ===
Lebokne URL COK (contoh: https://example.com):
https://example.com

🔍 Memulai pemindaian kerentanan untuk: https://example.com

[1/8] Mengecek aksesibilitas URL...
✅ URL dapat diakses dengan status: 200 OK
📌 Domain: example.com

[2/8] Memeriksa header HTTP...
⚠️ Header Content-Security-Policy hilang - Mencegah XSS dan injeksi data
✅ Header X-Content-Type-Options ditemukan: "nosniff"
...

[3/8] Memeriksa konfigurasi dasar keamanan...
✅ HTTPS digunakan.
...
```

## Peringatan Hukum

**PENTING**: Alat ini hanya boleh digunakan untuk menguji keamanan website yang Anda miliki atau memiliki izin tertulis untuk mengujinya. Penggunaan alat ini pada website tanpa izin dapat melanggar hukum dan dapat dikenakan sanksi hukum.

## Keterbatasan

- Scanner ini melakukan pengujian dasar dan mungkin tidak mendeteksi semua kerentanan.
- Beberapa pengujian mungkin menghasilkan false positive atau false negative.
- Pengujian dilakukan secara pasif dan tidak mencoba mengeksploitasi kerentanan yang ditemukan.

## Lisensi

[MIT License](LICENSE)

## Kontribusi

Kontribusi sangat diterima! Silakan buat pull request atau laporkan masalah melalui issue tracker.

## Pengembang

Dikembangkan oleh KFIEN

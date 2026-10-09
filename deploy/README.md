# Deploy SecVal ke VPS (HTTPS via nginx + Let's Encrypt)

Panduan ini dijalanin **di VPS IDCloud** (Ubuntu/Debian), bukan di laptop.
Domain `secval.my.id` sudah diarahkan (A record) ke IP publik VPS.

Arsitektur:

```
Internet --> nginx :443 (SSL) --+-- /      --> /var/www/secval (frontend static)
          secval.my.id          +-- /api/  --> 127.0.0.1:8000 (backend Docker)
```

Backend tetap jalan di Docker tapi cuma listen di `127.0.0.1:8000`, jadi ga bisa
diakses langsung dari internet. Semua lewat nginx (port 443).

---

## 0. Prasyarat

- VPS Ubuntu/Debian, punya akses sudo.
- Docker + docker compose udah keinstall di VPS.
- Repo ini udah di-clone/copy ke VPS, misal di `~/SecVal`.
- File `.env` (berisi token Telegram & IPInfo) ada di root repo di VPS.
  JANGAN commit file ini — udah masuk `.gitignore`.
- `dig secval.my.id +short` ngasih IP publik VPS lo.

---

## 1. Buka firewall (port 80 & 443)

```bash
sudo ufw allow 80,443/tcp
sudo ufw reload   # kalau ufw aktif
```

PENTING:
- Buka juga 80 & 443 di panel/security-group IDCloud kalau ada.
- JANGAN buka port 3000 & 8000 ke publik — biar ga ada yang bypass SSL
  lewat `http://IP:3000`. (compose prod udah bind 8000 ke localhost.)

---

## 2. Install nginx + certbot

```bash
sudo apt update
sudo apt install -y nginx certbot python3-certbot-nginx
```

---

## 3. Pasang config nginx

```bash
sudo cp deploy/nginx/secval.conf /etc/nginx/sites-available/secval
sudo ln -sf /etc/nginx/sites-available/secval /etc/nginx/sites-enabled/secval
sudo rm -f /etc/nginx/sites-enabled/default   # buang default page
```

---

## 4. Build frontend + up backend

```bash
bash deploy/deploy.sh
```

Script ini: build frontend -> copy ke `/var/www/secval`, up backend
(`docker-compose.prod.yml`), lalu reload nginx.

---

## 5. Tes HTTP dulu (sebelum SSL)

```bash
curl -I http://secval.my.id
```

Harus balik `200 OK` dan frontend muncul kalau dibuka di browser
(`http://secval.my.id`). Kalau belum muncul, beresin dulu sebelum lanjut SSL.

---

## 6. Pasang SSL (Let's Encrypt)

```bash
sudo certbot --nginx -d secval.my.id
```

- Isi email, setuju TOS.
- Pas ditanya redirect, pilih **Redirect** (opsi 2) biar `http` otomatis
  dialihin ke `https`.

certbot bakal otomatis nambahin block `listen 443 ssl` + path sertifikat
ke `/etc/nginx/sites-available/secval` dan reload nginx.

Cek auto-renew:

```bash
sudo certbot renew --dry-run
```

---

## 7. Verifikasi

```bash
curl -I https://secval.my.id            # 200, pakai TLS
curl    https://secval.my.id/api/health # respons backend
```

Buka `https://secval.my.id` di browser -> harus ada gembok (secure),
dan `http://` auto-redirect ke `https://`.

---

## Update aplikasi (deploy ulang)

Setelah pull perubahan baru di VPS:

```bash
git pull
bash deploy/deploy.sh
```

SSL ga perlu diulang — sertifikat & config 443 tetap kepasang.

---

## Troubleshooting

- **502 Bad Gateway di /api/** -> backend ga jalan. Cek:
  `docker compose -f docker-compose.prod.yml ps` dan `... logs secval`.
- **Frontend blank / 404 pas refresh route** -> pastikan block `try_files`
  di nginx ada (udah ada di `secval.conf`).
- **certbot gagal** -> pastikan port 80 kebuka dari internet & A record
  bener-bener nunjuk ke IP VPS ini (`dig secval.my.id +short`).
- **Mixed content (http di dalam https)** -> frontend manggil API pakai path
  relatif `/api`, jadi harusnya aman. Jangan hardcode `http://...:8000`.

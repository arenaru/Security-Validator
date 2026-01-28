#!/bin/bash

# Konfigurasi Input
INPUT_FILE="${1:-list.txt}"

# Cek File
if [[ ! -f "$INPUT_FILE" ]]; then
    echo "ERROR|File Tidak Ditemukan|$INPUT_FILE"
    exit 1
fi

check_insecure_cookie() {
  # Clean newline characters dari input
  raw_domain=$(echo "$1" | tr -d '\r\n')
  domain=$(echo "$raw_domain" | sed -E 's~^https?://~~; s~/$~~')
  
  # Target URL
  target_url="https://$domain"

  # Eksekusi CURL (Timeout 3s connect, 5s max)
  # Kita ambil Header saja (-I atau -D)
  response_headers=$(curl -s -k -L -D - -o /dev/null -A "Mozilla/5.0" --connect-timeout 3 --max-time 5 "$target_url" 2>/dev/null)
  curl_status=$?

  # 1. Cek Koneksi
  if [ $curl_status -ne 0 ]; then
    echo "$target_url|ERROR|Connection Timeout/Refused"
    return
  fi

  # 2. Ambil Cookie
  cookies=$(echo "$response_headers" | grep -i "Set-Cookie:")

  if [ -z "$cookies" ]; then
    echo "$target_url|INFO|No Cookies Found"
  else
    # 3. Cek Insecure (Cari yang TIDAK ada kata 'secure')
    insecure=$(echo "$cookies" | grep -vi "secure")

    if [ -n "$insecure" ]; then
      # Ada cookie yang tidak secure -> VULNERABLE
      # Kita kirim output bersih tanpa warna biar CSV aman
      echo "$target_url|VULNERABLE|Cookie Without Secure Flag"
    else
      # Semua cookie aman
      echo "$target_url|SAFE|All Cookies are Secure"
    fi
  fi
}

# Loop baca file
while IFS= read -r target || [[ -n "$target" ]]; do
  [[ -z "$target" || "$target" =~ ^# ]] && continue
  target=$(echo "$target" | xargs)
  check_insecure_cookie "$target"
done < "$INPUT_FILE"
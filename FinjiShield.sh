#!/usr/bin/env bash
set -euo pipefail

## Author
## Koji Xenpai
## GitHub : https://github.com/alfarozy

# === CONFIG - sesuaikan ini ===
URL="https://raw.githubusercontent.com/rahulalam31/Laravel-Abuse-IP/refs/heads/main/abuseip.json"
JSON_FILE="/tmp/abuseip.json"
CHAIN="BLOCKLIST"
NGINX_LOG="/var/log/nginx/access.log"
ADMIN_IP="YOUR_ADMIN_IP_HERE"        # isi dengan IP admin/jump host agar tidak ke-block
LAST_BLOCKED_FILE="/tmp/last_blocked.txt"
TMP_SENSITIVE="/tmp/sensitive_hits.txt"

# Auto-block thresholds (ubah sesuai kebutuhan)
THRESH_404=20            # jika >= THRESH_404 404 dalam window waktu -> auto block
THRESH_SENSITIVE=5      # jika >= THRESH_SENSITIVE hits ke path sensitif -> auto block
THRESH_BRUTE=1500        # jika >= THRESH_BRUTE hit dalam 10 menit -> auto block

# Helper: cek RFC1918 / loopback & skip
is_protected_ip() {
  local ip="$1"
  [[ -n "$ADMIN_IP" && "$ip" == "$ADMIN_IP" ]] && return 0
  [[ "$ip" == "127.0.0.1" || "$ip" == "::1" ]] && return 0
  if [[ "$ip" =~ ^10\. ]] || [[ "$ip" =~ ^192\.168\. ]] || [[ "$ip" =~ ^172\.1[6-9]\. ]] || [[ "$ip" =~ ^172\.2[0-9]\. ]] || [[ "$ip" =~ ^172\.3[0-1]\. ]]; then
    return 0
  fi
  return 1
}

# === Daftar path sensitif (lengkap) ===
SENSITIVE_PATTERNS=(
  "wp-login.php"
  "xmlrpc.php"
  "wp-admin"
  "administrator"
  "admin.php"
  "phpmyadmin"
  "pma"
  "sql.php"
  "dbadmin"
  "config.php"
  "setup.php"
  "install.php"
  "wp-content/plugins"
  "wp-content/themes"
  "wp-includes"
  "manager/html"
  "shell.php"
  "wp-json/wp/v2"
  ".env"
  "wp-config.php"
  "login.php"
  "user/login"
  "admin/login"
  "webdav"
  "solr"
  "adminer.php"
  "phpunit"
  "vendor/phpunit"
  "CMSPages"
  "cgi-bin"
  "backup.zip"
  "backup.tar"
  "backup.sql"
  "git/HEAD"
  ".git"
  "wp-login"
  "boaform"
  "boaform/admin"
  "hudson"
  "jenkins"
  "console"
  "remote/login"
  "autodiscover/autodiscover.xml"
  "owa/auth/logon.aspx"
  "Solr/admin"
  "ManageServer"
  "eval("
)

# === Functions ===

init_chain() {
  if ! iptables -L "$CHAIN" -n >/dev/null 2>&1; then
    iptables -N "$CHAIN"
  fi
  if ! iptables -C INPUT -j "$CHAIN" >/dev/null 2>&1; then
    iptables -I INPUT -j "$CHAIN"
  fi
}

flush_chain() {
  echo "Menghapus semua IP di $CHAIN ..."
  iptables -F "$CHAIN" || true
  echo "" > "$LAST_BLOCKED_FILE"
  echo "Selesai, semua IP sudah dibuka."
}

fetch_json() {
  echo "Mengunduh JSON dari $URL ..."
  if ! curl -fsS "$URL" -o "$JSON_FILE"; then
    echo "Gagal mengunduh $URL"
    return 1
  fi
  if ! jq empty "$JSON_FILE" >/dev/null 2>&1; then
    echo "JSON tidak valid di $JSON_FILE"
    return 1
  fi
  return 0
}

sync_blocklist() {
  init_chain
  fetch_json || return 1
  echo "=== Sinkronisasi blocklist ==="

  # Simpan IP lama (perbaikan awk)
  iptables -S "$CHAIN" | awk '/-s/ {for(i=1;i<=NF;i++){if($i=="-s"){print $(i+1)}}}' > "${LAST_BLOCKED_FILE}.old" || true
  NEW_IPS=$(jq -r '.[]' "$JSON_FILE")

  # Hapus IP lama yang tidak ada di JSON
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    if ! grep -Fxq "$ip" <<< "$NEW_IPS"; then
      if is_protected_ip "$ip"; then
        echo "Lewati hapus protected IP: $ip"
        continue
      fi
      echo "Menghapus IP lama: $ip"
      iptables -D "$CHAIN" -s "$ip" -j DROP || true
    fi
  done < <(iptables -S "$CHAIN" | awk '/-s/ {for(i=1;i<=NF;i++){if($i=="-s"){print $(i+1)}}}')

  # Tambahkan IP baru
  for ip in $NEW_IPS; do
    [[ -z "$ip" ]] && continue
    if is_protected_ip "$ip"; then
      echo "Lewati admin/private IP: $ip"
      continue
    fi
    if ! iptables -C "$CHAIN" -s "$ip" -j DROP >/dev/null 2>&1; then
      iptables -A "$CHAIN" -s "$ip" -j DROP
      echo "Block baru ditambahkan: $ip"
    fi
  done

  # Simpan semua IP yang diblok
  iptables -S "$CHAIN" | awk '/-s/ {for(i=1;i<=NF;i++){if($i=="-s"){print $(i+1)}}}' > "$LAST_BLOCKED_FILE"
  echo "=== Selesai sinkronisasi ==="
}


list_blocked_ips() {
  echo "=== Semua IP di block (dipisah koma) ==="
  # ambil semua IP DROP, buang 0.0.0.0/0, urutkan unik
  ips=$(sudo iptables -L -n -v | grep DROP | awk '{print $8}' | grep -v '^0\.0\.0\.0/0$' | sort -u)
  # dipisahkan koma
  if [[ -n "$ips" ]]; then
    echo "$ips" | paste -sd, -
  else
    echo "Tidak ada IP spesifik yang diblokir"
  fi
  echo ""
  echo "======================================"
}



show_nginx_hits() {
  echo "=== IP yang diblock & muncul di log Nginx ==="
  while IFS= read -r ip; do
    [[ -z "$ip" ]] && continue
    hits=$(grep -c "$ip" "$NGINX_LOG" || true)
    if [[ "$hits" -gt 0 ]]; then
      echo "$ip → $hits hits"
    fi
  done < <(iptables -S "$CHAIN" | awk '/-s/ {print $3}')
  echo "============================================"
}

show_newly_blocked() {
  echo "=== IP baru yang diblock (sejak update terakhir) ==="
  if [[ ! -f "${LAST_BLOCKED_FILE}.old" || ! -f "$LAST_BLOCKED_FILE" ]]; then
    echo "Tidak ada data perbandingan (jalankan sync dulu)."
    return
  fi
  comm -13 <(sort "${LAST_BLOCKED_FILE}.old") <(sort "$LAST_BLOCKED_FILE") || true
  echo "===================================================="
}

detect_sensitive_hits() {
  tail -n 200000 "$NGINX_LOG" > /tmp/nginx_recent.log || true
  local pattern=""
  for p in "${SENSITIVE_PATTERNS[@]}"; do
    [[ -z "$pattern" ]] && pattern="$p" || pattern="$pattern|$p"
  done
  awk -v pat="$pattern" 'BEGIN{IGNORECASE=1} {print $0}' /tmp/nginx_recent.log | egrep -i "$pattern" > "$TMP_SENSITIVE" || true
  echo "Top IPs for sensitive pattern hits:"
  awk '{print $1}' "$TMP_SENSITIVE" | sort | uniq -c | sort -nr | head -20
  echo ""
  echo "Top IPs for 404 responses:"
  awk '$9 ~ /404/ {print $1}' /tmp/nginx_recent.log | sort | uniq -c | sort -nr | head -20
}

auto_block_from_detection() {
  echo "=== Auto-block berdasarkan deteksi ==="

  # Pastikan chain BLOCKLIST sudah ada
  init_chain

  # Deteksi sensitive hits
  detect_sensitive_hits

  echo "--- Auto-block sensitive hits ---"
  # Hitung total hits per IP
  while IFS= read -r line; do
    cnt=$(awk '{print $1}' <<< "$line")
    ip=$(awk '{print $2}' <<< "$line")
    [[ -z "$ip" ]] && continue

    if (( cnt >= THRESH_SENSITIVE )); then
      if is_protected_ip "$ip"; then
        echo "Lewati auto-block protected IP: $ip"
        continue
      fi
      if ! iptables -C "$CHAIN" -s "$ip" -j DROP >/dev/null 2>&1; then
        iptables -A "$CHAIN" -s "$ip" -j DROP
        echo "Auto-block (sensitive) ditambahkan: $ip (count=$cnt)"
      fi
    fi
  done < <(awk '{print $1}' "$TMP_SENSITIVE" | sort | uniq -c | sort -nr)

  echo "--- Auto-block 404 hits ---"
  # Hitung total 404 hits per IP
  while IFS= read -r line; do
    cnt=$(awk '{print $1}' <<< "$line")
    ip=$(awk '{print $2}' <<< "$line")
    [[ -z "$ip" ]] && continue

    if (( cnt >= THRESH_404 )); then
      if is_protected_ip "$ip"; then
        echo "Lewati auto-block protected IP: $ip"
        continue
      fi
      if ! iptables -C "$CHAIN" -s "$ip" -j DROP >/dev/null 2>&1; then
        iptables -A "$CHAIN" -s "$ip" -j DROP
        echo "Auto-block (404) ditambahkan: $ip (count=$cnt)"
      fi
    fi
  done < <(awk '$9 ~ /404/ {print $1}' /tmp/nginx_recent.log | sort | uniq -c | sort -nr)

  # Simpan daftar IP terakhir yang diblock
  iptables -S "$CHAIN" | awk '/-s/ {print $3}' > "$LAST_BLOCKED_FILE"

  echo "=== Selesai auto-block ==="
}


detect_bruteforce() {
  echo "=== Deteksi brute force dalam 10 menit terakhir ==="
  cutoff=$(date -d "10 minutes ago" +"%d/%b/%Y:%H:%M")
  awk -v cutoff="$cutoff" '$4 > "["cutoff {print $1}' "$NGINX_LOG" \
    | sort | uniq -c | sort -nr | while read -r cnt ip; do
      echo "$ip → $cnt hits"
      if (( cnt >= THRESH_BRUTE )); then
        if ! is_protected_ip "$ip"; then
          if ! iptables -C "$CHAIN" -s "$ip" -j DROP >/dev/null 2>&1; then
            iptables -A "$CHAIN" -s "$ip" -j DROP
            echo "Auto-block (bruteforce) ditambahkan: $ip (count=$cnt)"
          fi
        fi
      fi
    done
  echo "=== Selesai deteksi brute force ==="
}

manual_block() {
  read -rp "Masukkan IP yang ingin diblock: " ip
  if [[ -z "$ip" ]]; then
    echo "IP kosong, dibatalkan."
    return
  fi
  if is_protected_ip "$ip"; then
    echo "IP $ip dilindungi, tidak diblock."
    return
  fi
  if ! iptables -C "$CHAIN" -s "$ip" -j DROP >/dev/null 2>&1; then
    iptables -A "$CHAIN" -s "$ip" -j DROP
    echo "IP $ip berhasil diblock manual."
  else
    echo "IP $ip sudah ada di blocklist."
  fi
}

show_logs_for_ip() {
  read -rp "Masukkan IP yang ingin dilihat lognya: " ip
  if [[ -z "$ip" ]]; then
    echo "IP kosong, dibatalkan."
    return
  fi
  echo "=== Log Nginx untuk IP: $ip ==="
  grep "$ip" "$NGINX_LOG" || echo "Tidak ada log untuk IP ini."
  echo "================================"
}

run_menu_option() {
  local func="$1"
  $func
  while true; do
    read -rp "Kembali ke menu? [y/n]: " yn
    case "$yn" in
      [Yy]*) return 0 ;;  # kembali ke menu utama
      [Nn]*) echo "Keluar..."; exit 0 ;;
      *) echo "Silakan pilih y atau n." ;;
    esac
  done
}


print_menu() {
  cat <<EOF

_______ _________ _       __________________   _______          _________ _______  _        ______
(  ____ \\__   __/( (    /|\__    _/\__   __/  (  ____ \|\     /|\__   __/(  ____ \( \      (  __  \
| (    \/   ) (   |  \  ( |   )  (     ) (     | (    \/| )   ( |   ) (   | (    \/| (      | (  \  )
| (__       | |   |   \ | |   |  |     | |     | (_____ | (___) |   | |   | (__    | |      | |   ) |
|  __)      | |   | (\ \) |   |  |     | |     (_____  )|  ___  |   | |   |  __)   | |      | |   | |
| (         | |   | | \   |   |  |     | |           ) || (   ) |   | |   | (      | |      | |   ) |
| )      ___) (___| )  \  ||\_)  )  ___) (___  /\____) || )   ( |___) (___| (____/\| (____/\| (__/  )
|/       \_______/|/    )_)(____/   \_______/  \_______)|/     \|\_______/(_______/(_______/(______/


FinjiShield v1.0
Author : Koji Xenpai
GitHub : https://github.com/alfarozy
LinkedIn : https://www.linkedin.com/in/muhammad-alfarozi/

======== MENU ABUSE IP =========
1) Sync blocklist (ambil JSON & sinkronisasi iptables)
2) Tampilkan IP blocklist yg ada di Nginx log
3) Tampilkan IP baru yg diblock (sejak update terakhir)
4) List semua IP yg diblock
5) Deteksi akses berbahaya (show) dari Nginx log
6) Auto-block dari deteksi akses berbahaya dari Nginx log
7) Buka semua IP (flush blocklist)
8) Deteksi brute force (10 menit terakhir)
9) Block IP manual (input)
10) Lihat log dari IP tertentu (input)
0) Exit
================================
EOF
}

command -v jq >/dev/null 2>&1 || { echo "Install jq dulu: sudo apt install -y jq"; exit 1; }
command -v curl >/dev/null 2>&1 || { echo "Install curl dulu: sudo apt install -y curl"; exit 1; }

while true; do
  print_menu
  read -rp "Pilih menu [0-10]: " choice
  case "$choice" in
    1) run_menu_option sync_blocklist ;;
    2) run_menu_option show_nginx_hits ;;
    3) run_menu_option show_newly_blocked ;;
    4) run_menu_option list_blocked_ips ;;
    5) run_menu_option detect_sensitive_hits ;;
    6) run_menu_option auto_block_from_detection ;;
    7) run_menu_option flush_chain ;;
    8) run_menu_option detect_bruteforce ;;
    9) run_menu_option manual_block ;;
    10) run_menu_option show_logs_for_ip ;;
    0) echo "Keluar..."; exit 0 ;;
    *) echo "Pilihan tidak valid" ;;
  esac
done


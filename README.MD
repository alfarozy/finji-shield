

FinjiShield
===========

**FinjiShield** — Lightweight detection & blocking tool untuk server Debian (fokus: Nginx + SSH). Mendeteksi aktivitas berbahaya (sensitive path scans, 404 flood, request flood/brute-force pada Nginx, brute-force SSH) dan otomatis mem-block IP lewat `iptables`. Dilengkapi menu interaktif, opsi manual, dan sinkronisasi blocklist dari JSON remote.


> **PENTING:** sebelum menjalankan, isi `ADMIN_IP` pada script agar IP management/jump-host tidak ikut terbanned.

Latar Belakang Masalah
-----------

Selama beberapa hari terakhir, server saya mendapat percobaan brute-force directory yang mencoba mengakses berbagai path sensitif. Awalnya saya mencoba Cloudflare Free dengan beberapa firewall rule dan captcha, namun beberapa serangan masih berhasil melewati filter. Blok manual IP satu per satu juga merepotkan, dan penggunaan API Cloudflare untuk menambahkan banyak abuse IP gagal karena batas payload.

Sebagai solusi alternatif, saya mengembangkan FinjiShield untuk mendeteksi dan mem-block IP berbahaya langsung di server.

Fitur utama
-----------

* Sync blocklist – Ambil Abuse IP dari repository (https://github.com/rahulalam31/Laravel-Abuse-IP) dan sinkronisasi ke iptables.
* Tampilkan IP blocklist dari Nginx log – Lihat IP yang sudah diblokir berdasarkan log Nginx.
* Tampilkan IP baru yang diblokir – IP yang diblokir sejak update blocklist terakhir.
* List semua IP yang diblokir – Menampilkan semua IP yang pernah diblokir.
* Deteksi akses berbahaya (show) – Analisis log Nginx untuk menampilkan akses ke path sensitif atau request mencurigakan.
* Auto-block dari deteksi akses berbahaya – Secara otomatis mem-block IP berdasarkan deteksi dari Nginx log.
* Buka semua IP (flush blocklist) – Hapus seluruh IP yang diblokir.
* Deteksi brute-force (10 menit terakhir) – Analisis log untuk mendeteksi percobaan brute-force terkini.
* Block IP manual – Memasukkan IP secara manual untuk diblokir.
* Lihat log dari IP tertentu – Menampilkan aktivitas IP spesifik dari log.

Persyaratan
-----------

*   OS: Debian (atau distro serupa; sesuaikan path log)
*   Akses root / sudo
*   `bash` (GNU bash)
*   `iptables`
*   `curl`
*   `jq`

    sudo apt update
    sudo apt install -y curl jq
    

Instalasi cepat
---------------

1.  clone this  repo
    
        https://github.com/alfarozy/finji-shield.git
        
    
2.  Beri permission:
    
        sudo chmod +x finjishield.sh
        
    
3.  Edit konfigurasi di header script: set `ADMIN_IP`, `NGINX_LOG`, thresholds, dan `URL` JSON bila perlu.

Menjalankan (interaktif)
------------------------

    sudo finjishield.sh
    

Menu interaktif:

    ========= MENU FINJISHIELD =========
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
    ====================================
    
Threshold rekomendasi
---------------------

*   `THRESH_SENSITIVE=20` — hits ke path sensitif.
*   `THRESH_404=50` — hits 404.
*   `THRESH_BRUTE=1500` — hits dalam 10 menit.

Safety & Best Practices
-----------------------

*   Wajib set `ADMIN_IP` sebelum auto-block.
*   Uji mode deteksi dulu sebelum auto-block.
*   Gunakan `iptables-save` untuk persistensi reboot.

Emergency unlock
----------------

    sudo iptables -D BLOCKLIST -s <ADMIN_IP> -j DROP
    sudo iptables -F BLOCKLIST
    

Logging & Forensik
------------------

*   Periksa: `/var/log/auth.log`, `/var/log/nginx/access.log`, `/var/log/nginx/error.log`.


License
-------

MIT License.

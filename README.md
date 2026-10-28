# Simulasi Information Exchange, KDC dan AES

| Name           | NRP        | Kelas     |
| ---            | ---        | ----------|
| Hasan Abdurrahman | 5025241114 | B |
| Royan Habibi Alfatih | 5025241115 | B |

# Menjalankan Proyek di Windows + 2 VM VirtualBox

Panduan ringkas menjalankan KDC, Alice, dan Bob di tiga perangkat dengan IP berbeda.

## Isi dulu

Catat nilai berikut, lalu ganti setiap placeholder di panduan ini **termasuk tanda `< >`**.
Di PowerShell dan bash, `<` adalah operator khusus, jadi perintah yang masih berisi placeholder akan error.

| Placeholder | Arti | Cara mencari |
|---|---|---|
| `<ip-kdc>` | IP VM KDC di jaringan host-only | `ip a` di VM KDC (biasanya `192.168.56.x`) |
| `<ip-bob>` | IP VM Bob di jaringan host-only | `ip a` di VM Bob |
| `<port-kdc>` | Port KDC, misalnya `5000` | Bebas, di atas 1024 dan tidak dipakai program lain |
| `<port-bob>` | Port Bob, misalnya `6000` | Sama, dan berbeda dari `<port-kdc>` |
| `<user-vm>` | Nama user Linux di VM | `whoami` di VM |
| `<nama-interface>` *(opsional)* | Nama adapter host-only di VM | `ip a`, adapter yang ber-IP `192.168.56.x` (misalnya `enp0s8`) |
| `<ip-vm>` *(opsional)* | IP statis yang dipilih untuk VM itu | Lihat bagian 2b |
| `<nama-file>` *(opsional)* | Nama file netplan, misalnya `60-host-only` | Lihat bagian 2b |

```
Benar : python alice.py --kdc 192.168.56.10:5000 ...
Salah : python alice.py --kdc <192.168.56.10>:5000 ...
```

## 0. Susunan perangkat

| Perangkat | Peran | Alamat |
|---|---|---|
| Laptop Windows (host) | Alice | – (client, tidak perlu port) |
| VM 1 | KDC | `<ip-kdc>:<port-kdc>` |
| VM 2 | Bob | `<ip-bob>:<port-bob>` |

Alice ditaruh di host karena ia berbicara dengan KDC **dan** Bob, sehingga Wireshark di Windows bisa menangkap seluruh alur.
KDC dan Bob tidak pernah terhubung satu sama lain.

## 1. Jaringan VM

Untuk **setiap VM**, dalam keadaan VM mati: **Settings → Network**

- **Adapter 1:** NAT (agar VM tetap punya internet)
- **Adapter 2:** Enable → *Attached to:* **Host-only Adapter** → pilih adapter yang **sama** untuk kedua VM

Nyalakan VM, lalu cek IP dan koneksi:

```bash
ip a                    # di VM: catat IP 192.168.56.x sebagai <ip-kdc> / <ip-bob>
```
```powershell
ping <ip-kdc>           # di Windows
ping <ip-bob>
```

Kalau adapter kedua belum punya IP: `sudo dhclient <nama-interface>`

## 2. Siapkan VM (sekali saja)

### 2a. Python, SSH, dan firewall

Di **setiap VM**:

```bash
python3 --version                       # minimal 3.8
sudo apt update && sudo apt install -y openssh-server
sudo systemctl enable --now ssh
sudo ufw status                         # kalau "inactive", lewati baris di bawah
```

Kalau `ufw` aktif:

```bash
sudo ufw allow 22/tcp                   # kedua VM (SSH)
sudo ufw allow <port-kdc>/tcp           # hanya di VM KDC
sudo ufw allow <port-bob>/tcp           # hanya di VM Bob
```

### 2b. IP statis (opsional, disarankan untuk demo)

IP dari DHCP bisa berubah setelah restart. Agar tetap, atur IP statis (Ubuntu, netplan):

```bash
ls /etc/netplan/                        # lihat file yang sudah ada
sudo nano /etc/netplan/<nama-file>.yaml
```

```yaml
network:
  version: 2
  ethernets:
    <nama-interface>:
      dhcp4: false
      addresses: [<ip-vm>/24]
```

```bash
sudo chmod 600 /etc/netplan/<nama-file>.yaml
sudo netplan apply
ip a                                    # pastikan IP sudah berubah
```

| Aturan | Alasan |
|---|---|
| File di `/etc/netplan/` dan berakhiran `.yaml` | Netplan hanya membaca file seperti itu |
| Awali nama dengan angka lebih besar dari file yang ada (misalnya `60-`) | File dibaca berurutan; yang terakhir menimpa |
| `<ip-vm>` di luar rentang DHCP (misalnya `.10` dan `.20`) | Rentang DHCP host-only biasanya mulai `.101`; cek di *File → Tools → Network Manager* |
| `chmod 600` | Netplan memberi peringatan bila file bisa dibaca semua user |

## 3. Salin proyek dari Windows

Dari folder **induk** proyek (folder yang berisi `kdc-aes`):

```powershell
scp -r kdc-aes <user-vm>@<ip-kdc>:~
scp -r kdc-aes <user-vm>@<ip-bob>:~
ssh <user-vm>@<ip-kdc> "ls ~/kdc-aes"   # cek hasil
```

- Jangan `scp -r . <user-vm>@<ip>:~`: file akan tercecer langsung di folder home.
- Ketiga perangkat harus memakai **versi file yang sama**, terutama `common.py`. Salin ulang setiap kali kode berubah.
- Alternatif: `git clone` / `git pull` di setiap VM bila proyek ada di GitHub.

## 4. Jalankan (urutan: KDC → Bob → Alice)

Buka tiga panel di Windows Terminal. **Tulis semua alamat secara lengkap**, jangan mengandalkan nilai default.

```bash
# Panel 1: KDC
ssh <user-vm>@<ip-kdc>
cd ~/kdc-aes && python3 kdc.py --host 0.0.0.0 --port <port-kdc>
#   -> masukkan master key Alice dan Bob
```
```bash
# Panel 2: Bob
ssh <user-vm>@<ip-bob>
cd ~/kdc-aes && python3 bob.py --host 0.0.0.0 --port <port-bob>
#   -> masukkan Kb (sama dengan master key Bob di KDC)
```
```powershell
# Panel 3: Alice (langsung di Windows)
python alice.py --kdc <ip-kdc>:<port-kdc> --bob <ip-bob>:<port-bob>
#   -> masukkan Ka (sama dengan master key Alice di KDC)
#   -> menu 1: key distribution, menu 2: chat
```

| Alamat | Dipakai di | Nilai untuk demo |
|---|---|---|
| `--host` | KDC dan Bob (alamat mendengarkan) | `0.0.0.0` = semua kartu jaringan |
| `--kdc`, `--bob` | Alice (alamat tujuan) | `<ip-kdc>`, `<ip-bob>` |
| `127.0.0.1` | – | Hanya untuk latihan di satu komputer |

Port harus **sama di semua tempat**:

| Tempat | KDC | Bob |
|---|---|---|
| Menjalankan server | `--port <port-kdc>` | `--port <port-bob>` |
| Tujuan Alice | `<ip-kdc>:<port-kdc>` | `<ip-bob>:<port-bob>` |
| Firewall VM | `ufw allow <port-kdc>/tcp` | `ufw allow <port-bob>/tcp` |
| Filter Wireshark | `tcp.port == <port-kdc>` | `tcp.port == <port-bob>` |

Kalau sesi SSH terputus, program di VM ikut berhenti. Jalankan ulang, atau gunakan `tmux` di VM.

## 5. Wireshark (di Windows)

1. Mulai capture **sebelum** menu 1 di Alice.
2. Interface: **VirtualBox Host-Only Network**.
3. Filter: `tcp.port == <port-kdc> || tcp.port == <port-bob>` (sekaligus menyaring SSH port 22).
4. Klik kanan paket → **Follow → TCP Stream**. Langkah (1) tampak plaintext; langkah (2)–(5) dan chat hanya hex.

## 6. Kalau gagal

| Gejala | Penyebab paling mungkin |
|---|---|
| `10061` / `Connection refused` | Server belum jalan, masih menunggu input key, atau mendengarkan di `127.0.0.1` (pastikan `--host 0.0.0.0`) |
| `timed out` | IP salah, adapter bukan host-only yang sama, atau `ufw` memblokir port |
| `Pesan rusak` | Alice menghubungi alamat yang salah (cek menu 6), atau versi `common.py` berbeda |
| KDC: `IDA dan IDB harus berupa teks` | Nama field di `kdc.py` dan `alice_kdc.py` tidak sama |
| `Ka salah?` / `Tiket tidak bisa dibuka dengan Kb` | Master key di Alice/Bob tidak sama dengan yang terdaftar di KDC |
| VM tidak punya IP `192.168.56.x` | Adapter 2 belum aktif: `sudo dhclient <nama-interface>` |
| `ssh: Connection refused` | Server SSH belum jalan atau port 22 diblokir (bagian 2a) |
| Wireshark kosong | Salah pilih interface, atau capture dimulai setelah koneksi selesai |
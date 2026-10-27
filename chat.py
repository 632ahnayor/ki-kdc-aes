"""
chat.py: chat Alice dan Bob setelah key distribution

Ide komunikasi dua arah:
    * Thread PENERIMA berjalan terus di latar belakang dan mencetak pesan
      masuk kapan saja.
    * Thread UTAMA membaca ketikan pengguna dan mengirimnya.
  Karena keduanya berjalan bersamaan, Alice dan Bob sama-sama bisa menjadi
  sender maupun receiver.

Format pesan (common.py):
    {"type": "msg", "from": "Alice", "data": "<hex>"}

Enkripsi memakai aes.encrypt / aes.decrypt (mode CBC, IV acak), sehingga
pesan yang sama menghasilkan ciphertext berbeda setiap kali dikirim.
"""

import socket
import threading

import aes
import common


class SaluranChat:
    def __init__(self, sock, penerima, ks, nama_saya):
        """
        sock      : socket setelah lolos langkah 5 key distrib
        penerima  : common.Penerima milik socket itu
        ks        : session key ASCII
        nama_saya : "Alice" atau "Bob"
        """
        self.sock = sock
        self.penerima = penerima
        self.ks = ks
        self.nama_saya = nama_saya
        self.aktif = True
        self.riwayat = [] # (arah, pengirim, plaintext/None, hex)
        self._kunci_kirim = threading.Lock()
        self._thread = None
    

    def mulai(self):
        self._thread = threading.Thread(target=self._loop_terima, daemon=True)
        self._thread.start()

    def _loop_terima(self):
        while self.aktif:
            try:
                pesan = self.penerima.terima()
            except (OSError, ValueError):
                pesan = None

            if pesan is None:
                if self.aktif:
                    common.log(self.nama_saya, "Koneksi chat ditutup oleh lawan.")
                self.aktif = False
                break

            if pesan.get("type") != "msg":
                continue

            pengirim = pesan.get("from", "?")
            hex_c = pesan.get("data", "")
            try:
                teks = aes.decrypt(self.ks, hex_c)
            except ValueError:
                teks = None # Ks berbeda / data rusak

            self.riwayat.append(("masuk", pengirim, teks, hex_c))
            common.log(self.nama_saya, f"Pesan masuk dari {pengirim}")
            common.log(self.nama_saya, f"  ciphertext (hex): {hex_c}")
            if teks is None:
                common.log(self.nama_saya, "  GAGAL DEKRIPSI (Ks berbeda?)")
            else:
                common.log(self.nama_saya, f"  plaintext       : {teks}")

    
    def kirim(self, teks):
        """
        Enkripsi teks dengan Ks lalu kirim.
        Error: ValueError jika teks bukan ASCII, 
        ConnectionError jika saluran sudah tertutup.
        """
        if not self.aktif:
            raise ConnectionError("Saluran chat sudah tertutup")
        if not teks.isascii():
            raise ValueError("Pesan harus berisi karakter ASCII saja")

        hex_c = aes.encrypt(self.ks, teks)
        with self._kunci_kirim:
            common.kirim(self.sock, {"type": "msg", "from": self.nama_saya, "data": hex_c})

        self.riwayat.append(("keluar", self.nama_saya, teks, hex_c))
        common.log(self.nama_saya, f"Pesan terkirim: {teks}")
        common.log(self.nama_saya, f"  ciphertext (hex): {hex_c}")

    def ubah_ks(self, ks_baru):
        """Ganti Ks di sisi ini saja"""
        self.ks = ks_baru

    def tutup(self):
        """Hentikan saluran dan tutup socket"""
        self.aktif = False
        try:
            self.sock.shutdown(socket.SHUT_RDWR)
        except OSError:
            pass
        try:
            self.sock.close()
        except OSError:
            pass


def mode_chat(saluran):
    """
    Loop interaktif chat, dipakai menu Alice dan menu Bob.
    Ketik pesan lalu Enter. Ketik /keluar untuk kembali ke menu
    (saluran tetap terbuka)
    (pesan masuk tetap tercetak di latar belakang)
    """
    print("\n--- Mode chat (Ks aktif: %s) ---" % saluran.ks)
    print("Ketik pesan lalu Enter. Ketik /keluar untuk kembali ke menu.\n")
    while saluran.aktif:
        try:
            teks = input()
        except EOFError:
            break
        if teks.strip() == "/keluar":
            break
        if not teks:
            continue
        if not saluran.aktif:
            break
        try:
            saluran.kirim(teks)
        except ValueError as e:
            print(f"  ! {e}")
        except (OSError, ConnectionError) as e:
            print(f"  ! Gagal mengirim: {e}")
            break
    if not saluran.aktif:
        print("Saluran chat sudah tertutup. Jalankan key distribution lagi.")
"""
bob.py Responder B: langkah 3-5, lalu chat dua arah.

run: python bob.py --host 0.0.0.0 --port 6000

Bob tidak pernah menghubungi KDC. Ks didapat dari tiket E(Kb, [Ks || IDA])
yang dibawa Alice; tiket itu dibuat KDC dan hanya bisa dibuka dengan Kb.

Menu interaktif (key bisa diubah tanpa restart):
    1. Mode chat
    2. Info (Kb, Ks aktif, Alice yang terhubung)
    3. Ubah Kb
    4. Ubah Ks manual
    0. Keluar
"""

import argparse
import socket
import threading

import aes
import chat
import common

ID_BOB = "Bob"


class Bob:
    def __init__(self, kb):
        self.kb = kb #master key Bob, sama dengan yang disimpan KDC
        self.ks = None #session key dari tiket terakhir yang VALID
        self.ida = None #identitas Alice dari tiket
        self.alamat_alice = None #tuple (ip, port) Alice yang terhubung
        self.saluran = None #saluran chat aktif (chat.SaluranChat)
        self.kunci = threading.Lock() #lock state, dipakai bersama thread handshake dan menu
        self._server = None #socket server yang mendengarkan

    # JARINGAN

    def jalankan_server(self, host, port, latar=False):
        """
        Buka port lalu terima koneksi Alice satu per satu (tiap koneksi di thread sendiri).
        latar=False : loop di thread pemanggil (blocking).
        latar=True  : loop di thread latar; fungsi langsung kembali setelah port terbuka.
        Error membuka port (misalnya port sudah dipakai) langsung dilempar ke pemanggil.
        """
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM) #socket TCP IPv4
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1) #port bisa langsung dipakai ulang setelah restart
        srv.bind((host, port)) #ikat ke alamat dan port
        srv.listen(5) #antrean koneksi maksimal 5
        self._server = srv #simpan agar bisa ditutup di hentikan()
        common.log(ID_BOB, f"Menunggu Alice di {host}:{port}")
        if latar: #loop accept di thread latar, menu tetap bisa jalan
            threading.Thread(target=self._loop_accept, daemon=True).start()
        else: #loop accept di thread ini (blocking)
            self._loop_accept()

    def _loop_accept(self):
        while True: #terima koneksi terus sampai server ditutup
            try:
                conn, addr = self._server.accept() #tunggu Alice terhubung
            except OSError: #server ditutup
                break
            threading.Thread(target=self._handshake, args=(conn, addr), daemon=True).start() #handshake tiap Alice di thread sendiri

    def hentikan(self):
        """Tutup server dan saluran chat (dipakai saat keluar dan di file uji)."""
        if self._server is not None: #server pernah dibuka
            try:
                self._server.close() #tutup server, accept() di _loop_accept ikut berhenti
            except OSError:
                pass
        with self.kunci:
            saluran = self.saluran #ambil saluran di dalam lock
        if saluran is not None:
            saluran.tutup() #tutup di luar lock agar tidak saling tunggu

    # LANGKAH (3) - (5)

    def _tolak(self, conn, langkah, alasan):
        """
        input : conn    -> socket ke Alice
                langkah -> langkah tempat penolakan terjadi (4 atau 5)
                alasan  -> teks alasan untuk log dan untuk Alice
        Kirim pesan penolakan ke Alice lalu tutup koneksi.
        """
        common.log(ID_BOB, f"DITOLAK: {alasan}")
        try:
            if langkah == 4: #Alice sedang menunggu langkah (4), balas sebagai error langkah (4)
                common.kirim(conn, {"step": 4, "error": alasan})
            else: #Alice sedang menunggu hasil, balas valid=False
                common.kirim(conn, {"step": "hasil", "valid": False, "alasan": alasan})
        except OSError: #Alice sudah memutus koneksi
            pass
        conn.close() #tutup koneksi ke Alice

    def _handshake(self, conn, addr):
        """
        input : conn -> socket dari Alice
                addr -> tuple (ip, port) Alice
        Jalankan langkah 3-5; jika VALID, koneksi dijadikan saluran chat aktif.
        """
        conn.settimeout(30) #batas tunggu tiap pesan selama handshake
        penerima = common.Penerima(conn) #pembaca pesan JSON dari socket
        try:
            # LANGKAH (3): Alice -> Bob : E(Kb, [Ks || IDA])
            # buka tiket dengan Kb
            pesan = penerima.terima() #tunggu tiket dari Alice
            if pesan is None or pesan.get("step") != 3 or "ticket" not in pesan: #bukan langkah (3)
                common.log(ID_BOB, f"Koneksi dari {addr[0]} bukan langkah (3), diabaikan")
                conn.close()
                return

            tiket = pesan["ticket"] #ciphertext hex buatan KDC
            common.log(ID_BOB, f"Langkah (3): terima tiket dari {addr[0]}:{addr[1]}")
            common.log(ID_BOB, f"  tiket (hex): {tiket}")

            with self.kunci:
                kb = self.kb #salin Kb, bisa diubah dari menu di thread lain
            try:
                ks, ida = common.pecah(aes.decrypt(kb, tiket), 2) #dekripsi lalu pisah "Ks||IDA"
                if common.cek_ks(ks) or common.cek_id(ida): #cek_* mengembalikan teks error, None jika valid
                    raise ValueError("isi tiket tidak sesuai format")
            except ValueError: #Kb salah atau tiket rusak
                self._tolak(conn, 4, "Tiket tidak bisa dibuka dengan Kb")
                return
            common.log(ID_BOB, f"  dibuka dengan Kb -> Ks = {ks}, IDA = {ida}")

            # LANGKAH (4): Bob -> Alice : E(Ks, N2)
            # tantang Alice dengan nonce N2
            n2 = common.buat_nonce() #nonce acak 9 digit (CSPRNG)
            hex_n2 = aes.encrypt(ks, str(n2)) #enkripsi N2 dengan Ks dari tiket
            common.kirim(conn, {"step": 4, "data": hex_n2}) #kirim tantangan ke Alice
            common.log(ID_BOB, f"Langkah (4): kirim E(Ks, N2), N2 = {n2}")
            common.log(ID_BOB, f"  ciphertext (hex): {hex_n2}")

            # LANGKAH (5): Alice -> Bob : E(Ks, f(N2))
            # cek jawaban N2 + 1, hanya pemegang Ks yang bisa menjawab
            pesan = penerima.terima() #tunggu jawaban Alice
            if pesan is None or pesan.get("step") != 5 or "data" not in pesan: #bukan langkah (5)
                self._tolak(conn, 5, "Tidak ada jawaban langkah (5)")
                return
            common.log(ID_BOB, "Langkah (5): terima E(Ks, f(N2))")
            common.log(ID_BOB, f"  ciphertext (hex): {pesan['data']}")
            try:
                jawaban = int(aes.decrypt(ks, pesan["data"])) #dekripsi pakai Ks lalu ubah ke int
            except ValueError: #Ks berbeda, padding rusak, atau isi bukan angka
                self._tolak(conn, 5, "Jawaban tidak bisa dibuka dengan Ks")
                return
            if jawaban != n2 + 1: #harus tepat f(N2), mencegah replay
                self._tolak(conn, 5, f"Jawaban {jawaban} != N2 + 1 = {n2 + 1}")
                return

            common.kirim(conn, {"step": "hasil", "valid": True}) #beri tahu Alice: VALID
            common.log(ID_BOB, f"  f(N2) = {jawaban} = N2 + 1 -> VALID. {ida} terautentikasi.")

            # SIAP CHAT
            conn.settimeout(None) #timeout dimatikan
            saluran = chat.SaluranChat(conn, penerima, ks, ID_BOB) #saluran chat terenkripsi Ks
            with self.kunci: #ganti state sekaligus agar menu tidak membaca data setengah jadi
                lama = self.saluran #simpan saluran lama untuk ditutup
                self.saluran = saluran
                self.ks = ks
                self.ida = ida
                self.alamat_alice = addr
            if lama is not None:
                lama.tutup() #hanya satu Alice aktif, koneksi lama diputus
            saluran.mulai() #mulai thread penerima pesan chat
            common.log(ID_BOB, "Saluran chat siap. Pilih menu 1 untuk membalas.")

        except (OSError, ValueError) as e: #error jaringan atau data saat handshake
            common.log(ID_BOB, f"Handshake gagal: {e}")
            conn.close() #tutup koneksi ke Alice

    # MENU

    def info(self):
        with self.kunci:
            saluran = self.saluran
            print(f"  Kb          : {self.kb} (AES-{len(self.kb) * 8})")
            print(f"  Ks aktif    : {saluran.ks if saluran else '-'}")
            print(f"  Lawan bicara: {self.ida or '-'}"
                  + (f" dari {self.alamat_alice[0]}" if self.alamat_alice else ""))
            print(f"  Saluran     : {'AKTIF' if saluran and saluran.aktif else 'tidak ada'}")

    def menu(self):
        while True:
            print("\n===== MENU BOB =====")
            print("1. Mode chat")
            print("2. Info")
            print("3. Ubah Kb")
            print("4. Ubah Ks manual")
            print("0. Keluar")
            try:
                pilihan = input("Pilih: ").strip()
            except EOFError:
                pilihan = "0"

            with self.kunci:
                saluran = self.saluran

            if pilihan == "1":
                if saluran is not None and saluran.aktif:
                    chat.mode_chat(saluran)
                else:
                    print("Belum ada Alice yang terhubung.")
            elif pilihan == "2":
                self.info()
            elif pilihan == "3":
                kb = common.minta_key("Kb baru (16/24/32 karakter): ")
                with self.kunci:
                    self.kb = kb
                print("Kb diubah. Berlaku untuk tiket berikutnya.")
            elif pilihan == "4":
                if saluran is None:
                    print("Belum ada saluran chat.")
                    continue
                ks = common.minta_ks("Ks baru (16 karakter): ")
                saluran.ubah_ks(ks)
                with self.kunci:
                    self.ks = ks
                print("Ks di sisi Bob diubah.")
            elif pilihan == "0":
                break
            else:
                print("Pilihan tidak dikenal.")


def main():
    parser = argparse.ArgumentParser(description="Bob (Responder)")
    parser.add_argument("--host", default="0.0.0.0", help="alamat yang didengarkan")
    parser.add_argument("--port", type=int, default=6000)
    args = parser.parse_args()

    print("=== BOB (Responder) ===")
    kb = common.minta_key("Master key Bob, Kb (16/24/32 karakter, sama dengan di KDC): ")
    bob = Bob(kb)
    try:
        bob.jalankan_server(args.host, args.port, latar=True)
    except OSError as e:
        print(f"Tidak bisa membuka port {args.port}: {e}")
        return
    try:
        bob.menu()
    except KeyboardInterrupt:
        print()
    finally:
        bob.hentikan()
        print("Bob berhenti.")


if __name__ == "__main__":
    main()
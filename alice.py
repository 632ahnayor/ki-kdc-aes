"""
alice.py: Initiator A untuk key distribution dan chat.

Run: python alice.py --kdc 192.168.56.10:5000 --bob 192.168.56.12:6000
"""

import argparse

import alice_bob
import alice_kdc
import chat
import common

ID_ALICE = "Alice"


def parse_alamat(teks):
    """Parse alamat host:port."""
    host_port = teks.strip().rsplit(":", 1)
    if len(host_port) != 2 or not host_port[0]:
        raise ValueError("Alamat harus berformat host:port")
    try:
        port = int(host_port[1])
    except ValueError:
        raise ValueError("Port harus berupa angka") from None
    if not 1 <= port <= 65535:
        raise ValueError("Port harus berada dalam rentang 1-65535")
    return host_port[0], port


class Alice:
    def __init__(self, ka, alamat_kdc, alamat_bob, ida=ID_ALICE):
        masalah = common.cek_key(ka)
        if masalah:
            raise ValueError(masalah)
        masalah = common.cek_id(ida)
        if masalah:
            raise ValueError(masalah)
        self.ka = ka
        self.ida = ida
        self.idb = "Bob"
        self.alamat_kdc = alamat_kdc
        self.alamat_bob = alamat_bob
        self.ks = None
        self.tiket = None
        self.saluran = None

    def key_distribution(self):
        """Jalankan langkah (1)-(5) dan aktifkan saluran chat jika berhasil."""
        try:
            ks, tiket = alice_kdc.minta_session_key(
                self.alamat_kdc, self.ida, self.idb, self.ka
            )
        except alice_kdc.GagalKDC as error:
            common.log(self.ida, f"Key distribution gagal di KDC: {error}")
            print(f"Key distribution gagal: {error}")
            return False

        try:
            sock, penerima = alice_bob.handshake(self.alamat_bob, ks, tiket)
        except alice_bob.GagalHandshake as error:
            common.log(self.ida, f"Key distribution gagal saat handshake Bob: {error}")
            print(f"Handshake dengan Bob gagal: {error}")
            return False

        saluran_baru = chat.SaluranChat(sock, penerima, ks, self.ida)
        saluran_lama = self.saluran
        self.ks = ks
        self.tiket = tiket
        self.saluran = saluran_baru
        if saluran_lama is not None:
            saluran_lama.tutup()
        saluran_baru.mulai()
        common.log(self.ida, "Langkah (1)-(5) selesai. Saluran chat siap.")
        return True

    def _mode_chat(self):
        if self.saluran is None or not self.saluran.aktif:
            print("Belum ada saluran chat. Jalankan key distribution terlebih dahulu.")
            return
        chat.mode_chat(self.saluran)

    def _ubah_alamat(self):
        print(f"Alamat KDC saat ini: {self.alamat_kdc[0]}:{self.alamat_kdc[1]}")
        print(f"Alamat Bob saat ini: {self.alamat_bob[0]}:{self.alamat_bob[1]}")
        kdc = input("Alamat KDC baru (kosong untuk tetap): ").strip()
        bob = input("Alamat Bob baru (kosong untuk tetap): ").strip()
        alamat_kdc = parse_alamat(kdc) if kdc else self.alamat_kdc
        alamat_bob = parse_alamat(bob) if bob else self.alamat_bob
        self.alamat_kdc = alamat_kdc
        self.alamat_bob = alamat_bob
        print("Alamat diperbarui. Berlaku untuk key distribution berikutnya.")

    def _ubah_ks(self):
        if self.ks is None:
            print("Belum ada session key.")
            return
        ks = common.minta_ks("Ks baru (16 karakter): ")
        self.ks = ks
        if self.saluran is not None and self.saluran.aktif:
            self.saluran.ubah_ks(ks)
        print("Ks di sisi Alice diubah. Untuk komunikasi, ubah Ks di Bob juga.")

    def info(self):
        print(f"  ID Alice    : {self.ida}")
        print(f"  ID Bob      : {self.idb}")
        print(f"  KDC         : {self.alamat_kdc[0]}:{self.alamat_kdc[1]}")
        print(f"  Bob         : {self.alamat_bob[0]}:{self.alamat_bob[1]}")
        print(f"  Ka          : {self.ka} (AES-{len(self.ka) * 8})")
        print(f"  Ks aktif    : {self.ks or '-'}")
        print(f"  Saluran     : {'AKTIF' if self.saluran and self.saluran.aktif else 'tidak ada'}")

    def menu(self):
        while True:
            print("\n===== MENU ALICE =====")
            print("1. Key distribution (langkah 1-5)")
            print("2. Mode chat")
            print("3. Ubah alamat KDC/Bob")
            print("4. Ubah Ka")
            print("5. Ubah Ks manual")
            print("6. Info")
            print("0. Keluar")
            try:
                pilihan = input("Pilih: ").strip()
            except EOFError:
                pilihan = "0"

            if pilihan == "1":
                self.key_distribution()
            elif pilihan == "2":
                self._mode_chat()
            elif pilihan == "3":
                try:
                    self._ubah_alamat()
                except ValueError as error:
                    print(f"Alamat tidak valid: {error}")
            elif pilihan == "4":
                self.ka = common.minta_key("Ka baru (16/24/32 karakter): ")
                print("Ka diperbarui. Pastikan nilainya sama dengan master key Alice di KDC.")
            elif pilihan == "5":
                try:
                    self._ubah_ks()
                except ValueError as error:
                    print(f"Ks tidak valid: {error}")
            elif pilihan == "6":
                self.info()
            elif pilihan == "0":
                break
            else:
                print("Pilihan tidak dikenal.")


def main():
    parser = argparse.ArgumentParser(description="Alice (Initiator)")
    parser.add_argument("--kdc", default="127.0.0.1:5000", help="alamat KDC host:port")
    parser.add_argument("--bob", default="127.0.0.1:6000", help="alamat Bob host:port")
    parser.add_argument("--id", default=ID_ALICE, help="ID Alice yang terdaftar di KDC")
    args = parser.parse_args()

    try:
        alamat_kdc = parse_alamat(args.kdc)
        alamat_bob = parse_alamat(args.bob)
        masalah = common.cek_id(args.id)
        if masalah:
            raise ValueError(masalah)
    except ValueError as error:
        parser.error(str(error))

    print("=== ALICE (Initiator) ===")
    ka = common.minta_key("Master key Alice, Ka (16/24/32 karakter, sama dengan di KDC): ")
    alice = Alice(ka, alamat_kdc, alamat_bob, args.id)
    try:
        alice.menu()
    except KeyboardInterrupt:
        print()
    finally:
        if alice.saluran is not None:
            alice.saluran.tutup()
        print("Alice berhenti.")


if __name__ == "__main__":
    main()

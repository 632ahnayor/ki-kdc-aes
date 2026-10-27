"""
kdc.py: Key Distribution Center untuk langkah 1-2.

Run: python kdc.py --host 127.0.0.1 --port 5000
"""

import argparse
import socket
import threading

import aes
import common


class KDC:
    def __init__(self):
        self.master_keys = {}
        self.mode_ks = "acak"
        self.ks_manual = None
        self._kunci = threading.RLock()
        self._server = None

    def jalankan_server(self, host, port):
        """Buka server KDC dan jalankan penerimaan koneksi di thread latar."""
        srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        srv.bind((host, port))
        srv.listen(10)
        self._server = srv
        threading.Thread(target=self._loop_accept, daemon=True).start()
        common.log("KDC", f"Server berjalan di {host}:{port}")

    def _loop_accept(self):
        server = self._server
        while True:
            try:
                conn, addr = server.accept()
            except OSError:
                break
            threading.Thread(target=self._layani, args=(conn, addr), daemon=True).start()

    def hentikan(self):
        """Tutup server KDC."""
        if self._server is not None:
            try:
                self._server.close()
            except OSError:
                pass
            self._server = None

    def _layani(self, conn, addr):
        """Layani satu permintaan key distribution dari Alice."""
        with conn:
            conn.settimeout(10)
            penerima = common.Penerima(conn)
            try:
                pesan = penerima.terima()
                if pesan is None or pesan.get("step") != 1:
                    raise ValueError("Permintaan bukan langkah (1)")

                ida = pesan.get("ida")
                idb = pesan.get("idb")
                n1 = pesan.get("n1")
                if not isinstance(ida, str) or not isinstance(idb, str):
                    raise ValueError("IDA dan IDB harus berupa teks")
                if isinstance(n1, bool) or not isinstance(n1, (int, str)):
                    raise ValueError("N1 tidak valid")
                try:
                    n1 = int(n1)
                except ValueError:
                    raise ValueError("N1 tidak valid") from None
                if not 100_000_000 <= n1 <= 999_999_999:
                    raise ValueError("N1 harus berupa nonce 9 digit")
                for identitas in (ida, idb):
                    masalah = common.cek_id(identitas)
                    if masalah:
                        raise ValueError(masalah)

                with self._kunci:
                    ka = self.master_keys.get(ida)
                    kb = self.master_keys.get(idb)
                    mode_ks = self.mode_ks
                    ks_manual = self.ks_manual
                if ka is None or kb is None:
                    raise ValueError("IDA atau IDB belum terdaftar di KDC")

                ks = ks_manual if mode_ks == "manual" else common.buat_session_key()
                masalah = common.cek_ks(ks)
                if masalah:
                    raise ValueError(f"Session key KDC tidak valid: {masalah}")

                data_alice = aes.encrypt(ka, common.gabung(ks, ida, idb, n1))
                tiket_bob = aes.encrypt(kb, common.gabung(ks, ida))
                common.kirim(conn, {"step": 2, "data": data_alice, "ticket": tiket_bob})
                common.log("KDC", f"Langkah (1): permintaan IDA={ida}, IDB={idb}, N1={n1} dari {addr[0]}")
                common.log("KDC", f"Langkah (2): kirim E(Ka, data) dan tiket E(Kb, [Ks || IDA])")
            except (OSError, ValueError) as error:
                common.log("KDC", f"Permintaan dari {addr[0]} ditolak: {error}")
                try:
                    common.kirim(conn, {"step": "error", "error": str(error)})
                except OSError:
                    pass

    def _tampil_master_keys(self):
        with self._kunci:
            keys = sorted(self.master_keys.items())
        print("\nMaster key terdaftar:")
        if not keys:
            print("  (belum ada)")
        for identitas, key in keys:
            print(f"  {identitas}: {key} (AES-{len(key) * 8})")

    def _ubah_master_key(self):
        identitas = common.minta_id("ID: ")
        key = common.minta_key("Master key (16/24/32 karakter): ")
        with self._kunci:
            self.master_keys[identitas] = key
        print(f"Master key untuk {identitas} disimpan.")

    def _hapus_master_key(self):
        identitas = common.minta_id("ID yang dihapus: ")
        with self._kunci:
            if identitas not in self.master_keys:
                print(f"ID {identitas} tidak terdaftar.")
                return
            del self.master_keys[identitas]
        print(f"Master key {identitas} dihapus.")

    def menu(self):
        while self._server is not None:
            print("\n===== MENU KDC =====")
            print("1. Lihat master key")
            print("2. Tambah/ubah master key")
            print("3. Hapus master key")
            print("4. Mode Ks (acak/manual)")
            print("0. Keluar")
            try:
                pilihan = input("Pilih: ").strip()
            except EOFError:
                pilihan = "0"

            if pilihan == "1":
                self._tampil_master_keys()
            elif pilihan == "2":
                try:
                    self._ubah_master_key()
                except ValueError as error:
                    print(f"Input tidak valid: {error}")
            elif pilihan == "3":
                try:
                    self._hapus_master_key()
                except ValueError as error:
                    print(f"Input tidak valid: {error}")
            elif pilihan == "4":
                print("1. Acak (disarankan)")
                print("2. Manual (untuk demonstrasi)")
                mode = input("Pilih mode: ").strip()
                if mode == "1":
                    with self._kunci:
                        self.mode_ks = "acak"
                        self.ks_manual = None
                    print("Session key akan dibuat acak.")
                elif mode == "2":
                    try:
                        ks = common.minta_ks("Ks manual (16 karakter): ")
                    except ValueError as error:
                        print(f"Input tidak valid: {error}")
                        continue
                    with self._kunci:
                        self.mode_ks = "manual"
                        self.ks_manual = ks
                    print("Session key manual disimpan.")
                else:
                    print("Pilihan tidak dikenal.")
            elif pilihan == "0":
                break
            else:
                print("Pilihan tidak dikenal.")


def main():
    parser = argparse.ArgumentParser(description="KDC (Key Distribution Center)")
    parser.add_argument("--host", default="127.0.0.1", help="alamat yang didengarkan")
    parser.add_argument("--port", type=int, default=5000)
    args = parser.parse_args()

    print("=== KDC ===")
    kdc = KDC()
    try:
        for identitas in ("Alice", "Bob"):
            key = common.minta_key(
                f"Master key {identitas} (16/24/32 karakter): "
            )
            kdc.master_keys[identitas] = key
        kdc.jalankan_server(args.host, args.port)
    except (OSError, ValueError) as error:
        print(f"Tidak bisa menjalankan KDC: {error}")
        return
    try:
        kdc.menu()
    except KeyboardInterrupt:
        print()
    finally:
        kdc.hentikan()
        print("KDC berhenti.")


if __name__ == "__main__":
    main()

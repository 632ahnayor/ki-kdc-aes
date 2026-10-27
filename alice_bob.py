"""
alice_bob.py: Sisi Alice untuk langkah 3-5.

Alur (slide security 07, Key Distribution Scenario):
(3) Alice -> Bob : E(Kb, [Ks || IDA]) tiket diteruskan
(4) Bob -> Alice : E(Ks, N2)
(5) Alice -> Bob : E(Ks, f(N2)) f(N2) = N2 + 1

handshake(alamat_bob, ks, tiket_hex) -> (sock, penerima)
    sock, penerima : koneksi ke Bob yang sudah VALID, siap dipakai
                        chat.SaluranChat(sock, penerima, ks, "Alice")
Error: GagalHandshake berisi pesan yang siap ditampilkan.
"""

import socket

import aes
import common

NAMA = "Alice"


class GagalHandshake(Exception):
    """Dilempar jika langkah 3-5 gagal."""


def f(n2):
    """fungsi nonce f(N2) = N2 + 1."""
    return n2 + 1


def handshake(alamat_bob, ks, tiket_hex, timeout=10):
    """
    alamat_bob : tuple (ip, port)
    ks         : session key dari langkah (2)
    tiket_hex  : E_Kb dari KDC, diteruskan tanpa diubah (hanya bisa dibuka kb)
    """
    try:
        sock = socket.create_connection(alamat_bob, timeout=timeout)
    except OSError as e:
        raise GagalHandshake(f"Tidak bisa terhubung ke Bob {alamat_bob[0]}:{alamat_bob[1]} ({e})")

    try:
        penerima = common.Penerima(sock)

        # LANGKAH (3)
        common.kirim(sock, {"step": 3, "ticket": tiket_hex})
        common.log(NAMA, "Langkah (3): kirim tiket E(Kb, [Ks || IDA]) ke Bob")
        common.log(NAMA, f"  tiket (hex): {tiket_hex}")

        # LANGKAH (4)
        pesan = penerima.terima()
        if pesan is None:
            raise GagalHandshake("Bob menutup koneksi sebelum langkah (4)")
        if "error" in pesan:
            raise GagalHandshake(f"Bob menolak: {pesan['error']}")
        if pesan.get("step") != 4 or "data" not in pesan:
            raise GagalHandshake("Balasan Bob bukan langkah (4)")

        try:
            n2 = int(aes.decrypt(ks, pesan["data"]))
        except ValueError:
            raise GagalHandshake("N2 dari Bob tidak bisa dibuka dengan Ks") from None
        common.log(NAMA, "Langkah (4): terima E(Ks, N2) dari Bob")
        common.log(NAMA, f"  ciphertext (hex): {pesan['data']}")
        common.log(NAMA, f"  N2 = {n2}")

        # LANGKAH (5)
        jawaban = f(n2)
        hex_jawaban = aes.encrypt(ks, str(jawaban))
        common.kirim(sock, {"step": 5, "data": hex_jawaban})
        common.log(NAMA, f"Langkah (5): kirim E(Ks, f(N2)), f(N2) = N2 + 1 = {jawaban}")
        common.log(NAMA, f"  ciphertext (hex): {hex_jawaban}")

        hasil = penerima.terima()
        if hasil is None:
            raise GagalHandshake("Bob menutup koneksi sebelum memberi hasil")
        if hasil.get("valid") is not True:
            raise GagalHandshake(f"Bob: TIDAK VALID ({hasil.get('alasan', 'tanpa alasan')})")
        common.log(NAMA, "Bob menyatakan VALID. Saluran aman siap dipakai.")

        sock.settimeout(None) # set no timeout
        return sock, penerima

    except GagalHandshake:
        sock.close()
        raise
    except (OSError, ValueError) as e: 
        sock.close()
        raise GagalHandshake(f"Handshake dengan Bob gagal: {e}") from None
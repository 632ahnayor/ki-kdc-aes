"""
all purpose tools:  wrap pesan json, nonce (N), session key, concat
dipakai: kdc, alice, bob, chat
"""

import json
import secrets
import string
import threading
import time

SEP = "||"
PANJANG_KS = 16 # Ks selalu ASCII 16 karakter (AES-128)
PANJANG_KEY_VALID = (16, 24, 32)    # AES-128 / 192 / 256
HURUF_KS = string.ascii_letters + string.digits   # tanpa "|", aman untuk SEP

LOG_AKTIF = True
_kunci_cetak = threading.Lock()

# LOG
def log(sumber, teks):
    """
    Cetak satu baris log dengan jam dan nama sumber, misalnya:
        [14:02:11] [Bob] Langkah (3): tiket diterima

    Pakai lock agar log dari beberapa thread tidak tercampur di satu baris.
    """
    if not LOG_AKTIF:
        return
    jam = time.strftime("%H:%M:%S")
    with _kunci_cetak:
        print(f"[{jam}] [{sumber}] {teks}", flush=True)


# KIRIM TERIMA PESAN
def kirim(sock, pesan):
    """
    kirim satu pesan sebagai satu baris JSON.
    pakai sendall. send bisa mengirim sebagian saja.
    """
    data = (json.dumps(pesan) + "\n").encode("utf-8")
    sock.sendall(data)


class Penerima:
    """
    Pembaca pesan dari satu socket.

    karena tcp, simpan dulu di buffer sampai "\n"
    """

    def __init__(self, sock):
        self.sock = sock
        self._buffer = b""

    def terima(self):
        """
        output: dict pesan, atau None jika lawan menutup koneksi.
        error: ValueError jika baris yang diterima bukan JSON yang valid.
                OSError / socket.timeout diteruskan ke pemanggil.
        """
        while b"\n" not in self._buffer:
            potongan = self.sock.recv(4096)
            if not potongan:            # b"" = koneksi ditutup lawan
                return None
            self._buffer += potongan
        baris, self._buffer = self._buffer.split(b"\n", 1)
        try:
            pesan = json.loads(baris.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as e:
            raise ValueError(f"Pesan rusak: {e}") from None
        if not isinstance(pesan, dict):
            raise ValueError("Pesan harus berupa objek JSON")
        return pesan

#NONCE

def buat_nonce():
    """
    random 9 digit untuk N1/2.

    pakai modul secrets (CSPRNG sistem operasi)
    """
    return secrets.randbelow(900_000_000) + 100_000_000

# SESSION KEY
def buat_session_key():
    """Ks acak: 16 karakter ASCII (huruf + angka, tanpa "|")."""
    return "".join(secrets.choice(HURUF_KS) for _ in range(PANJANG_KS))

# CONCAT

def gabung(*bagian):
    """gabung(Ks, "Alice", "Bob", 617803919) -> "Ks||Alice||Bob||617803919" """
    return SEP.join(str(b) for b in bagian)


def pecah(teks, jumlah):
    """
    Kebalikan gabung().
        pecah("Ks||Alice||Bob||617803919", 4) -> ["Ks", "Alice", "Bob", "617803919"]

    Error: ValueError jika jumlah bagian tidak sesuai (tanda key salah / data rusak).
    """
    bagian = teks.split(SEP)
    if len(bagian) != jumlah:
        raise ValueError(f"Diharapkan {jumlah} bagian, didapat {len(bagian)}")
    return bagian


# VALIDASI INPUT

def cek_key(key):
    """Master key: ASCII, panjang 16/24/32. return None jika valid, masalah jika tidak."""
    if not key.isascii():
        return "Key harus berisi karakter ASCII saja"
    if len(key) not in PANJANG_KEY_VALID:
        return f"Key harus 16, 24, atau 32 karakter (sekarang {len(key)})"
    return None


def cek_ks(ks):
    """Session key: ASCII 16 karakter, tanpa "|"."""
    if not ks.isascii():
        return "Ks harus berisi karakter ASCII saja"
    if len(ks) != PANJANG_KS:
        return f"Ks harus {PANJANG_KS} karakter (sekarang {len(ks)})"
    if "|" in ks:
        return "Ks tidak boleh mengandung karakter '|'"
    return None


def cek_id(identitas):
    """ID entitas: tidak kosong, ASCII, tanpa "|"."""
    if not identitas:
        return "ID tidak boleh kosong"
    if not identitas.isascii():
        return "ID harus berisi karakter ASCII saja"
    if "|" in identitas:
        return "ID tidak boleh mengandung karakter '|'"
    return None


def _minta(prompt, pemeriksa):
    while True:
        nilai = input(prompt)
        salah = pemeriksa(nilai)
        if salah is None:
            return nilai
        print(f"  ! {salah}")


def minta_key(prompt):
    """Minta master key dari keyboard sampai valid (key tidak di-hardcode)."""
    return _minta(prompt, cek_key)


def minta_ks(prompt):
    """Minta session key manual dari keyboard sampai valid."""
    return _minta(prompt, cek_ks)


def minta_id(prompt):
    """Minta ID entitas dari keyboard sampai valid."""
    return _minta(prompt, cek_id)
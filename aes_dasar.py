"""
aes_dasar: GF(2^8), SBox, key expansion

gmul(a, b)              -> int 0..255
SBOX, INV_SBOX          -> list 256 int
sub_bytes(state)        -> list 16 int baru
inv_sub_bytes(state)    -> list 16 int baru
key_expansion(key)      -> list round key (bytes 16 per ronde)
11 / 13 / 15 buah untuk key 16 / 24 / 32 byte

state = list 16 int, urutan per KOLOM (sama dengan urutan byte input).
Byte ke-i ada di baris r = i % 4, kolom c = i // 4.

    indeks: 0  4  8 12      <- baris 0
            1  5  9 13      <- baris 1
            2  6 10 14      <- baris 2
            3  7 11 15      <- baris 3

"""

POLINOM = 0x11B     # m(x) = x^8 + x^4 + x^3 + x + 1
# Konstanta ronde untuk key expansion: x^(i-1) di GF(2^8).
RCON = [0x01, 0x02, 0x04, 0x08, 0x10, 0x20, 0x40, 0x80, 0x1B, 0x36]

# aritmetika GF(2^8)
# Byte dianggap polinom berderajat < 8 dengan koefisien 0/1
# Penjumlahan = XOR. Perkalian = perkalian polinom lalu direduksi mod m(x)

def xtime(a):
    a <<= 1 #leftshift 1. sama saja kali dengan x polinom
    if a & 0x100: #jika overflow ke bit 8
        a ^= POLINOM #kurangi dengan m(x) (polinom). reduksi modulo polinom AES, pengurangan pakai XOR
    return a & 0xFF #return bit < 8

def gmul(a, b):
    hasil = 0 #siapkan hasil awal 0
    while b: #ulangi selama masih ada bit pada b
        if b & 1: #jika bit paling kanan b menyala
            hasil ^= a #tambahkan a ke hasil dengan XOR
        a = xtime(a) #kalikan a dengan x untuk posisi bit berikutnya
        b >>= 1 #geser b ke kanan untuk memeriksa bit berikutnya
    return hasil #return hasil perkalian di GF(2^8)


def ginv(a):
    # Grup perkalian GF(2^8) berorde 255, jadi a^255 = 1 dan a^-1 = a^254.
    if a == 0: #ginv(0) = 0
        return 0
    hasil = 1 # nilai awal untuk menghitung a^254
    for _ in range(254): #kalikan a sebanyak 254 kali
        hasil = gmul(hasil, a) #perbarui hasil perkalian di GF(2^8)
    return hasil


# S-BOX
def _affine(b):
    """
    Transformasi affine AES pada satu byte (FIPS-197 persamaan 5.1):
        b'_i = b_i ^ b_(i+4) ^ b_(i+5) ^ b_(i+6) ^ b_(i+7) ^ c_i
    indeks bit dihitung modulo 8, dan c = 0x63
    """
    hasil = 0 #init hasil
    for i in range(8): #hitung setiap bit keluaran
        bit = ((b >> i)
               ^ (b >> ((i + 4) % 8))
               ^ (b >> ((i + 5) % 8))
               ^ (b >> ((i + 6) % 8))
               ^ (b >> ((i + 7) % 8))
               ^ (0x63 >> i)) & 1
        hasil |= bit << i #pasang bit keluaran pada posisi ke-i
    return hasil #kembalikan byte hasil transformasi affine


def _bangun_sbox():
    """
    S-Box[x] = affine(invers GF(2^8) dari x)
    Inverse S-Box diperoleh dengan membalik tabel
        SBOX[0x00] = 0x63, SBOX[0x53] = 0xED, INV_SBOX[0xED] = 0x53
    """
    sbox = [_affine(ginv(x)) for x in range(256)] #build S-Box untuk semua nilai byte
    inv_sbox = [0] * 256 #siapkan tabel Inverse S-Box
    for x, y in enumerate(sbox): #key dan value sbox
        inv_sbox[y] = x #diinverse
    return sbox, inv_sbox


SBOX, INV_SBOX = _bangun_sbox()

def sub_bytes(state):
    return [SBOX[b] for b in state] #ganti setiap byte state menggunakan S-Box


def inv_sub_bytes(state):
    return [INV_SBOX[b] for b in state] #ganti setiap byte state menggunakan Inverse S-Box


#KEY EXXPANSION
# word = 4 byte
# Nk = panjang key / 4 (4, 6, 8)
# Nr = Nk + 6 (10, 12, 14).
# butuh 4 * (Nr + 1) word = Nr + 1 round key.

def rot_word(word):
    """[a0, a1, a2, a3] -> [a1, a2, a3, a0]"""
    return word[1:] + word[:1] 


def sub_word(word):
    """Terapkan S-Box ke keempat byte word."""
    return [SBOX[b] for b in word] 

def key_expansion(key, trace=None):
    """
    input : key   -> bytes (len=16/24/32)
            trace -> None, atau fungsi trace(i, word) untuk ditampilkan aes_tool.py
    output: list round key (bytes 16), sebanyak Nr + 1

    FIPS-197 Appendix A.1 (key 2b7e151628aed2a6abf7158809cf4f3c):
        w[4] = a0fafe17, round key terakhir = d014f9a8c9ee2589e13f0cc8b6630ca6
    """
    key = bytes(key) #key dalam bytes
    if len(key) not in (16, 24, 32): #cek len key AES
        raise ValueError(f"Panjang key harus 16, 24, atau 32 byte (sekarang {len(key)})")

    nk = len(key) // 4 #hitung jumlah word dalam key awal
    nr = nk + 6 #jumlah ronde AES berdasarkan panjang key
    w = [list(key[4 * i: 4 * i + 4]) for i in range(nk)] #pecah key awal jadi word berisi 4 byte

    for i in range(nk, 4 * (nr + 1)): 
        temp = list(w[i - 1]) #word sebelumnya
        if i % nk == 0: # batas kelompok key
            temp = sub_word(rot_word(temp)) #rotasi word lalu substitusi tiap byte
            temp[0] ^= RCON[i // nk - 1] #XOR byte pertama dengan konstanta ronde
        elif nk == 8 and i % nk == 4: #(AES-256)
            temp = sub_word(temp) #substitusi tambahan khusus ekspansi key AES-256
        w.append([w[i - nk][j] ^ temp[j] for j in range(4)]) #gabungkan word dari nk posisi sebelumnya dengan temp memakai XOR

    if trace is not None: #tracing on/true
        for i, word in enumerate(w):
            trace(i, bytes(word))

    return [bytes(w[4 * r] + w[4 * r + 1] + w[4 * r + 2] + w[4 * r + 3])
            for r in range(nr + 1)] # 4 word jadi tiap round key
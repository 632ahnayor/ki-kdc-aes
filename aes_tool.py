"""Interactive, offline demonstration tool for the AES implementation."""

from aes import (
    add_round_key,
    decrypt,
    decrypt_block,
    encrypt,
    encrypt_block,
    mix_columns,
    shift_rows,
)
from aes_dasar import key_expansion, sub_bytes


VEKTOR_FIPS = [
    (
        "AES-128",
        bytes.fromhex("000102030405060708090a0b0c0d0e0f"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("69c4e0d86a7b0430d8cdb78070b4c55a"),
    ),
    (
        "AES-192",
        bytes.fromhex("000102030405060708090a0b0c0d0e0f1011121314151617"),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("dda97ca4864cdfe06eaf70a0ec0d7191"),
    ),
    (
        "AES-256",
        bytes.fromhex(
            "000102030405060708090a0b0c0d0e0f"
            "101112131415161718191a1b1c1d1e1f"
        ),
        bytes.fromhex("00112233445566778899aabbccddeeff"),
        bytes.fromhex("8ea2b7ca516745bfeafc49904b496089"),
    ),
]


def tampil_state(state):
    """Print the 16 state bytes as the AES 4x4 column-major matrix."""
    for row in range(4):
        print("  " + " ".join(f"{state[column * 4 + row]:02x}" for column in range(4)))


def _baca_key():
    key = input("Key ASCII (16, 24, atau 32 karakter): ")
    if not key.isascii():
        raise ValueError("Key harus berisi karakter ASCII saja")
    if len(key) not in (16, 24, 32):
        raise ValueError("Key harus 16, 24, atau 32 karakter")
    return key.encode("ascii")


def _tampil_trace_key(key):
    def tampil_word(index, word):
        print(f"  w[{index:02d}] = {word.hex()}")

    print("\nEkspansi key:")
    round_keys = key_expansion(key, trace=tampil_word)
    for round_index, round_key in enumerate(round_keys):
        print(f"  Round key {round_index:02d}: {round_key.hex()}")
    return round_keys


def menu_trace():
    key = _baca_key()
    plaintext = input("Plaintext ASCII (tepat 16 byte): ")
    if not plaintext.isascii() or len(plaintext.encode("ascii")) != 16:
        raise ValueError("Trace blok tunggal memerlukan plaintext ASCII tepat 16 byte")

    round_keys = _tampil_trace_key(key)
    state = list(plaintext.encode("ascii"))
    print("\nState awal:")
    tampil_state(state)

    state = add_round_key(state, round_keys[0])
    print("\nRound 0 - AddRoundKey:")
    tampil_state(state)

    for round_index, round_key in enumerate(round_keys[1:-1], start=1):
        state = sub_bytes(state)
        print(f"\nRound {round_index} - SubBytes:")
        tampil_state(state)
        state = shift_rows(state)
        print(f"Round {round_index} - ShiftRows:")
        tampil_state(state)
        state = mix_columns(state)
        print(f"Round {round_index} - MixColumns:")
        tampil_state(state)
        state = add_round_key(state, round_key)
        print(f"Round {round_index} - AddRoundKey:")
        tampil_state(state)

    state = sub_bytes(state)
    print(f"\nRound {len(round_keys) - 1} - SubBytes:")
    tampil_state(state)
    state = shift_rows(state)
    print(f"Round {len(round_keys) - 1} - ShiftRows:")
    tampil_state(state)
    state = add_round_key(state, round_keys[-1])
    print(f"Round {len(round_keys) - 1} - AddRoundKey (tanpa MixColumns):")
    tampil_state(state)

    ciphertext = encrypt_block(plaintext.encode("ascii"), round_keys)
    if bytes(state) != ciphertext:
        raise RuntimeError("Hasil trace berbeda dari hasil encrypt_block")
    print(f"\nCiphertext: {ciphertext.hex()}")


def menu_uji_fips():
    lulus = True
    for nama, key, plaintext, expected in VEKTOR_FIPS:
        round_keys = key_expansion(key)
        ciphertext = encrypt_block(plaintext, round_keys)
        recovered = decrypt_block(ciphertext, round_keys)
        ok = ciphertext == expected and recovered == plaintext
        lulus = lulus and ok
        status = "LULUS" if ok else "GAGAL"
        print(f"{nama}: {status}")
        if not ok:
            print(f"  expected : {expected.hex()}")
            print(f"  actual   : {ciphertext.hex()}")
            print(f"  recovered: {recovered.hex()}")
    print(f"\nUji FIPS: {'LULUS' if lulus else 'GAGAL'}")


def _menu_encrypt():
    key = _baca_key()
    plaintext = input("Plaintext ASCII: ")
    mode = input("Mode (CBC/ECB) [CBC]: ").strip().upper() or "CBC"
    print(f"Ciphertext hex: {encrypt(key, plaintext, mode)}")


def _menu_decrypt():
    key = _baca_key()
    ciphertext = input("Ciphertext hex: ").strip()
    mode = input("Mode (CBC/ECB) [CBC]: ").strip().upper() or "CBC"
    plaintext = decrypt(key, ciphertext, mode)
    if isinstance(plaintext, bytes):
        print(f"Plaintext bytes (hex): {plaintext.hex()}")
    else:
        print(f"Plaintext ASCII: {plaintext}")


def _menu_mode():
    key = _baca_key()
    plaintext = input("Plaintext ASCII: ")
    for mode in ("ECB", "CBC"):
        ciphertext = encrypt(key, plaintext, mode)
        recovered = decrypt(key, ciphertext, mode)
        print(f"\n{mode}")
        print(f"  Ciphertext hex: {ciphertext}")
        print(f"  Hasil decrypt : {recovered}")
    print("CBC menyertakan IV acak pada 16 byte pertama ciphertext.")


def main():
    print("Demo AES lokal (tidak menggunakan jaringan)")
    actions = {
        "1": _menu_encrypt,
        "2": _menu_decrypt,
        "3": menu_trace,
        "4": _menu_mode,
        "5": menu_uji_fips,
    }
    while True:
        print("\n1. Enkripsi")
        print("2. Dekripsi")
        print("3. Trace proses AES per ronde")
        print("4. Demo ECB dan CBC")
        print("5. Uji vektor FIPS")
        print("0. Keluar")
        pilihan = input("Pilih: ").strip()
        if pilihan == "0":
            return
        action = actions.get(pilihan)
        if action is None:
            print("Pilihan tidak valid.")
            continue
        try:
            action()
        except (ValueError, UnicodeEncodeError) as error:
            print(f"Input/error: {error}")


if __name__ == "__main__":
    main()

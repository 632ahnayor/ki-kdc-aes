from __future__ import annotations

from aes_dasar import gmul, key_expansion, inv_sub_bytes, sub_bytes


# Helper
def _as_bytes(value):
    if isinstance(value, bytes):
        return value
    if isinstance(value, bytearray):
        return bytes(value)
    if isinstance(value, str):
        return value.encode("ascii")
    return bytes(value)


def _key_bytes(key):
    key = _as_bytes(key)
    if len(key) not in (16, 24, 32):
        raise ValueError(f"Panjang key harus 16, 24, atau 32 byte (sekarang {len(key)})")
    return key


def _state_from_block(block):
    block = _as_bytes(block)
    if len(block) != 16:
        raise ValueError(f"Blok harus 16 byte (sekarang {len(block)})")
    return list(block)


def _block_from_state(state):
    return bytes(state)


# Ronde
def shift_rows(state):
    state_new = state.copy()
    for i in range(len(state)):
        row = i % 4
        index_new = (i + (row * 4)) % 16
        state_new[i] = state[index_new]
    return state_new


def inv_shift_rows(state):
    state_new = state.copy()
    for i in range(len(state)):
        row = i % 4
        index_new = (i - (row * 4)) % 16
        state_new[i] = state[index_new]
    return state_new


def mix_columns(state):
    state_new = state.copy()
    for i in range(0, 16, 4):
        a0, a1, a2, a3 = state[i:i + 4]

        state_new[i] = gmul(a0, 0x2) ^ gmul(a1, 0x3) ^ a2 ^ a3
        state_new[i + 1] = a0 ^ gmul(a1, 0x2) ^ gmul(a2, 0x3) ^ a3
        state_new[i + 2] = a0 ^ a1 ^ gmul(a2, 0x2) ^ gmul(a3, 0x3)
        state_new[i + 3] = gmul(a0, 0x3) ^ a1 ^ a2 ^ gmul(a3, 0x2)

    return state_new


def inv_mix_columns(state):
    state_new = state.copy()
    for i in range(0, 16, 4):
        a0, a1, a2, a3 = state[i:i + 4]

        state_new[i] = gmul(a0, 0xE) ^ gmul(a1, 0xB) ^ gmul(a2, 0xD) ^ gmul(a3, 0x9)
        state_new[i + 1] = gmul(a0, 0x9) ^ gmul(a1, 0xE) ^ gmul(a2, 0xB) ^ gmul(a3, 0xD)
        state_new[i + 2] = gmul(a0, 0xD) ^ gmul(a1, 0x9) ^ gmul(a2, 0xE) ^ gmul(a3, 0xB)
        state_new[i + 3] = gmul(a0, 0xB) ^ gmul(a1, 0xD) ^ gmul(a2, 0x9) ^ gmul(a3, 0xE)

    return state_new


def add_round_key(state, rk):
    return [byte ^ round_key for byte, round_key in zip(state, rk)]


# Blok
def encrypt_block(blok, round_keys, trace=None):
    state = _state_from_block(blok)
    state = add_round_key(state, round_keys[0])

    for round_index in range(1, len(round_keys) - 1):
        state = sub_bytes(state)
        state = shift_rows(state)
        state = mix_columns(state)
        state = add_round_key(state, round_keys[round_index])
        if trace is not None:
            trace(round_index, _block_from_state(state))

    state = sub_bytes(state)
    state = shift_rows(state)
    state = add_round_key(state, round_keys[-1])
    if trace is not None:
        trace(len(round_keys) - 1, _block_from_state(state))

    return _block_from_state(state)


def decrypt_block(blok, round_keys, trace=None):
    state = _state_from_block(blok)
    state = add_round_key(state, round_keys[-1])

    for round_index in range(len(round_keys) - 2, 0, -1):
        state = inv_shift_rows(state)
        state = inv_sub_bytes(state)
        state = add_round_key(state, round_keys[round_index])
        state = inv_mix_columns(state)
        if trace is not None:
            trace(round_index, _block_from_state(state))

    state = inv_shift_rows(state)
    state = inv_sub_bytes(state)
    state = add_round_key(state, round_keys[0])
    if trace is not None:
        trace(0, _block_from_state(state))

    return _block_from_state(state)


# Padding
def pkcs7_pad(data):
    data = _as_bytes(data)
    pad_len = 16 - (len(data) % 16)
    return data + bytes([pad_len]) * pad_len


def pkcs7_unpad(data):
    data = _as_bytes(data)
    if not data:
        raise ValueError("Data kosong")
    pad_len = data[-1]
    if pad_len < 1 or pad_len > 16 or data[-pad_len:] != bytes([pad_len]) * pad_len:
        raise ValueError("Padding tidak valid")
    return data[:-pad_len]


# Mode operasi
def encrypt_ecb(data, key):
    key = _key_bytes(key)
    data = pkcs7_pad(_as_bytes(data))
    round_keys = key_expansion(key)
    return b"".join(encrypt_block(data[i:i + 16], round_keys) for i in range(0, len(data), 16))


def decrypt_ecb(data, key):
    key = _key_bytes(key)
    data = _as_bytes(data)
    if len(data) % 16 != 0:
        raise ValueError("Panjang data harus kelipatan 16 byte")
    round_keys = key_expansion(key)
    plain = b"".join(decrypt_block(data[i:i + 16], round_keys) for i in range(0, len(data), 16))
    return pkcs7_unpad(plain)


def encrypt_cbc(data, key):
    key = _key_bytes(key)
    data = pkcs7_pad(_as_bytes(data))
    iv = bytearray(16)
    import os
    iv = os.urandom(16)
    prev = iv
    cipher = bytearray()
    cipher.extend(iv)
    round_keys = key_expansion(key)
    for i in range(0, len(data), 16):
        block = list(data[i:i + 16])
        block = [b ^ prev[j] for j, b in enumerate(block)]
        encrypted = encrypt_block(bytes(block), round_keys)
        cipher.extend(encrypted)
        prev = encrypted
    return bytes(cipher)


def decrypt_cbc(data, key):
    key = _key_bytes(key)
    data = _as_bytes(data)
    if len(data) < 16 or len(data) % 16 != 0:
        raise ValueError("Panjang data CBC harus kelipatan 16 byte dengan IV 16 byte")
    iv = data[:16]
    content = data[16:]
    round_keys = key_expansion(key)
    out = bytearray()
    prev = iv
    for i in range(0, len(content), 16):
        block = content[i:i + 16]
        decrypted = decrypt_block(block, round_keys)
        out.extend([d ^ prev[j] for j, d in enumerate(decrypted)])
        prev = block
    return pkcs7_unpad(bytes(out))


def encrypt(key, plaintext, mode="CBC"):
    key = _key_bytes(key)
    data = _as_bytes(plaintext)
    mode = mode.upper()
    if mode == "ECB":
        ciphertext = encrypt_ecb(data, key)
    elif mode == "CBC":
        ciphertext = encrypt_cbc(data, key)
    else:
        raise ValueError(f"Mode tidak dikenal: {mode}")
    return ciphertext.hex()


def decrypt(key, ciphertext, mode="CBC"):
    key = _key_bytes(key)
    if isinstance(ciphertext, str):
        ciphertext = bytes.fromhex(ciphertext)
    else:
        ciphertext = _as_bytes(ciphertext)
    mode = mode.upper()
    if mode == "ECB":
        plaintext = decrypt_ecb(ciphertext, key)
    elif mode == "CBC":
        plaintext = decrypt_cbc(ciphertext, key)
    else:
        raise ValueError(f"Mode tidak dikenal: {mode}")
    try:
        return plaintext.decode("ascii")
    except UnicodeDecodeError:
        return plaintext

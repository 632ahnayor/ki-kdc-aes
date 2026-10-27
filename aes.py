from aes_dasar import gmul, sub_bytes, inv_sub_bytes, key_expansion

# Ronde
def shift_rows(state):
    # state_new = [state[i + 4*(i%2)] for i, _ in enumerate(state)]
    state_new = state.copy()
    for i, _ in enumerate(state):
        row = i % 4
        index_new = (i + (row * 4)) % 16 # plus goes left (trust), and mod 16 circular
        state_new[i] = state[index_new]
    return state_new

def inv_shift_rows(state):
    state_new = state.copy()
    for i, _ in enumerate(state):
        row = i % 4
        index_new = (i - (row * 4)) % 16
        state_new[i] = state[index_new]
    return state_new

def mix_columns(state):
    state_new = state.copy()
    for i in range(0, 16, 4):
        a0, a1, a2, a3 = state[i:i + 4]
        
        state_new[i]   = (gmul(a0, 0x2) ^ gmul(a1, 0x3) ^ a2 ^ a3)
        state_new[i+1] = (a0 ^ gmul(a1, 0x2) ^ gmul(a2, 0x3) ^ a3)
        state_new[i+2] = (a0 ^ a1 ^ gmul(a2, 0x2) ^ gmul(a3, 0x3))
        state_new[i+3] = (gmul(a0, 0x3) ^ a1 ^ a2 ^ gmul(a3, 0x2))
        
    return state_new

def inv_mix_columns(state):
    state_new = state.copy()
    for i in range(0, 16, 4):
        a0, a1, a2, a3 = state[i:i + 4]
        
        state_new[i]   = (gmul(a0, 0xE) ^ gmul(a1, 0xB) ^ gmul(a2, 0xD) ^ gmul(a3, 0x9))
        state_new[i+1] = (gmul(a0, 0x9) ^ gmul(a1, 0xE) ^ gmul(a2, 0xB) ^ gmul(a3, 0xD))
        state_new[i+2] = (gmul(a0, 0xD) ^ gmul(a1, 0x9) ^ gmul(a2, 0xE) ^ gmul(a3, 0xB))
        state_new[i+3] = (gmul(a0, 0xB) ^ gmul(a1, 0xD) ^ gmul(a2, 0x9) ^ gmul(a3, 0xE))
        
    return state_new

def add_round_key(state, rk):
    state_new = state.copy()
    for i, _ in enumerate(state):
        state_new[i] = state[i] ^ rk[i]
    return state_new

# Blok
def encrypt_block(blok, round_keys, trace=None):
    pass

def decrypt_block(blok, round_keys, trace=None):
    pass

# Padding
def pkcs7_pad(data):
    pass

def pkcs7_unpad(data):
    pass

# Mode operasi
def encrypt_ecb(data, key):
    pass

def decrypt_ecb(data, key):
    pass

def encrypt_bcb(data, key):
    pass

def decrypt_bcb(data, key):
    pass

# Fungsi akhir
def encrypt(key, plaintext, mode="CBC"): # ASCII -> hex
    pass

def encrypt(key, plaintext, mode="CBC"): # hex -> ASCII
    pass
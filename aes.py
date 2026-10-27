from aes_dasar import gmul, sub_bytes, inv_sub_bytes, key_expansion

# Ronde
def shift_rows(state):
    # state_new = [state[i + 4*(i%2)] for i, _ in enumerate(state)]
    state_new = [0] * 16
    for i, _ in enumerate(state):
        row = i % 4
        index_new = (i + (row * 4)) % 16 # plus goes left (trust), and mod 16 circular
        state_new[i] = state[index_new]
    return state_new

def inv_shift_rows(state):
    state_new = [0] * 16
    for i, _ in enumerate(state):
        row = i % 4
        index_new = (i - (row * 4)) % 16
        state_new[i] = state[index_new]
    return state_new

def mix_columns(state):
    pass

def inv_mix_columns(state):
    pass

def add_round_key(state, rk):
    pass

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
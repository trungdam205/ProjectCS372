"""Demo: is_valid_key() and safe 3DES brute-force loop.

Run: python3 demo_is_valid_key.py
"""
from Crypto.Cipher import DES3
from crypto_algorithms import (
    is_valid_key,
    triple_des_encrypt,
    triple_des_decrypt,
    generate_3des_key,
)

# 1) Khoa binh thuong, sinh dung cach (co adjust_key_parity) -> hop le
good_key = generate_3des_key()
print("good_key hop le?", is_valid_key(good_key, DES3))  # True

# 2) Khoa suy bien: K1 == K2 (kieu se gap khi zero-pad brute-force)
bad_key = b"\x00" * 8 + b"\x00" * 8 + b"\x05" * 8
print("bad_key hop le?", is_valid_key(bad_key, DES3))  # False

# 3) Chung minh: neu goi thang DES3.new() voi bad_key se raise ValueError
try:
    DES3.new(bad_key, DES3.MODE_CBC)
    print("khong raise (khong mong doi)")
except ValueError as e:
    print("DES3.new() raise nhu du doan:", e)

# 4) Mo phong mini brute-force: 1 ciphertext co dinh, thu vai khoa trong do co khoa suy bien
plaintext = b"secret message for brute-force demo"
result = triple_des_encrypt(plaintext, good_key)
ciphertext, iv = result.ciphertext, result.iv

candidate_keys = [
    bad_key,                                   # se bi is_valid_key loc, khong goi decrypt
    b"\x00" * 8 + b"\x00" * 8 + b"\x00" * 8,   # suy bien khac, cung bi loc
    good_key,                                  # khoa dung -> giai ma thanh cong
]

found = None
for k in candidate_keys:
    if not is_valid_key(k, DES3):
        continue  # bo qua, khong crash
    try:
        recovered = triple_des_decrypt(ciphertext, k, iv)
    except ValueError:
        continue  # padding sai -> khoa sai
    if recovered == plaintext:
        found = k
        break

print("Tim duoc khoa dung?", found == good_key)
import sys

sys.path.append("../smutil")

import SM4Util
from gmssl import *


data = b"asdf"
key = rand_bytes(SM4_KEY_SIZE)
iv_cbc = rand_bytes(SM4_CBC_IV_SIZE)
iv_ctr = rand_bytes(SM4_CTR_IV_SIZE)
iv_gcm = rand_bytes(SM4_GCM_DEFAULT_IV_SIZE)
aad = b'Additional auth-data'
taglen = SM4_GCM_DEFAULT_TAG_SIZE

# no mode
print('-' * 100)
print("SM4_KEY_SIZE = ", SM4_KEY_SIZE)
print("SM4_BLOCK_SIZE = ", SM4_BLOCK_SIZE)
print("")

plaintext = rand_bytes(SM4_BLOCK_SIZE)
c = SM4Util.enc(key, plaintext)
m = SM4Util.dec(key, c)
assert plaintext == m
print("plaintext = ", plaintext.hex())
print("key = ", key.hex())
print("ciphertext = ", c.hex())
print("decrypted message = ", m.hex())

# cbc mode
print('-' * 100)
print("SM4_CBC_IV_SIZE =", SM4_CBC_IV_SIZE)
print("")

c = SM4Util.CBCEnc(key, iv_cbc, data)
m = SM4Util.CBCDec(key, iv_cbc, c)
assert data == m
print("plaintext = ", data.hex())
print("key = ", key.hex())
print("iv = ", iv_cbc.hex())
print("ciphertext = ", c.hex())
print("decrypted message = ", m.hex())

# ctr mode
print('-' * 100)
print("SM4_CTR_IV_SIZE =", SM4_CTR_IV_SIZE)
print("")

c = SM4Util.CTREnc(key, iv_ctr, data)
m = SM4Util.CTRDec(key, iv_ctr, c)
assert data == m
print("plaintext = ", data.hex())
print("key = ", key.hex())
print("iv of ctr = ", iv_ctr.hex())
print("ciphertext = ", c.hex())
print("decrypted message = ", m.hex())

# gcm mode
print('-' * 100)
print("SM4_GCM_MIN_IV_SIZE = ", SM4_GCM_MIN_IV_SIZE)
print("SM4_GCM_MAX_IV_SIZE = ", SM4_GCM_MAX_IV_SIZE)
print("SM4_GCM_DEFAULT_IV_SIZE = ", SM4_GCM_DEFAULT_IV_SIZE)
print("SM4_GCM_DEFAULT_TAG_SIZE = ", SM4_GCM_DEFAULT_TAG_SIZE)
print("SM4_GCM_MAX_TAG_SIZE = ", SM4_GCM_MAX_TAG_SIZE)
print("")

c = SM4Util.GCMEnc(key, iv_gcm, aad, taglen, data)
m = SM4Util.GCMDec(key, iv_gcm, aad, c)
assert data == m
print("plaintext = ", data.hex())
print("key = ", key.hex())
print("iv of gcm = ", iv_gcm.hex())
print("ciphertext = ", c.hex())
print("decrypted message = ", m.hex())
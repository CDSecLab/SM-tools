import sys

sys.path.append("../smutil")

import SM3Util
from gmssl import *

data = b'asdf'
key = rand_bytes(16)
passwd = 'password'
salt = rand_bytes(SM3_PBKDF2_DEFAULT_SALT_SIZE)
iterator = SM3_PBKDF2_MIN_ITER
keylen = 32

# hash
print('-' * 100)
print("SM3_DIGEST_SIZE =", SM3_DIGEST_SIZE)
print()

mac = SM3Util.hash(data)
print("data = ", data.hex())
print("hash = ", mac.hex())

# hmac
print('-' * 100)
print("SM3_HMAC_MIN_KEY_SIZE =", SM3_HMAC_MIN_KEY_SIZE)
print("SM3_HMAC_MAX_KEY_SIZE =", SM3_HMAC_MAX_KEY_SIZE)
print("SM3_HMAC_SIZE =", SM3_HMAC_SIZE)
print()

tag = SM3Util.hmac(key, data)
print("key = ", key.hex())
print("data = ", data.hex())
print("hmac tag = ", tag.hex())

# kdf
print('-' * 100)
print("SM3_PBKDF2_MIN_ITER =", SM3_PBKDF2_MIN_ITER)
print("SM3_PBKDF2_MAX_ITER =", SM3_PBKDF2_MAX_ITER)
print("SM3_PBKDF2_MAX_SALT_SIZE =", SM3_PBKDF2_MAX_SALT_SIZE)
print("SM3_PBKDF2_DEFAULT_SALT_SIZE =", SM3_PBKDF2_DEFAULT_SALT_SIZE)
print("SM3_PBKDF2_MAX_KEY_SIZE =", SM3_PBKDF2_MAX_KEY_SIZE)
print()

keyOfKDF = SM3Util.kdf(passwd, salt, iterator, keylen)
print("password = ", passwd)
print("salt = ", salt.hex())
print("iterator times = ", iterator)
print("key = ", keyOfKDF.hex())
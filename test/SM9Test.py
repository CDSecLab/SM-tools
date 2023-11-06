import sys

sys.path.append("../smutil")

import SM9Util
from gmssl import *


data = rand_bytes(SM4_KEY_SIZE + SM3_HMAC_MIN_KEY_SIZE)
receiver_id = 'Alice'
passwd = 'password'
message = b"Message to be signed"

# enc/dec
print('-' * 100)
print("SM9_MAX_ID_SIZE = ", SM9_MAX_ID_SIZE)
print("SM9_MAX_PLAINTEXT_SIZE = ", SM9_MAX_PLAINTEXT_SIZE)
print("SM9_MAX_CIPHERTEXT_SIZE = ", SM9_MAX_CIPHERTEXT_SIZE)
print("")

SM9Util.genEncKeyPair(passwd)
masterSK = SM9Util.importEncMSK(passwd)
masterPK = SM9Util.importEncMPK()
assert masterSK._has_private_key == True
assert masterSK._has_public_key == True
assert masterPK._has_private_key == False
assert masterPK._has_public_key == True

c = SM9Util.enc(masterPK, data, receiver_id)
m = SM9Util.dec(masterSK, c, receiver_id)
assert data == m
print("data = ", data.hex())
print("ciphertext = ", c.hex())
print("decrypted = ", m.hex())

# sign/verify
print('-' * 100)
print("SM9_MAX_ID_SIZE = ", SM9_MAX_ID_SIZE)
print("SM9_SIGNATURE_SIZE = ", SM9_SIGNATURE_SIZE)
print("")

SM9Util.genSignKeyPair(passwd)
mSK = SM9Util.importSignMSK(passwd)
mPK = SM9Util.importSignMPK()
assert mSK._has_private_key == True
assert mSK._has_public_key == True
assert mPK._has_private_key == False
assert mPK._has_public_key == True

sig = SM9Util.sign(mSK, receiver_id, message)
assert SM9Util.verify(mPK, receiver_id, message, sig) == True
print("sigature = ", sig.hex())
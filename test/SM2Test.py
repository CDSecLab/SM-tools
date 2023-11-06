import sys

sys.path.append("../smutil")

import SM2Util, SM3Util
from gmssl import *

data = b'asdf'
passwd = 'password'
dgst = SM3Util.hash(data)

# key
SM2Util.genKeyPair(passwd)
privateKey = SM2Util.importPrivateKey(passwd)
publicKey = SM2Util.importPublicKey()
assert privateKey.has_private_key() == True
assert privateKey.has_public_key() == True
assert publicKey.has_private_key() == False
assert publicKey.has_public_key() == True
print("private key = ", privateKey)
print("public key = ", publicKey)

# sign
print('-' * 100)
print("SM2_DEFAULT_ID =", SM2_DEFAULT_ID)
print("SM2_MAX_SIGNATURE_SIZE =", SM2_MAX_SIGNATURE_SIZE)
print("")

# - with no id
sig1 = SM2Util.sign(privateKey, dgst)
assert SM2Util.verify(publicKey, sig1, dgst) == True

# - with id
id = SM2Util.getId(publicKey)
sig2 = SM2Util.signWithId(privateKey, id, dgst)
assert SM2Util.verifyWithId(publicKey, id, sig2, dgst) == True

print("digest to sign = ", dgst.hex())
print("sign without id = ", sig1.hex())
print("generate id from pk = ", id)
print("sign with id = ", sig2.hex())

# pk enc/dec
print('-' * 100)
print("SM2_MIN_PLAINTEXT_SIZE = ", SM2_MIN_PLAINTEXT_SIZE)
print("SM2_MAX_PLAINTEXT_SIZE = ", SM2_MAX_PLAINTEXT_SIZE)
print("SM2_MIN_CIPHERTEXT_SIZE = ", SM2_MIN_CIPHERTEXT_SIZE)
print("SM2_MAX_CIPHERTEXT_SIZE = ", SM2_MAX_CIPHERTEXT_SIZE)
print("")

c = SM2Util.pkEnc(publicKey, data)
m = SM2Util.pkDec(privateKey, c)
assert m == data
print("data = ", data.hex())
print("ciphertext = ", c.hex())
print("decrypted = ", m.hex())

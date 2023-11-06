from gmssl import *

import SM3Util

"""
# sm2 = Public Key Cryptography
"""


# key

def genKeyPair(passwd: str):
    sm2 = Sm2Key()
    sm2.generate_key()
    sm2.export_public_key_info_pem('pk.pem')
    sm2.export_encrypted_private_key_info_pem('sk.pem', passwd)


def importPrivateKey(passwd: str) -> Sm2Key:
    key = Sm2Key()
    key.import_encrypted_private_key_info_pem('sk.pem', passwd)
    return key


def importPublicKey() -> Sm2Key:
    key = Sm2Key()
    key.import_public_key_info_pem('pk.pem')
    return key


# Sign
def getId(publicKey: Sm2Key) -> str:
    return publicKey.compute_z(SM2_DEFAULT_ID).hex()


def signWithId(privateKey: Sm2Key, id: str, dgst: bytes) -> bytes:
    Signer = Sm2Signature(privateKey, id, DO_SIGN)
    Signer.update(dgst)
    return Signer.sign()


def verifyWithId(publicKey: Sm2Key, id: str, sig: bytes, dgst: bytes) -> bool:
    verifier = Sm2Signature(publicKey, id, DO_VERIFY)
    verifier.update(dgst)
    return verifier.verify(sig)


def sign(privateKey: Sm2Key, dgst: bytes):
    Signer = Sm2Signature(privateKey, SM2_DEFAULT_ID, DO_SIGN)
    Signer.update(dgst)
    return Signer.sign()


def verify(publicKey: Sm2Key, sig: bytes, dgst: bytes) -> bool:
    verifier = Sm2Signature(publicKey, SM2_DEFAULT_ID, DO_VERIFY)
    verifier.update(dgst)
    return verifier.verify(sig)


# pk encrypt
def pkEnc(publicKey: Sm2Key, data: bytes) -> bytes:
    return publicKey.encrypt(data)


def pkDec(privateKey: Sm2Key, cypher: bytes) -> bytes:
    return privateKey.decrypt(cypher)

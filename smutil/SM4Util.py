from gmssl import *

"""
sm4 = block cipher
- no mode = 需要填充到分组长度
- cbc
- ctr
- gcm
"""


# no mode
def enc(key: bytes, data: bytes) -> bytes:
    sm4_enc = Sm4(key, DO_ENCRYPT)
    return sm4_enc.encrypt(data)


def dec(key: bytes, cipher: bytes) -> bytes:
    sm4_dec = Sm4(key, DO_DECRYPT)
    return sm4_dec.encrypt(cipher)


# CBC mode
def CBCEnc(key: bytes, iv: bytes, data: bytes) -> bytes:
    sm4_enc = Sm4Cbc(key, iv, DO_ENCRYPT)
    c = sm4_enc.update(data)
    c += sm4_enc.finish()
    return c


def CBCDec(key: bytes, iv: bytes, cipher: bytes) -> bytes:
    sm4_dec = Sm4Cbc(key, iv, DO_DECRYPT)
    m = sm4_dec.update(cipher)
    m += sm4_dec.finish()
    return m


# CTR mode
def CTREnc(key: bytes, iv: bytes, data: bytes) -> bytes:
    sm4_enc = Sm4Ctr(key, iv)
    c = sm4_enc.update(data)
    c += sm4_enc.finish()
    return c


def CTRDec(key: bytes, iv: bytes, cipher: bytes) -> bytes:
    sm4_dec = Sm4Ctr(key, iv)
    m = sm4_dec.update(cipher)
    m += sm4_dec.finish()
    return m


# GCM mode 认证加密
# aad = Additional Authenticated Data
def GCMEnc(key: bytes, iv: bytes, aad: bytes, taglen: int, data: bytes) -> bytes:
    sm4_enc = Sm4Gcm(key, iv, aad, taglen, DO_ENCRYPT)
    c = sm4_enc.update(data)
    c += sm4_enc.finish()
    return c


def GCMDec(key: bytes, iv: bytes, aad: bytes, cipher: bytes) -> bytes:
    sm4_dec = Sm4Gcm(key, iv, aad, 16, DO_DECRYPT)
    m = sm4_dec.update(cipher)
    m += sm4_dec.finish()
    return m


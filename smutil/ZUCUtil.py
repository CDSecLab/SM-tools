from gmssl import *

"""
Zuc: steam cypher
"""


def ZucEnc(key: bytes, iv: bytes, data: bytes) -> bytes:
    zuc = Zuc(key, iv)
    c = zuc.update(data)
    c += zuc.finish()
    return c


def ZucDec(key: bytes, iv: bytes, cypher: bytes) -> bytes:
    zuc = Zuc(key, iv)
    m = zuc.update(cypher)
    m += zuc.finish()
    return m

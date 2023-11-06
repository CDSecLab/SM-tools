from gmssl import *

"""
sm3 = hash & hmac & pbkdf2
"""


def hash(data: bytes) -> bytes:
    sm3 = Sm3()
    sm3.update(data)
    return sm3.digest()


def hmac(key: bytes, data: bytes) -> bytes:
    sm3 = Sm3Hmac(key)
    sm3.update(data)
    return sm3.generate_mac()


def kdf(passwd: str, salt: bytes, iterator: int, keylen: int):
    return sm3_pbkdf2(passwd, salt, iterator, keylen)


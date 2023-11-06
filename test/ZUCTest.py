import sys

sys.path.append("../smutil")

import ZUCUtil
from gmssl import *

if __name__ == "__main__":
    data = b'asdf'
    key = rand_bytes(ZUC_KEY_SIZE)
    iv = rand_bytes(ZUC_IV_SIZE)

    print("ZUC_KEY_SIZE = ", ZUC_KEY_SIZE)
    print("ZUC_IV_SIZE = ", ZUC_IV_SIZE)
    print("")

    c = ZUCUtil.ZucEnc(key, iv, data)
    m = ZUCUtil.ZucDec(key, iv, c)
    assert m == data
    print("key =", key.hex())
    print("iv =", iv.hex())
    print("plaintext =", data.hex())
    print("ciphertext = ", c.hex())
    print("decrypted =", m.hex())

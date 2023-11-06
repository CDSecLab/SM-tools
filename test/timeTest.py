import sys
sys.path.append("../smutil")

import SM2Util, SM3Util, SM4Util, SM9Util, ZUCUtil

from gmssl import *
from timeit import timeit


def testSM2Util(times):
    data = b'asdf'
    passwd = 'password'
    dgst = SM3Util.hash(data)

    t1 = timeit(lambda: SM2Util.genKeyPair(passwd), number=1)
    print("gen. key pair:", t1, "s")
    privateKey = SM2Util.importPrivateKey(passwd)
    publicKey = SM2Util.importPublicKey()

    sig = SM2Util.sign(privateKey, dgst)
    c = SM2Util.pkEnc(publicKey, data)
    m = SM2Util.pkDec(privateKey, c)

    t2 = timeit(lambda: SM2Util.sign(privateKey, dgst), number=times)
    print("sign:", t2 / times, "s")

    t3 = timeit(lambda: SM2Util.verify(publicKey, sig, dgst), number=times)
    print("verify:", t3 / times, "s")

    t4 = timeit(lambda: SM2Util.pkEnc(publicKey, data), number=times)
    print("enc:", t4 / times, "s")

    t5 = timeit(lambda: SM2Util.pkDec(privateKey, c), number=times)
    print("dec:", t5 / times, "s")


def testSM3Util(times):
    data = b'asdf'
    key = rand_bytes(16)

    t1 = timeit(lambda: SM3Util.hash(data), number=times)
    print("hash:", t1 / times, "s")

    t2 = timeit(lambda: SM3Util.hmac(key, data), number=times)
    print("hmac:", t2 / times, "s")


def testSM4Util(times):
    data = b"asdf"
    key = rand_bytes(SM4_KEY_SIZE)
    iv_cbc = rand_bytes(SM4_CBC_IV_SIZE)
    iv_ctr = rand_bytes(SM4_CTR_IV_SIZE)
    iv_gcm = rand_bytes(SM4_GCM_DEFAULT_IV_SIZE)
    aad = b'Additional auth-data'
    taglen = SM4_GCM_DEFAULT_TAG_SIZE

    c = SM4Util.CBCEnc(key, iv_cbc, data)
    t1 = timeit(lambda: SM4Util.CBCEnc(key, iv_cbc, data), number=times)
    print("cbc enc:", t1 / times, "s")
    t2 = timeit(lambda: SM4Util.CBCDec(key, iv_cbc, c), number=times)
    print("cbc dec:", t2 / times, "s")

    c = SM4Util.CTREnc(key, iv_ctr, data)
    t3 = timeit(lambda: SM4Util.CTREnc(key, iv_ctr, data), number=times)
    print("ctr enc:", t3 / times, "s")
    t4 = timeit(lambda: SM4Util.CTRDec(key, iv_ctr, c), number=times)
    print("ctr dec:", t4 / times, "s")

    c = SM4Util.GCMEnc(key, iv_gcm, aad, taglen, data)
    t5 = timeit(lambda: SM4Util.GCMEnc(key, iv_gcm, aad, taglen, data), number=times)
    print("gcm enc:", t5 / times, "s")
    t6 = timeit(lambda: SM4Util.GCMDec(key, iv_gcm, aad, c), number=times)
    print("gcm dec:", t6 / times, "s")


def testSM9Util():
    data = rand_bytes(SM4_KEY_SIZE + SM3_HMAC_MIN_KEY_SIZE)
    receiver_id = 'Alice'
    passwd = 'password'
    message = b"Message to be signed"

    t1 = timeit(lambda: SM9Util.genEncKeyPair(passwd), number=1)
    print("gen. enc. key pair:", t1, "s")
    masterSK = SM9Util.importEncMSK(passwd)
    masterPK = SM9Util.importEncMPK()

    c = SM9Util.enc(masterPK, data, receiver_id)
    t2 = timeit(lambda: SM9Util.enc(masterPK, data, receiver_id), number=1)
    print("enc:", t2, "s")
    t3 = timeit(lambda: SM9Util.dec(masterSK, c, receiver_id), number=1)
    print("dec:", t3, "s")

    t4 = timeit(lambda: SM9Util.genSignKeyPair(passwd), number=1)
    print("gen. sig. key pair:", t4, "s")
    mSK = SM9Util.importSignMSK(passwd)
    mPK = SM9Util.importSignMPK()

    sig = SM9Util.sign(mSK, receiver_id, message)
    t5 = timeit(lambda: SM9Util.sign(mSK, receiver_id, message), number=1)
    print("sig:", t5, "s")
    t6 = timeit(lambda: SM9Util.verify(mPK, receiver_id, message, sig), number=1)
    print("verify:", t6, "s")


def testZUCUtil(times):
    data = b'asdf'
    key = rand_bytes(ZUC_KEY_SIZE)
    iv = rand_bytes(ZUC_IV_SIZE)

    c = ZUCUtil.ZucEnc(key, iv, data)
    t1 = timeit(lambda: ZUCUtil.ZucEnc(key, iv, data), number=times)
    print("ZUC enc:", t1 / times, "s")
    t2 = timeit(lambda: ZUCUtil.ZucDec(key, iv, c), number=times)
    print("ZUC dec:", t2 / times, "s")


if __name__ == "__main__":
    times = 100  # 进行times次运算, 求平均值

    print('-' * 50)
    testSM2Util(times)

    print('-' * 50)
    testSM3Util(times)

    print('-' * 50)
    testSM4Util(times)

    print('-' * 50)
    testSM9Util()

    print('-' * 50)
    testZUCUtil(times)

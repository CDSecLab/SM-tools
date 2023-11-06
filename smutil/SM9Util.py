from gmssl import *


# enc/dec
def genEncKeyPair(passwd: str):
    key = Sm9EncMasterKey()
    key.generate_master_key()
    key.export_encrypted_master_key_info_pem('enc_msk.pem', passwd)
    key.export_public_master_key_pem('enc_mpk.pem')


def importEncMSK(passwd: str) -> Sm9EncMasterKey:
    masterSK = Sm9EncMasterKey()
    masterSK.import_encrypted_master_key_info_pem('enc_msk.pem', passwd)
    return masterSK


def importEncMPK() -> Sm9EncMasterKey:
    masterPK = Sm9EncMasterKey()
    masterPK.import_public_master_key_pem('enc_mpk.pem')
    return masterPK


def enc(masterPK: Sm9EncMasterKey, data: bytes, id: str) -> bytes:
    return masterPK.encrypt(data, id)


def dec(masterSK: Sm9EncMasterKey, cipher: bytes, id: str) -> bytes:
    receiverKey = masterSK.extract_key(id)
    return receiverKey.decrypt(cipher)


# sign/verify
def genSignKeyPair(passwd: str):
    key = Sm9SignMasterKey()
    key.generate_master_key()
    key.export_encrypted_master_key_info_pem('sign_msk.pem', passwd)
    key.export_public_master_key_pem('sign_mpk.pem')


def importSignMSK(passwd: str) -> Sm9SignMasterKey:
    masterSK = Sm9SignMasterKey()
    masterSK.import_encrypted_master_key_info_pem('sign_msk.pem', passwd)
    return masterSK


def importSignMPK() -> Sm9SignMasterKey:
    masterSK = Sm9SignMasterKey()
    masterSK.import_public_master_key_pem('sign_mpk.pem')
    return masterSK


def sign(masterSK: Sm9SignMasterKey, id: str, message: bytes) -> bytes:
    key = masterSK.extract_key(id)
    signer = Sm9Signature(DO_SIGN)
    signer.update(message)
    return signer.sign(key)


def verify(masterPK: Sm9SignMasterKey, id: str, message: bytes, sig: bytes) -> bool:
    verifier = Sm9Signature(DO_VERIFY)
    verifier.update(message)
    return verifier.verify(sig, masterPK, id)

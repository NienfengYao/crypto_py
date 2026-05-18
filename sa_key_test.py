#!/usr/bin/python3
# -*- coding: utf-8 -*-
from binascii import hexlify, unhexlify
try:
    from Crypto.Hash import CMAC
    from Crypto.Cipher import AES
    from Crypto.Util.Padding import pad
except ModuleNotFoundError:
    from Cryptodome.Hash import CMAC
    from Cryptodome.Cipher import AES
    from Cryptodome.Util.Padding import pad


def test_SA_MAC_KEY():
    """
    MAC_GEN_KEY:       Asset Number=0x6, Policy = 0x0022280D
    MAC_VERIFY_KEY:    Asset Number=0x5, Policy = 0x0022280B
    Type: AES-CMAC-256
    """
    key = unhexlify('7c1b8a7231e0e462dee101851fa7bad4df7295830ed88066deeb5eeff0e6d371')
    # key = unhexlify('05ca8ad4f2d71c61e69d0776fd2e9f28553aea976b08b3dd13d4528940c5a8e2') # ATE
    msg = unhexlify('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    mac = unhexlify('5f49359c808e94bc76ef1e7141a95c10')
    
    print("\n%s()" % test_SA_MAC_KEY.__name__)
    cmac = CMAC.new(key, ciphermod=AES)
    cmac.update(msg)
    print("\tAES-CMAC Generate:")
    print("\t\t", cmac.digest().hex())

    # Verify
    try:
        print("\tAES-CMAC Verify:")
        cmac.verify(mac)
        print("\t\tThe message '%s' is authentic [PASS]" % msg.hex())
    except ValueError:
        print("\t\tThe message or the key is wrong [FAIL]")


def test_SA_COMM_ICV_KEY():
    """
    COMM_ICV_KEY:       Asset Number=0x4, Policy = 0x08232809
    Type: AES-CBC-256
    """
    print("\n%s()" % test_SA_COMM_ICV_KEY.__name__)
    key = unhexlify('071025b3b38e56fb404217402fc69a7803b162cb2336efe30383856af4a9afe6')
    # key = unhexlify('d332ae77f71397393f72c7ba7dfd0e299093d7445fd3ee7d24c324d91f51ae7c') # ATE
    ptx = unhexlify('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    ctx = unhexlify('ab6497f70421a361974e905cfe87cd2efc844bfe9af9b808bc55bbfc6b76710c')
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    # Create a cipher object with Key ,CBC_MODE and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Encrypt data
    data = cipher.encrypt(ptx)
    print("\tciphertext:", data.hex(), "[PASS]" if data==ctx else "[FAIL]")
    # Decrytp data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(ctx)
    print("\tplaintext:", data.hex(), "[PASS]" if data==ptx else "[FAIL]")


def test_SA_KeyEoL():
    """
    KeyEoL:             Asset Number=0x3, Policy = 0x08232807
    Type: AES-CBC-256
    """
    print("\n%s()" % test_SA_KeyEoL.__name__)
    key = unhexlify('1a6544d451eaab8821177dab466b83eaaecf2e537f58c7c5ff609221ca1e26f6')
    # key = unhexlify('cea4a1e94e8b5649050ba1fd92560cb60dfa4622fdaf0f724ceb0efb8c4d5772')  # ATE
    ptx = unhexlify('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    ctx = unhexlify('57efe391c9a7cfba7f705847794138a1ef743e0f17330cd00929300d504419eb')
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    # Create a cipher object with Key ,CBC_MODE and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Encrypt data
    data = cipher.encrypt(ptx)
    print("\tciphertext:", data.hex(), "[PASS]" if data==ctx else "[FAIL]")
    # Decrytp data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(ctx)
    print("\tplaintext:", data.hex(), "[PASS]" if data==ptx else "[FAIL]")


def ex_sa():
    test_SA_MAC_KEY()
    test_SA_COMM_ICV_KEY()
    test_SA_KeyEoL()


if __name__ == '__main__':
    ex_sa()


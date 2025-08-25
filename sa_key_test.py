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
        print("\t\tThe message '%s' is authentic" % msg.hex())
    except ValueError:
        print("\t\tThe message or the key is wrong")


def test_SA_COMM_ICV_KEY():
    """
    COMM_ICV_KEY:       Asset Number=0x4, Policy = 0x08232809
    Type: AES-CBC-256
    """
    print("\n%s()" % test_SA_COMM_ICV_KEY.__name__)
    key = unhexlify('071025b3b38e56fb404217402fc69a7803b162cb2336efe30383856af4a9afe6')
    ptx = unhexlify('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    ctx = unhexlify('ab6497f70421a361974e905cfe87cd2efc844bfe9af9b808bc55bbfc6b76710c')
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    # Create a cipher object with Key ,CBC_MODE and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Encrypt data
    data = cipher.encrypt(ptx)
    print("\tciphertext:", data.hex())
    # Decrytp data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(ctx)
    print("\tplaintext:", data.hex())


def test_SA_KeyEoL():
    """
    KeyEoL:             Asset Number=0x3, Policy = 0x08232807
    Type: AES-CBC-256
    """
    print("\n%s()" % test_SA_KeyEoL.__name__)
    key = unhexlify('1a6544d451eaab8821177dab466b83eaaecf2e537f58c7c5ff609221ca1e26f6')
    ptx = unhexlify('0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF0123456789ABCDEF')
    ctx = unhexlify('57efe391c9a7cfba7f705847794138a1ef743e0f17330cd00929300d504419eb')
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    # Create a cipher object with Key ,CBC_MODE and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # Encrypt data
    data = cipher.encrypt(ptx)
    print("\tciphertext:", data.hex())
    # Decrytp data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(ctx)
    print("\tplaintext:", data.hex())


def ex_sa():
    test_SA_MAC_KEY()
    test_SA_COMM_ICV_KEY()
    test_SA_KeyEoL()


if __name__ == '__main__':
    ex_sa()


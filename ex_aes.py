#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Reference:
    PyCryptodome: AES
        https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html
        https://officeguide.cc/python-pycryptodome-aes-symmetric-encryption-tutorial-examples/
    Cryptography: Key wrapping
        https://cryptography.io/en/latest/hazmat/primitives/keywrap/#cryptography.hazmat.primitives.keywrap.aes_key_wrap
        pip install cryptography==35.0.0
    RFC 5649: Advanced Encryption Standard (AES) Key Wrap with Padding Algorithm
        https://www.rfc-editor.org/rfc/rfc5649.html
"""


from Crypto.Cipher import AES
from binascii import unhexlify
import os
# for RFC 3394
from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
# for RFC 5649
from cryptography.hazmat.primitives.keywrap import aes_key_wrap_with_padding, aes_key_unwrap_with_padding 
from Crypto.Util.Padding import pad, unpad


def ex_aes():
    print("\n%s()" % ex_aes.__name__)
    key = b'Sixteen byte key'
    data = b'My secret data.'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    # encryption
    print("\tnonce:", nonce.hex())
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("\tciphertext:", ciphertext.hex())
    print("\ttag:", tag.hex())
    # decryption
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    plaintext = cipher.decrypt(ciphertext)
    try:
        cipher.verify(tag)
        print("\tThe message is authentic:", plaintext)
    except ValueError:
        print("\tKey incorrect or message corrupted")


def ex_aes_cbc():
    print("\n%s()" % ex_aes_cbc.__name__)
    key= unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    # plaintext
    ptx = unhexlify("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    # ciphertext
    ctx = unhexlify("7649abac8119b246cee98e9b12e9197d5086cb9b507219ee95db113a917678b273bed6b8e3c1743b7116e69e222295163ff1caa1681fac09120eca307586e1a7")
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


def ex_aes_cbc_padding():
    print("\n%s()" % ex_aes_cbc_padding.__name__)
    key= unhexlify("2b7e151628aed2a6abf7158809cf4f3c")
    # plaintext
    ptx = unhexlify("bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e5130c81c46a35ce411e5fbc1191a0a52eff69f2445df4f9b17ad2b417be66c3710")
    iv = unhexlify("000102030405060708090a0b0c0d0e0f")
    # Create a cipher object with Key ,CBC_MODE and IV
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    # padding
    pad_ptx = pad(ptx, AES.block_size)
    # Encrypt data
    data = cipher.encrypt(pad_ptx)
    print("\tciphertext:", data.hex())
    

def ex_aes_keywrap_rfc3394():
    print("\n%s()" % ex_aes_keywrap_rfc3394.__name__)
    aes_key = os.urandom(16)  # Generate a random 128-bit AES key

    # Randomly generate an AES key for wrapping and unwrapping
    wrapping_key = os.urandom(32)  # Generate a random 256-bit AES key

    # Wrap AES keys using the aes_key_wrap function
    wrapped_aes_key = aes_key_wrap(wrapping_key, aes_key)

    # Unwrap the AES key using the aes_key_unwrap function
    unwrapped_aes_key = aes_key_unwrap(wrapping_key, wrapped_aes_key)

    print("\tThe first example randomly generates data.")
    print("\t\taes_key(%d): %s" % (len(aes_key), aes_key.hex()))
    print("\t\twrapping_key(%d): %s" % (len(wrapping_key), wrapping_key.hex()))
    print("\t\twrapped_aes_key(%d): %s" % (len(wrapped_aes_key), wrapped_aes_key.hex()))
    print("\t\tunwrapped_aes_key(%d): %s" % (len(unwrapped_aes_key), unwrapped_aes_key.hex()))
    if aes_key == unwrapped_aes_key:
        print("\t\tAES key wrapping and unwrapping successful!\n")
    else:
        print("\t\tAES key wrapping and unwrapping failed!\n")

    print("\tThe second example uses fixed data for testing.")
    KEK = unhexlify("000102030405060708090A0B0C0D0E0F")
    CIPHER = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    PLAIN = unhexlify("00112233445566778899AABBCCDDEEFF")
    print("\t\tKEK(%d): %s" % (len(KEK), KEK.hex()))
    print("\t\tCIPHER(%d): %s" % (len(CIPHER), CIPHER.hex()))
    print("\t\tPLAIN(%d): %s" % (len(PLAIN), PLAIN.hex()))
    assert aes_key_unwrap(KEK, CIPHER) == PLAIN
    assert aes_key_wrap(KEK, PLAIN) == CIPHER
    print("\t\tAES key wrapping and unwrapping successful!\n")


def ex_aes_keywrap_rfc5649():
    print("\n%s()" % ex_aes_keywrap_rfc5649.__name__)
    print("\tThe first example wraps 20 octets of key data with a 192-bit KEK.")
    KEK = unhexlify("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
    Key = unhexlify("c37b7e6492584340bed12207808941155068f738")
    Wrap = unhexlify("138bdeaa9b8fa7fc61f97742e72248ee5ae6ae5360d1ae6a5f54f373fa543b6a")
    print("\t\tKEK(%d): %s" % (len(KEK), KEK.hex()))
    print("\t\tKey(%d): %s" % (len(Key), Key.hex()))
    print("\t\tWrap(%d): %s" % (len(Wrap), Wrap.hex()))
    assert aes_key_wrap_with_padding(KEK, Key) == Wrap
    assert aes_key_unwrap_with_padding(KEK, Wrap) == Key
    print("\t\tAES key wrapping and unwrapping successful!\n")

    print("\tThe second example wraps 7 octets of key data with a 192-bit KEK.")
    KEK = unhexlify("5840df6e29b02af1ab493b705bf16ea1ae8338f4dcc176a8")
    Key = unhexlify("466f7250617369")
    Wrap = unhexlify("afbeb0f07dfbf5419200f2ccb50bb24f")
    print("\t\tKEK(%d): %s" % (len(KEK), KEK.hex()))
    print("\t\tKey(%d): %s" % (len(Key), Key.hex()))
    print("\t\tWrap(%d): %s" % (len(Wrap), Wrap.hex()))
    assert aes_key_wrap_with_padding(KEK, Key) == Wrap
    assert aes_key_unwrap_with_padding(KEK, Wrap) == Key
    print("\t\tAES key wrapping and unwrapping successful!\n")


def aes_ccm_get_vect(vect_no):
    match vect_no:
        case 1:
            # [Alen = 0]
            key_b = unhexlify("b7c7ecb134e516e8b342b52ebcd53158a23419ca0908c68da6be3ba246805096")
            nonce_b = unhexlify("0535d8852ed3f4951bfdee85ed")
            aad_b = unhexlify("")
            payload_b = unhexlify("03ef7e463f524e2ec54a0c43d95942b96df69a649833f07b439dab9d26644e11")
            ct_b = unhexlify("775e4e1373fe0644c1348bb40b19dff283e4a805df82970cb5c79d478e9c4b76a7c1153193f856cd7b29c1ea2796dc7a")

        case 2:
            # [Alen = 6]
            key_b = unhexlify("434f617a771622349039b5c923c4844b0cf7609abe4a7285d7ae7432f81621c0")
            nonce_b = unhexlify("38f2d3718a55e1e58e62ade98c")
            aad_b = unhexlify("e9c0f7cad84b")
            payload_b = unhexlify("9246650a009acbeb66939d7bdcf952ea288d7621de9cf1f5ccd38ca19455b173")
            ct_b = unhexlify("150dfe59db06ae79c10bc8053806d60b7095ac3a4ac18bd4f3769e198a8c95bdfc717fdc3f6bdb6d13f30cb768e648de")

        case 3:
            # [Alen = 17]
            key_b = unhexlify("60a2666e890fa94954e0e5c87fa7f5a9e0b86c89b12f85052c345920587d55e4")
            nonce_b = unhexlify("611082dc33aea9a461cd8d72c6")
            aad_b = unhexlify("344e11033090e9ddb40aa66428d5100cbc")
            payload_b = unhexlify("1c8d60221d994c7428b7779bf3d0fdd90d4b77f07b23c1daa43c01b96af7e411")
            ct_b = unhexlify("a7befb376115bc1408dde12155f4559537a02162a25ea3cb99b64c59af618dab753a8f0ecee69af71635d91f1aa147bd")

        case 4:
            # [Alen = 31]
            key_b = unhexlify("4c5b076555d9064565dab0823af4d10b1b27006e681bce4075a944bf989d8db6")
            nonce_b = unhexlify("ba07666834c5e20a48e0d1c8b3")
            aad_b = unhexlify("ad75e6a6e0b2ec96432ec46de8091de8238f215d875f04fc10ccdc55a283b3")
            payload_b = unhexlify("bf5af50c7dbb411cb4260fc3cbf5a53ee358bd731592e2c9fa651d3d71cad1b3")
            ct_b = unhexlify("c3c8a8d77756d543c91b8775d080aefd143ce18a6b376ac1dda3357c4b388dec74c9f15cf9d7539d2f9459e3b5c5afe1")

        case 5:
            # [Alen = 32]
            key_b = unhexlify("21adac74c023980f14f5f7b6184338ab50949db9ad233e26b17a52e4d342aa07")
            nonce_b = unhexlify("0fcb90425ee2801926e7999698")
            aad_b = unhexlify("e97b52d90d4d6a2a91983fc8a0f1e30f73ba018bbbf366683f53c02ac697a69f")
            payload_b = unhexlify("fb1eb07c40709960f858f072bb6020416e2c561ab71590ceb313f7b5ece06ef3")
            ct_b = unhexlify("655ee526617e5d5a2a8f16a3c5b517775b2131cb9f725b6fc0e68a0252086dfb692c6f7227239a4b9a9ad36759cbf37f")

        case 6:
            # No plaintext, AAD only
            key_b = unhexlify("c6c14c655e52c8a4c7e8d54e974d698e1f21ee3ba717a0adfa6136d02668c476")
            nonce_b = unhexlify("291e91b19de518cd7806de44f6")
            aad_b = unhexlify("b4f8326944a45d95f91887c2a6ac36b60eea5edef84c1c358146a666b6878335")
            payload_b = unhexlify("")
            ct_b = unhexlify("ca482c674b599046cc7d7ee0d00eec1e")

        case _:
            (key_b, nonce_b, aad_b, payload_b, ct_b) = (None, None, None, None, None)

    return (key_b, nonce_b, aad_b, payload_b, ct_b)


def ex_aes_ccm_vect(vect_no):
    print("\tvect_no:", vect_no)

    (key_b, nonce_b, aad_b, payload_b, ct_b) = aes_ccm_get_vect(vect_no)
    if key_b is None:
        print("\t\t[ERROR] invalid vector")
        return
    print("\t\tkey:", key_b.hex())
    print("\t\tnonce:", nonce_b.hex())
    print("\t\taad:", aad_b.hex())
    print("\t\tpayload:", payload_b.hex())
    print("\t\tct:", ct_b.hex())

    # CCM test vector format:
    # CT = ciphertext || tag
    tag_len = 16
    ciphertext_b = ct_b[:-tag_len]
    tag_b = ct_b[-tag_len:]

    print("\t\tciphertext:", ciphertext_b.hex())
    print("\t\ttag:", tag_b.hex())

    # -------------------------
    # Encryption
    # -------------------------
    cipher = AES.new(key_b, AES.MODE_CCM, nonce=nonce_b, mac_len=tag_len)

    if len(aad_b) > 0:
        cipher.update(aad_b)

    enc_ciphertext_b = cipher.encrypt(payload_b)
    enc_tag_b = cipher.digest()
    enc_ct_b = enc_ciphertext_b + enc_tag_b

    print("\t\tenc_ciphertext:", enc_ciphertext_b.hex())
    print("\t\tenc_tag       :", enc_tag_b.hex())
    print("\t\tenc_ct        :", enc_ct_b.hex())

    if enc_ct_b == ct_b:
        print("\t\t[PASS] Encryption match")
    else:
        print("\t\t[FAIL] Encryption mismatch")

    # -------------------------
    # Decryption
    # -------------------------
    cipher = AES.new(key_b, AES.MODE_CCM, nonce=nonce_b, mac_len=tag_len)

    if len(aad_b) > 0:
        cipher.update(aad_b)

    try:
        dec_payload_b = cipher.decrypt_and_verify(ciphertext_b, tag_b)
        print("\t\tdec_payload   :", dec_payload_b.hex())

        if dec_payload_b == payload_b:
            print("\t\t[PASS] Decryption match")
        else:
            print("\t\t[FAIL] Decryption mismatch")

    except ValueError:
        print("\t\t[FAIL] Tag verification failed")


def ex_aes_ccm():
    print("\n%s()" % ex_aes_ccm.__name__)
    for i in range(1, 7):
        ex_aes_ccm_vect(i)


if __name__ == '__main__':
    ex_aes()
    ex_aes_cbc()
    ex_aes_cbc_padding()
    ex_aes_keywrap_rfc3394()
    ex_aes_keywrap_rfc5649()
    ex_aes_ccm()

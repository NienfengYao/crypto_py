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


if __name__ == '__main__':
    ex_aes()
    ex_aes_cbc()
    ex_aes_cbc_padding()
    ex_aes_keywrap_rfc3394()
    ex_aes_keywrap_rfc5649()

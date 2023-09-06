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
"""


from Crypto.Cipher import AES
from binascii import unhexlify


def ex_aes():
    print("\n%s()" % ex_aes.__name__)
    key = b'Sixteen byte key'
    data = b'My secret data.'
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    # encryption
    print("\tnonce: ", nonce.hex())
    ciphertext, tag = cipher.encrypt_and_digest(data)
    print("\tciphertext: ", ciphertext.hex())
    print("\ttag: ", tag.hex())
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
    print("\tciphertext: ", data.hex())
    # Decrytp data
    cipher = AES.new(key, AES.MODE_CBC, iv=iv)
    data = cipher.decrypt(ctx)
    print("\tplaintext: ", data.hex())
    

def ex_aes_keywrap():
    from cryptography.hazmat.primitives.keywrap import aes_key_wrap, aes_key_unwrap
    import os

    print("\n%s()" % ex_aes_keywrap.__name__)
    aes_key = os.urandom(16)  # Generate a random 128-bit AES key
    # Randomly generate an AES key for wrapping and unwrapping
    wrapping_key = os.urandom(32)  # Generate a random 256-bit AES key
    # Wrap AES keys using the aes_key_wrap function
    wrapped_aes_key = aes_key_wrap(wrapping_key, aes_key)
    # Unwrap the AES key using the aes_key_unwrap function
    unwrapped_aes_key = aes_key_unwrap(wrapping_key, wrapped_aes_key)
    if aes_key == unwrapped_aes_key:
        print("\tAES key wrapping and unwrapping successful!")
    else:
        print("\tAES key wrapping and unwrapping failed!")

    KEK = unhexlify("000102030405060708090A0B0C0D0E0F")
    CIPHER = unhexlify("1FA68B0A8112B447AEF34BD8FB5A7B829D3E862371D2CFE5")
    PLAIN = unhexlify("00112233445566778899AABBCCDDEEFF")
    assert aes_key_unwrap(KEK, CIPHER) == PLAIN
    assert aes_key_wrap(KEK, PLAIN) == CIPHER
    print("\tAES key wrapping and unwrapping successful!")


if __name__ == '__main__':
    ex_aes()
    ex_aes_cbc()
    ex_aes_keywrap()


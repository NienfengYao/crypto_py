#!/usr/bin/python3
# -*- coding: utf-8 -*-
from Crypto.Hash import CMAC
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad
# from binascii import hexlify, unhexlify


def ex_aes_cmac():
    # NIST AES CMAC Vector from [NIST-SP-800-38B] #4
    # key = unhexlify('2b7e151628aed2a6abf7158809cf4f3c')
    key = bytes([ 
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6, 0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c])
    msg = bytes([
        0x6b, 0xc1, 0xbe, 0xe2, 0x2e, 0x40, 0x9f, 0x96, 0xe9, 0x3d, 0x7e, 0x11, 0x73, 0x93, 0x17, 0x2a])
    mac = bytes([
        0x07, 0x0a, 0x16, 0xb4, 0x6b, 0x4d, 0x41, 0x44, 0xf7, 0x9b, 0xdd, 0x9d, 0xd0, 0x4a, 0x28, 0x7c])

    print("\n%s()" % ex_aes_cmac.__name__)
    # Generate
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


def ex_aes_cbc_mac():
    # Miscellaneous AES CBC-MAC Test Vector #4
    key = bytes([ 
        0x01, 0x23, 0x45, 0x67, 0x89, 0xab, 0xcd, 0xef, 0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10])
    msg = bytes([
        0xda, 0x7a, 0x00, 0x01, 0xda, 0x7a, 0x00, 0x02, 0xda, 0x7a, 0x00, 0x03, 0xda, 0x7a, 0x00, 0x04])
    expected_mac = bytes([
        0x5d, 0xc4, 0x3c, 0x22, 0x64, 0x38, 0xc6, 0x94, 0x7c, 0x69, 0xaa, 0x8c, 0xad, 0x08, 0x26, 0x1c])

    print("\n%s()" % ex_aes_cbc_mac.__name__)
    # Generate
    cipher = AES.new(key, AES.MODE_CBC, iv=bytes(16))  # IV is zero for CBC-MAC
    # padded_msg = pad(msg, AES.block_size) 
    padded_msg = msg # RT-130 doesn't add apdding if size=16, adjust here
    """
    print("\tiv=%s" % (bytes(16).hex()))
    print("\tAES.block_size=%d" % AES.block_size)
    print("\tmsg=%s" % msg.hex())
    print("\tpadded_msg=%s" % padded_msg.hex())
    """
    encrypted_msg = cipher.encrypt(padded_msg)
    mac = encrypted_msg[-AES.block_size:]  # CBC-MAC is the last block of ciphertext

    print("\tAES-CBC-MAC Generate:")
    print("\t\t", mac.hex())

    # Verify
    try:
        print("\tAES-CBC-MAC Verify:")
        if mac == expected_mac:
            print("\t\tThe message '%s' is authentic" % msg.hex())
        else:
            print("\t\tThe message or the key is wrong")
    except ValueError:
        print("\t\tThe message or the key is wrong")


def ex_cmac():
    ex_aes_cmac()
    ex_aes_cbc_mac()


if __name__ == '__main__':
    ex_cmac()


#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Reference:
    How to Sign and Verify Digital Signature With Ecdsa?
        https://www.askpython.com/python/examples/sign-verify-signature-ecdsa
    ecdsa 0.18.0
        https://pypi.org/project/ecdsa/
"""


from ecdsa import SigningKey, VerifyingKey, NIST521p, BadSignatureError
import hashlib
from ecdsa.util import sigencode_der, sigdecode_der
from binascii import hexlify, unhexlify


def ex_ecdsa_basic():
    print("\n%s()" % ex_ecdsa_basic.__name__) 
    sk = SigningKey.generate() # uses NIST192p
    vk = sk.verifying_key
    signature = sk.sign(b"message")
    try:
        vk.verify(signature, b"message") # returns True or raises BadSignatureError
        print("\tSignature verified: True")
    except BadSignatureError:
        print("\tSignature verified: False")


def ex_ecdsa_nist521p():
    print("\n%s()" % ex_ecdsa_nist521p.__name__) 
    sk = SigningKey.generate(curve=NIST521p) # uses NIST521p
    print('\tsk(%d): %s' % ( len(sk.to_string().hex()), sk.to_string().hex())) 
    vk = sk.verifying_key
    print('\tvk(%d): %s' % ( len(vk.to_string().hex()), vk.to_string().hex())) 
    signature = sk.sign(b"message")
    try:
        vk.verify(signature, b"message") # returns True or raises BadSignatureError
        print("\tSignature verified: True")
    except ecdsa.BadSignatureError:
        print("\tSignature verified: False")


def ex_ecdsa_openssl_compatibility():
    '''
    openssl ecparam -name prime256v1 -genkey -out sk.pem
    [openssl ec -text -in sk.pem]
    openssl ec -in sk.pem -pubout -out vk.pem
    echo "data for signing" > data
    openssl dgst -sha256 -sign sk.pem -out data.sig data
    openssl dgst -sha256 -verify vk.pem -signature data.sig data
    openssl dgst -sha256 -prverify sk.pem -signature data.sig data
    '''
    print("\n%s()" % ex_ecdsa_openssl_compatibility.__name__) 
    with open("vk.pem") as f:
        vk = VerifyingKey.from_pem(f.read())
    with open("data", "rb") as f:
        data = f.read()
    with open("data.sig", "rb") as f:
        signature = f.read()
    try:
        vk.verify(signature, data, hashlib.sha256, sigdecode=sigdecode_der)
        print("\tSignature verified: True")
    except BadSignatureError:
        print("\tSignature verified: False")
    with open("sk.pem") as f:
        sk = SigningKey.from_pem(f.read(), hashlib.sha256)
    new_signature = sk.sign_deterministic(data, sigencode=sigencode_der)
    with open("data.sig2", "wb") as f:
        f.write(new_signature)
    # openssl dgst -sha256 -verify vk.pem -signature data.sig2 data


def ex_ecdsa_rt130_simple():
    '''
    openssl ecparam -genkey -name secp521r1 -noout -out ec512-key-pair.pem
    openssl ec -text -in ec512-key-pair.pem 
    '''
    print("\n%s()" % ex_ecdsa_rt130_simple.__name__) 
    priv_bytes = unhexlify("010eb5c1d9b465cddcfff32e69f9776a0b4effe188a54e59b955f7697ea0a276d676e50c64f04d9728ec09f3ee8f8b3719422c9a5248af637dd91ff6b4eb37d33cc1")
    public_bytes = unhexlify("01aa2560d95f0325bc5781dd58c5b0f4835cf0590506e686a2b76cae4fa40a8f0d7051ed2aeb7166e6e96ae4c9a6d01c48898ec5e8b2034f2f550a88f4ceaa213c2b0092eb6b067150e8d89e3356d27aef3e92fe999781ce663502c018c1a34825fc99a48a6531498030cd2d352ae862230ced6813258b7596f6d485e75950ef7c23c075")
    priv_key = SigningKey.from_string(priv_bytes, curve=NIST521p)
    # print('\tpriv_key(%d): %s' % (len(priv_key.to_string().hex()), priv_key.to_string().hex())) 
    public_key = VerifyingKey.from_string(public_bytes, curve=NIST521p)
    # print('\tpublic_key(%d): %s' % (len(public_key.to_string().hex()), public_key.to_string().hex())) 
    message = b"HelloWorld!"
    message_hash = hashlib.sha512(message).digest()
    signature = priv_key.sign(message_hash)
    print("\tSignature:",signature.hex())
    try:
        public_key.verify(signature, message_hash)
        print("\tSignature verified: True")
    except BadSignatureError:
        print("\tSignature verified: False")


def ex_ecdsa_rt130():
    '''
    openssl ecparam -genkey -name secp521r1 -noout -out ec512-key-pair.pem
    openssl ec -text -in ec512-key-pair.pem 
    dd if=/dev/random bs=16 count=1 > Ra.bin
    [xxd Ra.bin]
    [Rb: 68 C0 31 22 E0 0E 2A 37 EA AA 89 69 56 E4 1C 6C]
    echo -n -e '\x68\xC0\x31\x22\xE0\x0E\x2A\x37\xEA\xAA\x89\x69\x56\xE4\x1C\x6C' > Rb.bin
    cat Ra.bin Rb.bin > RaRb.bin
    openssl dgst -sha512 -sign ec512-key-pair.pem -out signature.bin RaRb.bin
    openssl asn1parse -inform DER -in signature.bin
    '''
    print("\n%s()" % ex_ecdsa_rt130.__name__) 
    with open("ec512-key-pair.pem") as f:
        sk = SigningKey.from_pem(f.read(), hashlib.sha512)
    print('\tsk(%d): %s' % ( len(sk.to_string().hex()), sk.to_string().hex())) 
    vk = sk.verifying_key
    print('\tvk(%d): %s' % ( len(vk.to_string().hex()), vk.to_string().hex())) 
    with open("RaRb.bin", "rb") as f:
        data = f.read()
    print('\tRaRb(%d): %s' % ( len(data.hex()), data.hex())) 
    with open("signature.bin", "rb") as f:
        signature = f.read()
    try:
        vk.verify(signature, data, hashlib.sha512, sigdecode=sigdecode_der)
        print("\tSignature verified: True")
    except BadSignatureError:
        print("\tSignature verified: False")
    new_signature = sk.sign_deterministic(data, sigencode=sigencode_der)
    with open("signature2.bin", "wb") as f:
        f.write(new_signature)
    # openssl dgst -sha512 -prverify ec512-key-pair.pem -signature signature2.bin RaRb.bin


if __name__ == '__main__':
    ex_ecdsa_basic()
    ex_ecdsa_nist521p()
    ex_ecdsa_openssl_compatibility()
    ex_ecdsa_rt130_simple()
    ex_ecdsa_rt130()

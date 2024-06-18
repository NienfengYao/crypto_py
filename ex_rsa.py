#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
Reference:
    https://coin028.com/python/python-rsa-encryption-decryption/
"""
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_v1_5
from binascii import unhexlify, hexlify
from hashlib import sha1, sha512
from Crypto.Random import get_random_bytes
from Crypto.Signature.pkcs1_15 import PKCS115_SigScheme
from Crypto.Hash import SHA1, SHA256, SHA512


def ex_rsa_pem():
    '''
    The following code generates public key stored in receiver.pem and private key stored in private.pem.
    These files will be used in the examples below. Every time, it generates different public key and private key pair.
    '''
    key = RSA.generate(2048)
    private_key = key.export_key()
    with open("rsa_private.pem", "wb") as f:
        f.write(private_key)
    # print(key.export_key())

    public_key = key.publickey().export_key()
    with open("rsa_public.pem", "wb") as f:
        f.write(public_key)

    print("\n%s()" % ex_rsa_pem.__name__)
    # print(key.publickey().export_key())


def ex_rsa_pkcs1_v15():
    # Generate key
    key = RSA.generate(2048)
    text = b"Hello World!"

    # Get the public key
    public_key = key.publickey().exportKey("PEM")

    # Get the private key
    private_key = key.exportKey("PEM")

    # Encrypt data
    cipher = PKCS1_v1_5.new(key.publickey())
    cipher_text = cipher.encrypt(text)

    # Decrypt data
    cipher = PKCS1_v1_5.new(key)
    sentinel = get_random_bytes(16)  # A sentinel value required by PKCS1_v1_5
    plain_text = cipher.decrypt(cipher_text, sentinel)

    print("\n%s()" % ex_rsa_pkcs1_v15.__name__)
    print("\tRSA_PKCS1_v1_5(2048)")
    print("\t\tText: ", text)
    print("\t\tCipherText(Hex) len=%d: %s" % ((len(cipher_text.hex())/2)*8, cipher_text.hex()))
    print("\t\tPlainText: ", plain_text)


def ex_rsa1024_generate_sha512_signature():
    # generate a 1024-bit RSA key-pair
    print("\n%s()" % ex_rsa1024_generate_sha512_signature.__name__)
    keyPair = RSA.generate(bits=1024)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

    # RSA sign the message
    msg = b'A message for signing'
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    signature = pow(hash, keyPair.d, keyPair.n)
    print("Signature:", hex(signature))

    # RSA verify signature
    msg = b'A message for signing'
    hash = int.from_bytes(sha512(msg).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)
    print("Signature valid:", hash == hashFromSignature)
    print("")


def ex_rsa1024_generate_sha1_signature():
    # generate a 1024-bit RSA key-pair
    print("\n%s()" % ex_rsa1024_generate_sha1_signature.__name__)
    keyPair = RSA.generate(bits=1024)
    print(keyPair.__str__)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

    # RSA sign the message
    msg = unhexlify("616263")
    # msg = b'A message for signing'
    hash = int.from_bytes(sha1(msg).digest(), byteorder='big')
    signature = pow(hash, keyPair.d, keyPair.n)
    print("Signature:", hex(signature))

    # RSA verify signature
    # msg = b'A message for signing'
    msg = unhexlify("616263")
    hash = int.from_bytes(sha1(msg).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)
    print("Signature valid:", hash == hashFromSignature)
    print("")


def ex_rsa1024_construct_sha1_signature():
    """
<bound method RsaKey.__str__ of RsaKey(n=113332785371544969920506974515434891834856912514512148643246136977327586416032313946216071524542301832980874828310121784033931955144108826571203754085725927022168288208565844290883221318702181430014715117397431598793302363493445634650028720281235826440572167810733054442044503526703127055761835617261981283733, e=65537, d=31274294268037761585247549233435159052647928083753485942492124864350968160488646073474795207613218924416117937500778986896770670137192854853597508165469170152435429173698900233155898837357259991295715567769637688656441775360510297914538846599879653161495589669231315218989439877825453991505932761348590827773, p=9958577633261444120057917172324898198335832572501567948319505012995712918745306084926271339520766886077983933982047239260760369430558506342966407671060631, q=11380418925792755961192858880505892302250966919438338814481860740314321761979505672719107141933030891704416104424592377212836942113514600014885827901758643, u=1369201919876447416757906150297217775629778451348238321210478531203586627549502247965843050084966360355671492664566351005281557701498216908553534542944886)>
Public key:  (n=0xa16428897eb5749747345f9d342f5baf7e130b92783019edef9464beced0746f948ae8663e146c178b795cb7e99203641f3c912183d822ce7e5cc130eef5462200a35624a2fa8ebf6fea2b1fd1d2ae270fbc7ba0dbae83f81da938713ae8a2f5bade6afb00abc8719eb64f42014c030ff4f6b247c5a856cdc95197e1d8383595, e=0x10001)
Private key: (n=0xa16428897eb5749747345f9d342f5baf7e130b92783019edef9464beced0746f948ae8663e146c178b795cb7e99203641f3c912183d822ce7e5cc130eef5462200a35624a2fa8ebf6fea2b1fd1d2ae270fbc7ba0dbae83f81da938713ae8a2f5bade6afb00abc8719eb64f42014c030ff4f6b247c5a856cdc95197e1d8383595, d=0x2c893c1a7d29cbabb74d7f991cfe78999bfbdb74a6cff747ce962f9aebed60442e448acf341064a7b6a85deaae7cc98cc685eb32c9744a5e9b463355b28b62b7acf07c79d6089dc144662c2f3a3cf249744ad1c9022127e6757c8228fe5d255162300388dcbe2cb0f9079ca240776691b500015c0e0177d3bb261317f99c78fd)
Signature: 0x4bebec12e9d7e86ba71c63ddeb18ffc7b2a18b0248ef5697efbb6aae1f8b0fc0d8f6b4627a408c57ab66be82e090e970c29e7fba23456185cec3d5f18ff2e8f6be49bc3c470b7e4c16016db41fdd83cd9e28ceb96d640fb9069efe7290bb76ece411fcd583da5a6622ee95bd131978498db7da9c57b322ee59e96c88b15d665f
    """
    n=113332785371544969920506974515434891834856912514512148643246136977327586416032313946216071524542301832980874828310121784033931955144108826571203754085725927022168288208565844290883221318702181430014715117397431598793302363493445634650028720281235826440572167810733054442044503526703127055761835617261981283733
    e=65537
    d=31274294268037761585247549233435159052647928083753485942492124864350968160488646073474795207613218924416117937500778986896770670137192854853597508165469170152435429173698900233155898837357259991295715567769637688656441775360510297914538846599879653161495589669231315218989439877825453991505932761348590827773
    p=9958577633261444120057917172324898198335832572501567948319505012995712918745306084926271339520766886077983933982047239260760369430558506342966407671060631
    q=11380418925792755961192858880505892302250966919438338814481860740314321761979505672719107141933030891704416104424592377212836942113514600014885827901758643

    print("\n%s()" % ex_rsa1024_construct_sha1_signature.__name__)
    keyPair = RSA.construct((n, e, d, p, q))
    print(keyPair.__str__)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

    # RSA sign the message
    msg = unhexlify("616263")
    hash = int.from_bytes(sha1(msg).digest(), byteorder='big')
    signature = pow(hash, keyPair.d, keyPair.n)
    print("Signature:", hex(signature))

    # RSA verify signature
    msg = unhexlify("616263")
    hash = int.from_bytes(sha1(msg).digest(), byteorder='big')
    hashFromSignature = pow(signature, keyPair.e, keyPair.n)
    print("Signature valid:", hash == hashFromSignature)
    print("")


def ex_rsa1024_construct_pkcs115_sha1_signature():
    n=113332785371544969920506974515434891834856912514512148643246136977327586416032313946216071524542301832980874828310121784033931955144108826571203754085725927022168288208565844290883221318702181430014715117397431598793302363493445634650028720281235826440572167810733054442044503526703127055761835617261981283733
    e=65537
    d=31274294268037761585247549233435159052647928083753485942492124864350968160488646073474795207613218924416117937500778986896770670137192854853597508165469170152435429173698900233155898837357259991295715567769637688656441775360510297914538846599879653161495589669231315218989439877825453991505932761348590827773
    p=9958577633261444120057917172324898198335832572501567948319505012995712918745306084926271339520766886077983933982047239260760369430558506342966407671060631
    q=11380418925792755961192858880505892302250966919438338814481860740314321761979505672719107141933030891704416104424592377212836942113514600014885827901758643

    print("\n%s()" % ex_rsa1024_construct_pkcs115_sha1_signature.__name__)
    keyPair = RSA.construct((n, e, d, p, q))
    print(keyPair.__str__)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

    pubKey = keyPair.publickey()

    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    msg = unhexlify("616263")
    hash = SHA1.new(msg)
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash)
    print("Signature:", hexlify(signature))

    # Verify valid PKCS#1 v1.5 signature (RSAVP1)
    msg = unhexlify("616263")
    hash = SHA1.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature)
        print("Signature is valid.")
    except:
        print("Signature is invalid.")

    # Verify invalid PKCS#1 v1.5 signature (RSAVP1)
    msg = b'A tampered message'
    hash = SHA1.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash, signature)
        print("Signature is valid.")
    except:
        print("Signature is invalid.")


def ex_rsa_pkcs115_signature(modulus, hash_alg):
    print("\n%s(%d, %s)" % (ex_rsa_pkcs115_signature.__name__, modulus, hash_alg.__name__))
    keyPair = RSA.generate(bits=modulus)
    print(keyPair.__str__)
    print(f"Public key:  (n={hex(keyPair.n)}, e={hex(keyPair.e)})")
    print(f"Private key: (n={hex(keyPair.n)}, d={hex(keyPair.d)})")

    pubKey = keyPair.publickey()
    # Sign the message using the PKCS#1 v1.5 signature scheme (RSASP1)
    msg = unhexlify("616263")
    hash_data = hash_alg.new(msg)
    signer = PKCS115_SigScheme(keyPair)
    signature = signer.sign(hash_data)
    print("Signature:", hexlify(signature))

    # Verify valid PKCS#1 v1.5 signature (RSAVP1)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash_data, signature)
        print("Pass: Signature is valid.")
    except:
        print("Fail: Signature is invalid.")

    # Verify invalid PKCS#1 v1.5 signature (RSAVP1)
    msg = b'A tampered message'
    hash_data = hash_alg.new(msg)
    verifier = PKCS115_SigScheme(pubKey)
    try:
        verifier.verify(hash_data, signature)
        print("Fail: Signature is valid.")
    except:
        print("Pass: Signature is invalid.")


def ex_rsa():
    ex_rsa_pem()
    ex_rsa_pkcs1_v15()
    ex_rsa1024_generate_sha512_signature()
    ex_rsa1024_generate_sha1_signature()
    ex_rsa1024_construct_sha1_signature()
    ex_rsa1024_construct_pkcs115_sha1_signature()
    for modulus in [1024, 2048, 3072]:
        for hash_alg in [SHA1, SHA256, SHA512]:
            ex_rsa_pkcs115_signature(modulus, hash_alg)


if __name__ == '__main__':
    ex_rsa()


# crypto_py
Study how to use cryptographic algorithms with Python

---
* AES (Advanced Encryption Standard)是一種對稱加密算法，而AES key wrap和AES key unwrap是與密鑰管理有關的特定用途，主要用於保護和傳輸加密金鑰。以下是它們之間的主要差異：
  * AES Encrypt/Decrypt（AES加密/解密）：
    * 對稱加密：AES使用相同的金鑰進行加密和解密，這種金鑰被稱為對稱密鑰。
    * 用途：AES加密和解密用於保護數據的機密性，將明文數據轉換為密文，然後再從密文還原回明文。
  * AES Key Wrap/Unwrap（AES金鑰包裹/解包裹）：
    * 金鑰管理：AES金鑰包裹和解包裹是用於保護和傳輸對稱金鑰的機制，這些對稱金鑰可以用於AES加密和解密操作。
    * 包裹金鑰：在金鑰包裹過程中，一個特定的金鑰（通常是要保護的對稱金鑰）被包裹或加密。
    * 解包裹金鑰：在解包裹過程中，已包裹的金鑰被解密和提取出來，以供後續使用。
    * 安全性：AES金鑰包裹和解包裹操作通常與其他安全性機制（如數字簽名）結合使用，以確保金鑰在傳輸過程中的完整性和機密性。
  * Padding
    * [AES加密与解密的padding问题](https://developer.aliyun.com/article/608799)
    * [加密演算法要注意的那些毛 (二) - 填充模式](https://ithelp.ithome.com.tw/articles/10250386)
  * 總之，AES加密/解密是用於保護數據的機密性，而AES金鑰包裹/解包裹是用於保護和傳輸金鑰的機制。它們有不同的用途，但通常可以一起使用，以實現安全的數據傳輸和存儲。

---
# Reference
* ex_aes.py
  * [PyCryptodome: AES](https://pycryptodome.readthedocs.io/en/latest/src/cipher/aes.html)
  * [Python 以 PyCryptodome 實作 AES 對稱式加密方法教學與範例](https://officeguide.cc/python-pycryptodome-aes-symmetric-encryption-tutorial-examples/)
  * [Cryptography: Key wrapping](https://cryptography.io/en/latest/hazmat/primitives/keywrap/#cryptography.hazmat.primitives.keywrap.aes_key_wrap)
    * pip install cryptography==35.0.0
    * For [RFC 3394](https://datatracker.ietf.org/doc/html/rfc3394): keywrap.aes_key_wrap()/keywrap.aes_key_unwrap()
    * For [RFC 5649](https://www.rfc-editor.org/rfc/rfc5649): aes_key_wrap_with_padding()/aes_key_unwrap_with_padding()
  * 提供 AES Encrypt/Decrypt, Wrap/Unwrap 測試範例。
* ex_ecdsa.py
  * [How to Sign and Verify Digital Signature With Ecdsa?](https://www.askpython.com/python/examples/sign-verify-signature-ecdsa)
  * [ecdsa 0.18.0](https://pypi.org/project/ecdsa/)
  * 配合 OpenSSL/RT-130 提供 ECDSA Sign/Verify 測試範例。
* ex_cmac.py
  * [PyCryptodome: CMAC](https://pycryptodome.readthedocs.io/en/latest/src/hash/cmac.html)
  * AES-CMAC example.
* ex_hmac.py
  * [Python加密—HMACSHA1 加密](https://www.jianshu.com/p/74ceffac1275)
  * HMAC example.
* ex_sha.py
  * [Python 計算 MD5 與 SHA 雜湊教學與範例](https://blog.gtwang.org/programming/python-md5-sha-hash-functions-tutorial-examples/)
  * [hashlib --- 安全哈希与消息摘要](https://docs.python.org/zh-tw/3/library/hashlib.html)
  * Hash example.
* ex_rsa.py
  * [RSA 加密是什麼，其運作原理為何？](https://nordvpn.com/zh-tw/blog/rsa-jiami/)
  * Sign/Verify
    * [筆記：RSA 簽章驗證](https://electronic.blue/blog/2013/08/07-a-note-on-rsa-signature-verification/)
    * [RSA: Sign / Verify - Examples](https://cryptobook.nakov.com/digital-signatures/rsa-sign-verify-examples)    
  * [PyCryptodome: keyGenerate an RSA key](https://pycryptodome.readthedocs.io/en/latest/src/examples.html#generate-an-rsa-key)
  * 使用 PyCryptodome
    * [使用 Python 來進行 RSA 加密與解密: ](https://coin028.com/python/python-rsa-encryption-decryption/)
    * [Python 以 PyCryptodome 實作 RSA 非對稱式加密方法教學與範例](https://officeguide.cc/python-pycryptodome-rsa-asymmetric-encryption-tutorial-examples/)
      * 讀寫 file
    * [PKCS#1 v1.5 encryption (RSA)](https://pycryptodome.readthedocs.io/en/latest/src/cipher/pkcs1_v1_5.html)

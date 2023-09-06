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
  * 總之，AES加密/解密是用於保護數據的機密性，而AES金鑰包裹/解包裹是用於保護和傳輸金鑰的機制。它們有不同的用途，但通常可以一起使用，以實現安全的數據傳輸和存儲。

---
# Reference
* ex_ecdsa.py
  * [How to Sign and Verify Digital Signature With Ecdsa?](https://www.askpython.com/python/examples/sign-verify-signature-ecdsa)
  * [ecdsa 0.18.0](https://pypi.org/project/ecdsa/)

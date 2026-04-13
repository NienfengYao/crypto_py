# AES-CCM 基本介紹

## AES-CCM 是什麼？
AES-CCM 是一種同時提供「加密 + 驗證」的安全機制（AEAD: Authenticated Encryption with Associated Data）。
* 保護資料內容不被偷看（Confidentiality）
* 確保資料沒有被竄改（Integrity）  

## 核心概念
AES-CCM = CBC-MAC（驗證） + CTR（加密）
* CBC-MAC：產生驗證碼（Tag）
* CTR mode：負責資料加密

## 輸入資料（3 種）
| 類型 | 說明 |
|------|------|
| Payload | 要加密的資料 |
| AAD | 不加密，但要驗證（如 header） |
| Nonce | 每次加密都要不同（流水號） |

## 運作流程（簡化）
* Step 1：產生驗證碼（Tag）
Tag = MAC(AAD + Payload)
確保資料完整性
* Step 2：加密 Payload
Ciphertext = Encrypt(Payload)
* Step 3：保護 Tag
Encrypted Tag = Encrypt(Tag)
* Step 4：輸出
Output = Ciphertext + Tag

## 解密流程
* 解密 Ciphertext → 得到 Payload  
* 重新計算 Tag  
* 比對 Tag  
* 判斷結果：
  * Tag 相同 → 資料可信  
  * Tag 不同 → 資料被竄改  

## 生活比喻
| 行為 | AES-CCM 對應 |
|------|-------------|
| 鎖箱子 | 加密 |
| 封條 | Tag 驗證 |
| 外箱資訊 | AAD |

## 常見應用
* Wi-Fi / Bluetooth  
* 車用通訊（CAN / 車聯網）  
* IoT 裝置  
* 行動裝置安全  

## 三個關鍵重點
* Nonce 不可重複, 重複會破壞安全性
* Tag 是安全核心, 用來驗證資料是否被修改
* AAD 不加密但受保護, 常用於控制資訊

## 一句話總結
AES-CCM = 加密資料 + 防偽驗證

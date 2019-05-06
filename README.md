# go-owcrypt

[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

## go package详情
___

go-owcrypt 提供目前区块链技术中使用的椭圆曲线算法与哈希算法。
目前支持的算法包括：
```
        公钥计算算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        签名算法：    
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        验签算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： curve25519、ed25519、x25519
        加密算法：
                ECDSA类 ： sm2-std
        密钥协商算法：
                ECDSA类 ： sm2-std-DH、 sm2-std-ElGamal
        G点相乘算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： ed25519、x25519
        G点的乘加算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
                EDDSA类 ： ed25519
        点的压缩与解压缩算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
        从签名恢复公钥算法：
                ECDSA类 ： secp256k1、secp256r1、primv1、NIST-P256、sm2-std
        点的域转换算法：
                x25519-to-ed25519、ed25519-to-x25519
        哈希算法：
                sha1,sha256,double-sha256,sha512,sha3-256,sha3-512
                md4,md5,
                ripemd160
                blake256,blake512,blake2b,blake2s
                sm3,hash160
                keccak256,keccak512,keccak256-ripemd160

        HMAC算法：
                sha256,sha512,sm3
```

## 接口说明
- 产生公钥:


    func GenPubkey(prikey []byte, pubkey []byte, typeChoose uint32) uint16
```
入参:
        prikey     : 私钥
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
                            ECC_CURVE_ED25519_NORMAL(0xECC00003)
                            ECC_CURVE_ED25519(0xECC00004)
	                    ECC_CURVE_X25519 (0xECC00005)
出参:    
        pubkey    : 公钥
返回值： uint16类型，如下：
                        SUCCESS(0x0001)                 : 生成成功
                        ECC_PRIKEY_ILLEGAL(0xE000)      : 传入了非法私钥
                        ECC_WRONG_TYPE(0xE002)          : 传入了错误的type
Tips：
        对于ECDSA类曲线算法，接口返回的公钥为未压缩的坐标点形式，X坐标在前，Y坐标在后，无前缀(0x04)
        对于EDDSA类曲线算法，接口接受的私钥为私钥本身，不是私钥+公钥拼接后的数组
```
- 数字签名：

   func Signature(prikey []byte, ID []byte, IDlen uint16, message []byte, message_len uint16, signature []byte, typeChoose uint32) uint16 
```
入参：   
        prikey     ： 私钥
        ID         ： 签名方标识符，仅SM2签名时需要传入
        IDlen      ： 签名方标识符长度
        message    ： 待签名的消息
        message_len： 待签名的消息长度
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
                            ECC_CURVE_ED25519_NORMAL(0xECC00003)
                            ECC_CURVE_ED25519(0xECC00004)
	                    ECC_CURVE_X25519 (0xECC00005)
出参：
        signature  ： 签名值
返回值： 
        uint16类型，如下：
                        SUCCESS(0x0001)                 : 生成成功
                        ECC_PRIKEY_ILLEGAL(0xE000)      : 传入了非法私钥
                        ECC_WRONG_TYPE(0xE002)          : 传入了错误的type
                        ECC_MISS_ID(0xE003)             : SM2签名时未传入签名方标识符

```
- 预置随机数：

   func PreprocessRandomNum(rand []byte) (ret uint16)
```
入参：
        rand：随机数
返回值：
        uint16类型，如下：
                        SUCCESS(0x0001)                 : 成功
                        其他                             : 失败
Tips：
        该接口主要用于签名算法采用固定随机数的情况，使用时应配合Signature接口使用，顺序为：
        1，PreprocessRandomNum - 写入随机数
        2. Signature调用签名 - 签名 
        签名时，应该将传入的typeChose或上 NOUNCE_OUTSIDE_FLAG 以使随机数生效
```
- 签名验证：

   func Verify(pubkey []byte, ID []byte, IDlen uint16, message []byte, message_len uint16, signature []byte, typeChoose uint32) uint16 

```

入参：
        pubkey     ： 公钥
        ID         ： 待验证方标识符，仅SM2签名时需要传入
        IDlen      ： 待验证方标识符长度
        message    ： 待验证的消息
        message_len： 待签名的消息长度
        signature  ： 签名值
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
                            ECC_CURVE_ED25519_NORMAL(0xECC00003)
                            ECC_CURVE_ED25519(0xECC00004)
	                    ECC_CURVE_X25519 (0xECC00005)
出参：   无
返回值：
        uint16类型， 如下：
                        SUCCESS(0x0001)                      : 签名验证通过
                        FAILURE(0x0000)                      : 签名验证不通过
                        ECC_PUBKEY_ILLEGAL(0xE001)           : 传入了非法公钥
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
                        ECC_MISS_ID(0xE002)                  : SM2验签时未传入被验证方标识符

```
- 加密：

   func Encryption(pubkey []byte, plain []byte, plain_len uint16, cipher []byte, typeChoose uint32) (ret, cipher_len uint16) 
```
入参：
        pubkey     ：公钥
        plain      ：明文
        plain_len  ：明文长度
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参：  
        cipher     ： 密文
返回值：
        ret： 结果返回码，如下：
                        SUCCESS(0x0001)                      : 加密成功
                        ECC_PUBKEY_ILLEGAL(0xE001)           : 传入了非法公钥
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type   
        cipher_len： 密文长度(目前架构下，SM2的密文长度为 plain_len + 97)
Tips：
        目前仅支持国密居推荐sm2参数的加密
```
- 解密：

   func Decryption(prikey []byte, cipher []byte, cipher_len uint16, plain []byte, typeChoose uint32) (ret, plain_len uint16) 
```
入参：
        prikey     ： 私钥
        cipher     ： 密文
        cipher_len ： 密文长度
        typeChoose ： 算法类型选择，可选参数如下
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
        plain      ： 明文
返回值：
        ret： 结果如下：
                        SUCCESS(0x0001)                      : 解密成功
                        FAILURE(0x0000)                      : 解密失败，密文非法
                        ECC_PRIKEY_ILLEGAL(0xE000)           : 传入了非法私钥
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
        plain_len  ： 明文长度(当前架构下，SM2明文长度为cipher_len - 97)
Tips：
        目前仅支持国密居推荐sm2参数的解密
```
- 协商：
```
Diffi-Hellman模式协商流程：
        1. KeyAgreement_initiator_step1
        2. KeyAgreement_responder_step1
        3. KeyAgreement_initiator_step2
        4. KeyAgreement_responder_step2
ElGamal模式协商流程：
        1. KeyAgreement_initiator_step1
        2. KeyAgreement_responder_ElGamal_step1
        3. KeyAgreement_initiator_step2
        4. KeyAgreement_responder_step2
```
   func KeyAgreement_initiator_step1(tmpPrikeyInitiator []byte, tmpPubkeyInitiator []byte, typeChoose uint32)
```
入参：
        typeChoose              ： 算法类型选择，目前仅支持sm2p256v1
                                       ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
        tmpPrikeyInitiator      ： 发起方临时私钥
        tmpPubkeyInitiator      ： 发起方临时公钥
返回值：
        无
```

   func KeyAgreement_initiator_step2(IDinitiator []byte, IDinitiator_len uint16, IDresponder []byte, IDresponder_len uint16, prikeyInitiator []byte,  pubkeyInitiator []byte, pubkeyResponder []byte, tmpPrikeyInitiator []byte, tmpPubkeyInitiator []byte, tmpPubkeyResponder []byte, Sin []byte, Sout []byte,  keylen uint16,  key []byte,  typeChoose uint32) uint16
```
入参：
        IDinitiator             ： 发起方标识符
        IDinitiator_len         ： 发起方标识符长度
        IDresponder             ： 响应方标识符
        IDresponder_len         ： 响应方标识符长度
        prikeyInitiator         ： 发起方私钥
        pubkeyInitiator         ： 发起方公钥
        pubkeyResponder         ： 响应方公钥
        tmpPrikeyInitiator      ： 发起方临时私钥
        tmpPubkeyInitiator      ： 发起方临时公钥
        tmpPubkeyResponder      ： 响应方临时公钥
        Sin                     ： 响应方发来的校验值
        keylen                  ： 期待的协商结果长度
        typeChoose              ： 算法类型选择，目前仅支持sm2p256v1
                                       ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
        Sout                    ： 发送给响应方的校验值
        key                     ： 协商结果
返回值：
        uint16类型， 结果如下：
                        SUCCESS(0x0001)                      : 发起方协商成功
                        FAILURE(0x0000)                      : 发起方协商失败
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
```

  func KeyAgreement_responder_step1(IDinitiator []byte, IDinitiator_len uint16, IDresponder []byte, IDresponder_len uint16, prikeyResponder []byte, pubkeyResponder []byte, pubkeyInitiator []byte, tmpPubkeyResponder []byte, tmpPubkeyInitiator []byte, Sinner []byte, Souter []byte, keylen uint16, key []byte, typeChoose uint32) uint16
```
入参：
        IDinitiator             ： 发起方标识符
        IDinitiator_len         ： 发起方标识符长度
        IDresponder             ： 响应方标识符
        IDresponder_len         ： 响应方标识符长度
        prikeyResponder         ： 响应方私钥
        pubkeyResponder         ： 响应方公钥
        pubkeyInitiator         ： 发起方公钥
        tmpPubkeyResponder      ： 响应方临时公钥
        tmpPubkeyInitiator      ： 发起方临时公钥
        keylen                  ： 期待的协商结果长度
        typeChoose              ： 算法类型选择，目前仅支持sm2p256v1
                                       ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
        Sinner                  ： 本地暂存的校验值
        Souter                  ： 发送给发起方的校验值
        key                     ： 协商结果
返回值：
        uint16类型， 结果如下：
                        SUCCESS(0x0001)                      : 响应方产生成功
                        FAILURE(0x0000)                      : 响应方协商失败
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
```
func KeyAgreement_responder_ElGamal_step1(IDinitiator []byte,IDinitiator_len uint16,IDresponder []byte,IDresponder_len uint16,prikeyResponder []byte,pubkeyResponder []byte,pubkeyInitiator []byte,tmpPubkeyInitiator []byte,keylen uint16,random []byte,typeChoose uint32) (key, tmpPubkeyResponder, Sinner, Souter []byte, ret uint16)
```
入参：
        IDinitiator             ： 发起方标识符
        IDinitiator_len         ： 发起方标识符长度
        IDresponder             ： 响应方标识符
        IDresponder_len         ： 响应方标识符长度
        prikeyResponder         ： 响应方私钥
        pubkeyResponder         ： 响应方公钥
        pubkeyInitiator         ： 发起方公钥
        tmpPubkeyResponder      ： 响应方临时公钥
        keylen                  ： 期待的协商结果长度
        random                  ： 固定临时私钥
        typeChoose              ： 算法类型选择，目前仅支持sm2p256v1
                                       ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
        Sinner                  ： 本地暂存的校验值
        Souter                  ： 发送给发起方的校验值
        key                     ： 协商结果
返回值：
        uint16类型， 结果如下：
                        SUCCESS(0x0001)                      : 响应方产生成功
                        FAILURE(0x0000)                      : 响应方协商失败
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
```

  func KeyAgreement_responder_step2(Sinitiator []byte, Sresponder []byte, typeChoose uint32) uint16 
```
入参：
        Sinitiator              ： 发起方发来的校验值
        Sresponder              ： 响应方暂存的校验值
        typeChoose              ： 算法类型选择，目前仅支持sm2p256v1
                                       ECC_CURVE_SM2_STANDARD(0xECC00002)
出参： 
       无
返回值：
        uint16类型， 结果如下：
                        SUCCESS(0x0001)                      : 响应方协商成功
                        FAILURE(0x0000)                      : 响应方协商失败
                        ECC_WRONG_TYPE(0xE002)               : 传入了错误的type
```

- G点相乘：

   func Point_mulBaseG(scalar []byte, typeChoose uint32) []byte

```
入参:
        scalar     : 乘子
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
                            ECC_CURVE_ED25519(0xECC00004)
	                    ECC_CURVE_X25519 (0xECC00005)
出参:    
        pubkey    : 公钥
返回值： uint16类型，如下：
                        SUCCESS(0x0001)                 : 生成成功
                        ECC_PRIKEY_ILLEGAL(0xE000)      : 传入了非法私钥
                        ECC_WRONG_TYPE(0xE002)          : 传入了错误的type
Tips：
        对于ECDSA类曲线算法，接口返回的公钥为压缩的坐标点形式
        对于EDDSA类曲线算法，由于curve25519的特殊性，此处可用ED25519进行计算，但与其私钥到公钥的计算流程并不一致
```

- G点的乘加操作： [scalar] * G + pointin

   func Point_mulBaseG_add(pointin, scalar []byte, typeChoose uint32) (point []byte, isinfinity bool)

```
入参:
        pointin    : 用于相加的点
        scalar     : 乘子
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
                            ECC_CURVE_ED25519(0xECC00004)
	                    ECC_CURVE_X25519 (0xECC00005)
出参:    
        pubkey    : 公钥
返回值： uint16类型，如下：
                        SUCCESS(0x0001)                 : 生成成功
                        ECC_PRIKEY_ILLEGAL(0xE000)      : 传入了非法私钥
                        ECC_WRONG_TYPE(0xE002)          : 传入了错误的type
Tips：
        对于ECDSA类曲线算法，接口返回的公钥为未压缩的坐标点形式，X坐标在前，Y坐标在后，无前缀(0x04)
        对于EDDSA类曲线算法，由于curve25519的特殊性，此处可用ED25519进行计算，但与其私钥到公钥的计算流程并不一致
```
- 获取曲线的基域特征
   func GetCurveOrder(typeChoose uint32) []byte
```
入参:
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参:    
        []byte    : 基域特征
```
- 点的压缩
   func PointCompress(point []byte, typeChoose uint32) []byte
```
入参:
        point      : 待压缩的点
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参:    
        []byte    : 压缩后的点
Tips：
        入参的待压缩点可以是X+Y的形式，也可以是0x04+X+Y的形式，均可以识别
```
- 点的解压缩
   func PointDecompress(point []byte, typeChoose uint32) []byte
```
入参:
        point      : 待解压缩的点
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参:    
        []byte    : 解压缩后的点
Tips：
        解压缩后的点是0x04+X+Y的形式
```
- 从签名恢复公钥
func RecoverPubkey(sig []byte, msg []byte, typeChoose uint32) ([]byte, uint16)
```
入参:
        sig        : 签名
        msg        : 签名对应的消息
        typeChoose : 算法类型选择，可选参数如下
                            ECC_CURVE_SECP256K1(0xECC00000)
                            ECC_CURVE_SECP256R1(0xECC00001)
                            ECC_CURVE_PRIMEV1(0xECC00001)
                            ECC_CURVE_NIST_P256(0xECC00001)
                            ECC_CURVE_SM2_STANDARD(0xECC00002)
出参:    
        []byte    : 解压缩后的点
Tips：
        签名采用 R || S || V 的形式顺序排放
```
- 点的域坐标转换：

   func CURVE25519_convert_X_to_Ed(x []byte) ([]byte, error)
```
入参:
        x          : x25519坐标点
出参:    
        []byte     : ed25519坐标点
返回值：
        error      : nil时为转换正确
```

   func CURVE25519_convert_Ed_to_X(ed []byte) ([]byte, error)

```
入参:
        x          : ed25519坐标点
出参:    
        []byte     : x25519坐标点
返回值：
        error      : nil时为转换正确
```
- 哈希算法：
   func Hash(data []byte, digestLen uint16, typeChoose uint32)
```
入参:
        data       : 原始数据
        digestLen  : blake2b类似的哈希算法需要指定的摘要长度，其他类型时无效
        typeChoose : 类型选择，可选参数如下：
                        HASH_ALG_SHA1(0xA0000000)
                        HASH_ALG_SHA3_256(0xA0000001)
                        HASH_ALG_SHA256(0xA0000002)
                        HASH_ALG_SHA512(0xA0000003)
                        HASH_ALG_MD4(0xA0000004)
                        HASH_ALG_MD5(0xA0000005)
                        HASH_ALG_RIPEMD160(0xA0000006)
                        HASH_ALG_BLAKE2B(0xA0000007)
                        HASH_ALG_BLAKE2S(0xA0000008)
                        HASH_ALG_SM3(0xA0000009)
                        HASh_ALG_DOUBLE_SHA256(0xA000000A)
                        HASH_ALG_HASH160(0xA000000B)
                        HASH_ALG_BLAKE256(0xA000000C)
                        HASH_ALG_BLAKE512(0xA000000D)
                        HASH_ALG_KECCAK256(0xA000000E)
                        HASH_ALG_KECCAK256_RIPEMD160(0xA000000F)
                        HASH_ALG_SHA3_256_RIPEMD160(0xA0000010)
                        HASH_ALG_KECCAK512(0xA0000011)
                        HASH_ALG_SHA3_512(0xA0000012)
出参:    
        []byte     : 哈希值
Tips：
        对于需要传入key的哈希算法，目前还不支持，按照默认方式进行计算。
```
- HMAC算法
   func Hmac(key []byte, data []byte, typeChoose uint32) []byte
```
入参:
        data       : 原始数据
        key        : 密钥
        typeChoose : 类型选择，可选参数如下：
                        HMAC_SHA256_ALG(0x50505050)
                        HMAC_SHA512_ALG(0x50505051)
                        HMAC_SM3_ALGuint32(0x50505052)
出参:
        []byte     : HMAC值
```
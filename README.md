# sm2js (jsrsasign-sm)
[![SM2JS CI](https://github.com/emmansun/sm2js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm2js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm2js.svg)](https://badge.fury.io/js/gmsm-sm2js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**sm2js is a pure Javascript implementation of the GM-Standards SM2 (also support sm3/sm4) based on [jsrsasign](https://github.com/kjur/jsrsasign).**

基于jsrsasign实现的优势在于充分利用jsrsasign的PKIX，CSR，CERT，PKCS8等处理能力。您也可以参考另外一个实现：[sjcl-sm](https://github.com/emmansun/sm4js)。

## 安全声明

**本库不承诺恒定时间（constant-time）运行，也不提供完整的侧信道防护保证。** Constant-time 指控制流和内存访问模式不依赖秘密数据，而不是每次调用的实际耗时完全相同。

JavaScript 引擎的 JIT 优化、垃圾回收及底层执行行为不受本库控制。SM2 依赖 jsrsasign 的大整数和椭圆曲线运算，纯 JavaScript SM4 使用秘密相关的查表访问，均不能视为 constant-time 实现。输入合法性检查、C3 的 XOR 累积比较和统一错误信息不能消除时间、缓存等侧信道风险，也不能保证解密接口不会形成可观测的 oracle。

NodeJS 环境下使用原生 SM3/SM4 并不意味着整个库具有 constant-time 保证，具体安全性质仍取决于底层实现和运行环境。对侧信道防护有严格要求的场景，应使用经过审计、对目标算法及平台明确提供相应保证的原生密码库、系统接口或硬件实现，并评估应用层的错误处理与接口暴露方式。

## SM2

- sign/verify functions (Passed integration test with ALI KMS)
- sm2Sign/sm2Verify functions (include uid and curve related parameters in signature)
- encrypt/decrypt functions (Passed integration test with ALI KMS), support both PLAIN and ASN.1 encoding format ciphertext output
- SM2 certificate signing request generation and parse
- SM2 certificate parse and verify signature, test CA & certificate are generated from https://www.gmcert.org/
- Parse SM2 private key in PKCS8 format (both encrypted and plaintext).

For usage, please reference [sm2_test.js](https://github.com/emmansun/sm2js/blob/master/test/sm2_test.js "sm2_test.js")

### 点校验与 jsrsasign 扩展边界

SM2 解密在使用私钥做标量乘法之前，校验 C1 的非压缩编码、坐标范围和曲线方程，并拒绝无穷远共享点。SM2 曲线的余因子为 1，合法非无穷远曲线点无需额外的子群检查。ASN.1 坐标在重新编码之前校验，避免超长整数被截断；C3 必须为 32 字节。

0.7.1 发布源码缺少 C1 曲线成员校验，不符合 SM2 解密算法的点校验要求。C3 完整性校验不能替代 C1 校验；这一缺陷本身并不证明具体部署环境下已经能够恢复私钥。

SM2 操作使用内部 ECDSA 密钥副本，不再改写调用方传入对象的签名、验签方法，也不再修改 BigInteger 原型。SM3withSM2 仅接受 SM2 曲线密钥。

SM2 私钥统一要求 `0 < d < n - 1`，即 `[1, n-2]`，签名、解密及由私钥派生公钥时均拒绝 `n-1`。预哈希验签也会校验公钥编码、坐标范围与曲线成员关系。重新调用签名对象的 `init` 会清空旧密钥和未完成的摘要状态。

UID 未传或为 `null` 时使用默认值；显式空字符串和空字节数组均表示空 UID。空消息可以签名，但 SM2 加密不接受空明文，解密不接受空 C2。ASN.1 密文按实际结构校验，不受裸密文最小编码长度限制。十六进制输入必须为偶数长度且不含空白、前缀或其他非法字符。

为兼容现有 PKCS8、CSR 和证书用法，加载模块仍会注册曲线/OID 并安装幂等的国密兼容补丁。Cipher 只扩展 SM4，其他算法委托 jsrsasign；PBES2 复用上游解析和非国密派生实现，补充可选 keyLength 后的 PRF 解析以及 SM3/SM4 支持；非 SM2 CSR 生成同样委托上游。这不是完全隔离、无全局副作用的插件接口。

## SM3
**SM3**使用比较简单，请参考[cryptojs_sm3_test.js](https://github.com/emmansun/sm2js/blob/master/test/cryptojs_sm3_test.js "cryptojs_sm3_test.js")。单独的**SM3**实现，可以参考[gmsm-sm3js](https://github.com/emmansun/sm3js)。

## SM4
[jsrsasign](https://github.com/kjur/jsrsasign) 内嵌了[crypto-js](https://github.com/brix/crypto-js)的剪裁版本，只支持默认的**CBC**模式和**PKCS7填充**模式（本实现为了测试，添加了ECB模式和无填充填充模式）。本**SM4**实现同时实现了[sjcl](https://github.com/bitwiseshiftleft/sjcl)所需方法，所以可以和sjcl支持的加密模式一起使用。具体使用方法，请参考[cryptojs_sm4_test.js](https://github.com/emmansun/sm2js/blob/master/test/cryptojs_sm4_test.js "cryptojs_sm4_test.js")。当然，把本**SM4**实现和独立的[crypto-js](https://github.com/brix/crypto-js)结合使用也是可以的。

在 NodeJS 环境下，扩展的 `KJUR.crypto.Cipher.encrypt` 和 `KJUR.crypto.Cipher.decrypt` 对 `sm4-CBC` 优先使用 NodeJS Native 实现，不可用时使用 CryptoJS 实现。AES、3DES 等非 SM4 算法保留 jsrsasign 原实现的行为。

SM4-CBC 兼容入口在两条路径下均要求 16 字节密钥、16 字节 IV，并检查密文分组长度及 PKCS#7 填充；SM4 允许空明文。CBC 不提供消息认证，填充校验不能替代 MAC 或认证加密。默认 `npm test` 会额外强制关闭原生 SM3/SM4，运行 SM2 和 SM4 兼容入口的回退测试。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm2js
[npm-url]: https://npmjs.org/package/gmsm-sm2js

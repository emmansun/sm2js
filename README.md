# sm2js
[![SM2JS CI](https://github.com/emmansun/sm2js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm2js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm2js.svg)](https://badge.fury.io/js/gmsm-sm2js)
[![NPM Downloads][npm-downloads-image]][npm-url]

sm2js（npm 包名 `gmsm-sm2js`）基于 [jsrsasign](https://github.com/kjur/jsrsasign) 提供 SM2、SM3 和 SM4 的 JavaScript 实现，并复用其密钥、PKCS#8、CSR 和 X.509 处理能力。在 Node.js 环境下，部分 SM3/SM4 操作会优先使用可用的原生实现。

> **安全提示：本库不承诺恒定时间（constant-time）运行，也不提供完整的侧信道防护保证。SM4-CBC 不提供消息认证。** 对侧信道防护有严格要求的场景，应使用对目标算法及平台明确提供相应保证的实现。详见[安全与兼容性](#安全与兼容性)。

## 安装

```bash
npm install gmsm-sm2js
```

下列示例为 Node.js CommonJS 代码。SM2 示例只需本包；SM3/SM4 示例直接使用 jsrsasign 的 CryptoJS 或 Cipher API，因此需要额外声明该依赖：

```bash
npm install jsrsasign@^11.1.4
```

## 快速开始

### SM2 加解密

```javascript
const sm2 = require('gmsm-sm2js')

const keys = sm2.generateKeyPair()
const ciphertextHex = sm2.encrypt(keys.pubKeyObj, 'hello SM2')
const plaintextHex = sm2.decryptHex(keys.prvKeyObj, ciphertextHex)

console.log(Buffer.from(plaintextHex, 'hex').toString('utf8'))
```

输出 `hello SM2`。加密返回十六进制密文；**解密返回十六进制明文，不是 UTF-8 字符串**。二进制明文不应按 UTF-8 解码。

默认密文为非压缩 C1 点开头的 `C1 || C3 || C2` 裸格式，不支持直接输入 `C1 || C2 || C3`。需要 ASN.1 格式时，向 `encrypt` 的第三个参数传入 `sm2.asn1EncrypterOptions()`；`decryptHex` 可识别裸格式和 ASN.1 格式。

### SM2 消息签名与验签

普通消息签名应使用 `sm2Sign/sm2Verify`。这两个方法自动计算 ZA，再计算消息摘要；UID 和曲线参数参与摘要计算，**不会直接嵌入 DER 签名**，双方需要事先约定相同的 UID。

```javascript
const sm2 = require('gmsm-sm2js')

const keys = sm2.generateKeyPair()
const signer = sm2.createSM2Signature()
signer.init(keys.prvKeyObj)
const signatureHex = signer.sm2Sign('hello SM2')

const verifier = sm2.createSM2Signature()
verifier.init(keys.pubKeyObj)
console.log(verifier.sm2Verify(signatureHex, 'hello SM2'))
```

输出 `true`。如需自定义 UID，将相同的字符串或字节数组分别作为 `sm2Sign(message, uid)` 和 `sm2Verify(signatureHex, message, uid)` 的参数。不要在这两个方法之前调用 `update`。

### SM3 摘要

加载本包后，SM3 和 SM4 注册在 jsrsasign 自带的 `CryptoJS` 实例上，不是本包入口对象上的方法。

```javascript
require('gmsm-sm2js')
const rs = require('jsrsasign')

console.log(rs.CryptoJS.SM3('abc').toString(rs.CryptoJS.enc.Hex))
```

输出 `66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0`。

### SM4-CBC 加解密

以下示例使用带 PKCS#7 填充的 SM4-CBC 兼容入口。**CBC 不提供完整性或来源认证**；实际协议需要 MAC 或认证加密，不能把填充校验当作认证。密钥应安全保存，IV 应为每次加密生成的不可预测随机值，并随密文一起传递。

```javascript
require('gmsm-sm2js')
const rs = require('jsrsasign')
const { randomBytes } = require('node:crypto')

const keyHex = randomBytes(16).toString('hex')
const ivHex = randomBytes(16).toString('hex')
const plaintextHex = Buffer.from('hello SM4', 'utf8').toString('hex')
const cipher = rs.KJUR.crypto.Cipher

const ciphertextHex = cipher.encrypt(plaintextHex, keyHex, 'sm4-CBC', { iv: ivHex })
const decryptedHex = cipher.decrypt(ciphertextHex, keyHex, 'sm4-CBC', { iv: ivHex })
console.log(Buffer.from(decryptedHex, 'hex').toString('utf8'))
```

输出 `hello SM4`。该入口要求 16 字节密钥和 16 字节 IV，允许空明文，解密时检查分组长度及填充。直接使用底层 `CryptoJS.SM4` 时，不应假设它具有兼容入口相同的参数与填充检查。

## API 与编码约定

### SM2

| API | 输入与行为 | 返回值 |
| --- | --- | --- |
| `generateKeyPair()` | 生成 SM2 密钥，确保私钥位于 `(0, n-1)` | `{ prvKeyObj, pubKeyObj }` 密钥对象 |
| `encrypt(publicKey, data, options)` | UTF-8 字符串或 `Uint8Array` 明文 | 十六进制密文 |
| `encryptHex(publicKey, plaintextHex, options)` | 十六进制明文 | 十六进制密文 |
| `decryptHex(privateKey, ciphertextHex)` | 裸格式或 ASN.1 十六进制密文 | 十六进制明文 |
| `decrypt(privateKey, ciphertext)` | 裸格式密文字节数组 | 十六进制明文 |
| `plainCiphertext2ASN1(ciphertextHex)` | 裸格式转换为 ASN.1 | 十六进制密文 |
| `asn1Ciphertext2Plain(ciphertextHex)` | ASN.1 转换为裸格式 | 十六进制密文 |
| `createSM2Signature()` | 创建 SM2 签名或验签对象，再用 `init(key)` 初始化 | `Signature` 对象 |
| `sm2Sign(message, uid)` | 完整消息，自动计算 ZA 与摘要 | DER 签名的十六进制编码 |
| `sm2Verify(signatureHex, message, uid)` | DER 签名、完整消息和相同 UID | 验证结果 |

`sm2Sign/sm2Verify` 是 `Signature` 实例方法。`sign/verify` 不自动加入 ZA；`signWithMessageHash/verifyWithMessageHash` 处理调用方已计算好的摘要，不再次哈希。只有明确掌握对端摘要约定时才应使用这些较低层接口，不能把普通消息摘要直接当作包含 ZA 的 SM2 消息摘要。

`generateKeyPair()` 返回的两个对象可直接传入加解密方法或 `Signature.init`，无需指定曲线。需要导出十六进制时，分别读取 `keys.prvKeyObj.prvKeyHex` 和 `keys.pubKeyObj.pubKeyHex`；不要将私钥写入日志或公开输出。

- SM2 曲线为 `sm2p256v1`。公钥可传 jsrsasign `ECDSA` 对象，或 `04 || X || Y` 的非压缩点十六进制编码，共 130 个字符。
- 私钥可传 `ECDSA` 对象，或无 `0x` 前缀的十六进制整数，范围为 `0 < d < n - 1`，即 `[1, n-2]`。建议使用左侧补零的 64 字符形式；解析也接受不超过 64 字符的短整数形式，不要求偶数长度。
- `Signature.init` 还可通过 jsrsasign 读取 PEM 等密钥形式。重新调用 `init` 会清空旧密钥和未完成的摘要状态。
- UID 未传或为 `null` 时使用 `1234567812345678`。显式空字符串和空字节数组都表示空 UID；UID 按 UTF-8 或字节数组处理，长度不得超过 8191 字节。
- 空消息可以签名。SM2 加密不接受空明文，解密不接受空 C2。
- 用于表示字节串的十六进制输入必须为偶数长度，且不含空白、`0x` 前缀或非法字符。字符串消息与十六进制字节串不能混用。
- 密文、密钥或格式错误可能抛出异常；验签不通过返回 `false`，无效的密钥等参数也可能导致异常。调用方应处理失败，不应继续使用未验证的数据。

### 密钥、CSR 与证书

本包支持 SM2 明文及加密 PKCS#8 私钥读取、CSR 生成与解析，以及通过 `createX509()` 验证 SM2 证书签名。证书签名验证不等同于完整的信任链、有效期或证书用途校验。

完整用例见 [SM2 测试](https://github.com/emmansun/sm2js/blob/main/test/sm2_test.js)。测试包含阿里云 KMS 的签名及 CSR 样本，但不是对所有 KMS 配置或版本的兼容保证。

SM3 的更多输入示例见 [SM3 测试](https://github.com/emmansun/sm2js/blob/main/test/cryptojs_sm3_test.js)；底层 SM4 及 SJCL GCM 接入示例见 [SM4 测试](https://github.com/emmansun/sm2js/blob/main/test/cryptojs_sm4_test.js)。本包不会自动扩展独立安装的 `crypto-js` 实例。

## 运行环境

- 提供 CommonJS 模块入口；当前 CI 覆盖 Node.js 22、24、26。这是测试范围，不是对更早版本兼容性的声明。
- SM2 运算使用 JavaScript 实现。SM2 内部的 SM3 摘要及 SM4-CBC 兼容入口会优先使用 Node.js 中可用的原生实现，不可用时回退到 JavaScript；直接调用 `rs.CryptoJS.SM3/SM4` 则使用 JavaScript 实现。
- 纯 JavaScript 回退测试仍在 Node.js 中运行，不等同于浏览器兼容性验证。浏览器使用需要构建工具处理 CommonJS 和可选的 Node.js `crypto` 依赖，本仓库没有提供直接通过 `<script>` 加载的构建产物。

## 安全与兼容性

### 侧信道限制

**本库不承诺 constant-time 运行，也不提供完整的侧信道防护保证。** Constant-time 关注控制流和内存访问模式是否依赖秘密数据，而不是每次调用耗时是否完全相等。

JavaScript 引擎的 JIT 优化、垃圾回收及底层执行行为不受本库控制。SM2 依赖 jsrsasign 的大整数和椭圆曲线运算，纯 JavaScript SM4 使用秘密相关的查表访问，均不能视为 constant-time 实现。输入检查、C3 的 XOR 累积比较及统一错误信息不能消除时间、缓存等侧信道风险，也不能保证解密接口不会形成可观测的 oracle。

使用原生 SM3/SM4 不意味着整个库具有 constant-time 保证。对侧信道防护有严格要求的场景，应选择经过审计、对目标算法及平台明确提供相应保证的原生密码库、系统接口或硬件实现，并评估应用层错误处理与接口暴露方式。

### 加载副作用与校验边界

加载模块会为共享的 jsrsasign 实例注册曲线、OID、SM3/SM4 算法并安装兼容补丁，因此本包不是无全局副作用的插件。SM2 操作使用内部密钥副本，不改写调用方传入对象的签名或验签方法，也不修改 BigInteger 原型。

Cipher 补丁只扩展 SM4；AES、3DES 等其他算法委托上游实现。PBES2 复用上游解析与非国密派生实现，补充可选 `keyLength` 后的 PRF 解析和 SM3/SM4 支持；非 SM2 CSR 生成也委托上游。

SM2 解密在私钥标量乘法之前校验 C1 的编码、坐标范围和曲线方程，并拒绝无穷远共享点；预哈希验签同样检查公钥。SM2 曲线余因子为 1，合法非无穷远曲线点无需额外子群检查。ASN.1 坐标在重新编码前校验，C3 必须为 32 字节；完整性校验不能替代点校验。

## 变更记录

版本变化及升级注意事项见 [CHANGELOG](CHANGELOG.md)。

## 测试

从源码仓库运行：

```bash
npm ci
npm test
```

测试包括 Standard 风格检查、已知摘要与加密向量、签名验签、非法输入、CSR/证书样本和兼容性回归。默认测试会额外启动子进程，强制禁用原生 SM3/SM4 并验证回退路径；CI 还分别运行原生与纯 JavaScript 矩阵任务。测试通过不代表密码实现获得安全认证。

## 许可证

[Apache-2.0](LICENSE)。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm2js
[npm-url]: https://npmjs.org/package/gmsm-sm2js

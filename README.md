# sm2js
[![SM2JS CI](https://github.com/emmansun/sm2js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm2js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm2js.svg)](https://badge.fury.io/js/gmsm-sm2js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**sm2js is a pure Javascript implementation of the GM-Standards SM2 (also support sm3/sm4) based on [jsrsasign](https://github.com/kjur/jsrsasign).**

## SM2

- sign/verify functions (Passed integration test with ALI KMS)
- sm2Sign/sm2Verify functions (include uid and curve related parameters in signature)
- encrypt/decrypt functions (Passed integration test with ALI KMS), support both PLAIN and ASN.1 encoding format ciphertext output
- SM2 certificate signing request generation and parse
- SM2 certificate parse and verify signature, test CA & certificate are generated from https://www.gmcert.org/
- Parse SM2 private key in PKCS8 format (both encrypted and plaintext).

For usage, please reference [sm2_test.js](https://github.com/emmansun/sm2js/blob/master/src/sm2_test.js "sm2_test.js")

## SM3
**SM3**使用比较简单，请参考[cryptojs_sm3_test.js](https://github.com/emmansun/sm2js/blob/master/src/cryptojs_sm3_test.js "cryptojs_sm3_test.js")。单独的**SM3**实现，可以参考[gmsm-sm3js](https://github.com/emmansun/sm3js)。

## SM4
[jsrsasign](https://github.com/kjur/jsrsasign) 内嵌了[crypto-js](https://github.com/brix/crypto-js)的剪裁版本，只支持默认的**CBC**模式和**PKCS7填充**模式（本实现为了测试，添加了ECB模式和无填充填充模式）。本**SM4**实现同时实现了[sjcl](https://github.com/bitwiseshiftleft/sjcl)所需方法，所以可以和sjcl支持的加密模式一起使用。具体使用方法，请参考[cryptojs_sm4_test.js](https://github.com/emmansun/sm2js/blob/master/src/cryptojs_sm4_test.js "cryptojs_sm4_test.js")。当然，把本**SM4**实现和独立的[crypto-js](https://github.com/brix/crypto-js)结合使用也是可以的。单独的**SM4**实现，可以参考[gmsm-sm4js](https://github.com/emmansun/sm4js)。

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm2js
[npm-url]: https://npmjs.org/package/gmsm-sm2js

# sm2js
[![SM2JS CI](https://github.com/emmansun/sm2js/actions/workflows/ci.yml/badge.svg)](https://github.com/emmansun/sm2js/actions/workflows/ci.yml)
[![npm version](https://badge.fury.io/js/gmsm-sm2js.svg)](https://badge.fury.io/js/gmsm-sm2js)
[![NPM Downloads][npm-downloads-image]][npm-url]

**sm2js is a pure Javascript implementation of the GM-Standards SM2 (also support sm3/sm4).**

- sign/verify functions (Passed integration test with ALI KMS)
- sm2Sign/sm2Verify functions (include uid and curve related parameters in signature)
- encrypt/decrypt functions (Passed integration test with ALI KMS), support both PLAIN and ASN.1 encoding format ciphertext output
- SM2 certificate signing request generation and parse
- SM2 certificate parse and verify signature, test CA & certificate are generated from https://www.gmcert.org/
- Parse SM2 private key in PKCS8 format (both encrypted and plaintext).


For usage, please reference [sm2_test.js](https://github.com/emmansun/sm2js/blob/master/src/sm2_test.js "sm2_test.js")

[npm-downloads-image]: https://badgen.net/npm/dm/gmsm-sm2js
[npm-url]: https://npmjs.org/package/gmsm-sm2js

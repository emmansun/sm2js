const rs = require('jsrsasign')
const util = require('./util')
const KJUR = rs.KJUR
const C = rs.CryptoJS

function parsePBES2 (hP8Prv) {
  const pASN = rs.ASN1HEX.parse(hP8Prv)
  if (util.aryval(pASN, 'seq.0.seq.0.oid') !== 'pkcs5PBES2' ||
    util.aryval(pASN, 'seq.0.seq.1.seq.0.seq.0.oid') !== 'pkcs5PBKDF2') {
    throw new Error('not pkcs5PBES2 and pkcs5PBKDF2 used')
  }
  const pASNKDF = util.aryval(pASN, 'seq.0.seq.1.seq.0.seq.1.seq')
  if (pASNKDF === undefined) {
    throw new Error('PBKDF2 parameter not found')
  }
  const salt = util.aryval(pASNKDF, '0.octstr.hex')
  const hIter = util.aryval(pASNKDF, '1.int.hex')
  const prf = util.aryval(pASNKDF, `${pASNKDF.length - 1}.seq.0.oid`, 'hmacWithSHA1')
  let iter = -1
  try {
    iter = parseInt(hIter, 16)
  } catch (ex) {
    throw new Error('iter not proper value')
  }

  const encalg = util.aryval(pASN, 'seq.0.seq.1.seq.1.seq.0.oid')
  const enciv = util.aryval(pASN, 'seq.0.seq.1.seq.1.seq.1.octstr.hex')
  const enc = util.aryval(pASN, 'seq.1.octstr.hex')
  if (encalg === undefined || enciv === undefined || enc === undefined) {
    throw new Error('encalg, enciv or enc is undefined')
  }

  return {
    salt,
    iter,
    prf,
    encalg,
    enciv,
    enc
  }
}

function getDKFromPBES2Param (pPBES2, passcode) {
  const pHasher = {
    hmacWithSHA1: C.algo.SHA1,
    hmacWithSHA224: C.algo.SHA224,
    hmacWithSHA256: C.algo.SHA256,
    hmacWithSHA384: C.algo.SHA384,
    hmacWithSHA512: C.algo.SHA512,
    hmacWithSM3: C.algo.SM3
  }
  const pKeySize = {
    'des-EDE3-CBC': 192 / 32,
    'aes128-CBC': 128 / 32,
    'aes256-CBC': 256 / 32,
    'sm4-CBC': 128 / 32
  }

  const hasher = pHasher[pPBES2.prf]
  if (hasher === undefined) { throw new Error('unsupported prf') }

  const keysize = pKeySize[pPBES2.encalg]
  if (keysize === undefined) { throw new Error('unsupported encalg') }

  const wSalt = C.enc.Hex.parse(pPBES2.salt)
  const iter = pPBES2.iter
  try {
    const wKey = C.PBKDF2(passcode,
      wSalt,
      {
        keySize: keysize,
        iterations: iter,
        hasher
      })
    const keyHex = C.enc.Hex.stringify(wKey)
    return keyHex
  } catch (ex) {
    throw new Error('PBKDF2 error: ' + ex + ' ' + JSON.stringify(pPBES2) + ' ' + passcode)
  }
}

function patchSM3 () {
  KJUR.crypto.Util.DEFAULTPROVIDER.sm3 = 'cryptojs'
  KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME.sm3 = C.algo.SM3

  rs.asn1.x509.OID.name2oidList.sm3 = '1.2.156.10197.1.401.1'
  rs.asn1.x509.OID.name2oidList.hmacWithSM3 = '1.2.156.10197.1.401.2'
}

function patchSM4 () {
/**
 * encrypt raw string by specified key and algorithm<br/>
 * @name encrypt
 * @memberOf KJUR.crypto.Cipher
 * @function
 * @param {string} s input string to encrypt
 * @param {string} hexadecimal string of symmetric cipher key
 * @param {string} algName short/long algorithm name for encryption/decryption (OPTION)
 * @param {object} param parameters for synchronous cipher such as initial vector (OPTION)
 * @return {string} hexadecimal encrypted string
 * @since jsrsasign 6.2.0 crypto 1.1.10
 *
 * @description
 * This static method encrypts raw string with specified key and algorithm.
 * <br/>
 * NOTE: From jsrsasign 10.9.0, asymmetric cipher ({des-EDE3,sm4-CBC,aes{128,256}}-CBC) is also supported.
 * NOTE2: From jsrsasign 11.0.0, RSA and RSAOAEP encryption/decryption support is removed
 * because of Marvin attack vulnerability.
 *
 * @example
 * KJUR.crypto.Cipher.encrypt("12abcd...", "5a7d...", "aes256-CBC", { iv: "1b3c..." })
 * KJUR.crypto.Cipher.encrypt("12abcd...", "5a7d...", any, { encalg: "aes128-CBC", iv: "1b3c..." })
 * KJUR.crypto.Cipher.encrypt("12abcd...", any, any, { encalg: "des-EDE3-CBC", iv: "1b3c...", key: "3d41..." })
 * KJUR.crypto.Cipher.encrypt("12abcd...", "5a7d...", "sm4-CBC", { iv: "1b3c..." })
 * KJUR.crypto.Cipher.encrypt(any, any, any, { encalg: "des-EDE3-CBC", iv: "1b3c...", key: "3d41...", enc: "12abcd..." })
 */
  KJUR.crypto.Cipher.encrypt = function (s, keyObj, algName, param) {
    if (util.CryptoJSaryval(param, 'enclag') !== undefined) algName = param.encalg

    if (typeof algName === 'string' && algName.substr(-4) === '-CBC') {
      let hKey = keyObj
      const hPlain = s
      if (util.aryval(param, 'key') !== undefined) hKey = param.key
      // if (aryval(param, 'enc') !== undefined) hEnc = param.enc
      const wKey = C.enc.Hex.parse(hKey)
      const wPlain = C.enc.Hex.parse(hPlain)
      const wIV = C.enc.Hex.parse(param.iv)
      let wEnc
      if (algName === 'des-EDE3-CBC') {
        wEnc = C.TripleDES.encrypt(wPlain, wKey, { iv: wIV })
      } else if (algName === 'aes128-CBC' || algName === 'aes256-CBC') {
        wEnc = C.AES.encrypt(wPlain, wKey, { iv: wIV })
      } else if (algName === 'sm4-CBC') {
        wEnc = C.SM4.encrypt(wPlain, wKey, { iv: wIV })
      } else {
        throw new Error('unsupported algorithm: ' + algName)
      }
      return wEnc + ''
    } else {
      throw new Error('Cipher.encrypt: unsupported key or algorithm')
    }
  }

  /**
   * decrypt encrypted hexadecimal string with specified key and algorithm<br/>
   * @name decrypt
   * @memberOf KJUR.crypto.Cipher
   * @function
   * @param {string} hex hexadecimal string of encrypted message
   * @param {object} hexadecimal string of symmetric cipher key
   * @param {string} algName short/long algorithm name for encryption/decryption (OPTION)
   * @param {object} param parameters for synchronous cipher such as initial vector (OPTION)
   * @return {string} decrypted raw string
   * @since jsrsasign 6.2.0 crypto 1.1.10
   *
   * @description
   * This static method decrypts encrypted hexadecimal string with specified key and algorithm.
   * <br/>
   * NOTE: From jsrsasign 10.9.0, asymmetric cipher ({des-EDE3,sm4-CBC,aes{128,256}}-CBC) is also supported.
   * NOTE2: From jsrsasign 11.0.0, RSA and RSAOAEP encryption/decryption support is removed
   * because of Marvin attack vulnerability.
   *
   * @example
   * KJUR.crypto.Cipher.decrypt("12abcd...", "5a7d...", "aes256-CBC", { iv: "1b3c..." })
   * KJUR.crypto.Cipher.decrypt("12abcd...", "5a7d...", any, { encalg: "aes128-CBC", iv: "1b3c..." })
   * KJUR.crypto.Cipher.decrypt("12abcd...", any, any, { encalg: "des-EDE3-CBC", iv: "1b3c...", key: "3d41..." })
   * KJUR.crypto.Cipher.decrypt("12abcd...", "5a7d...", "sm4-CBC", { iv: "1b3c..." })
   * KJUR.crypto.Cipher.decrypt(any, any, any, { encalg: "des-EDE3-CBC", iv: "1b3c...", key: "3d41...", enc: "12abcd..." })
   */
  KJUR.crypto.Cipher.decrypt = function (hex, keyObj, algName, param) {
    if (util.aryval(param, 'enclag') !== undefined) algName = param.encalg

    if (typeof algName === 'string' && algName.substr(-4) === '-CBC') {
      let hKey = keyObj
      const hEnc = hex
      if (util.aryval(param, 'key') !== undefined) hKey = param.key
      // if (aryval(param, 'enc') !== undefined) hEnc = param.enc
      const wKey = C.enc.Hex.parse(hKey)
      const wEnc = C.enc.Hex.parse(hEnc)
      const wIV = C.enc.Hex.parse(param.iv)
      let wDec
      if (algName === 'des-EDE3-CBC') {
        wDec = C.TripleDES.decrypt({ ciphertext: wEnc }, wKey, { iv: wIV })
      } else if (algName === 'aes128-CBC' || algName === 'aes256-CBC') {
        wDec = C.AES.decrypt({ ciphertext: wEnc }, wKey, { iv: wIV })
      } else if (algName === 'sm4-CBC') {
        wDec = C.SM4.decrypt({ ciphertext: wEnc }, wKey, { iv: wIV })
      } else {
        throw new Error('unsupported algorithm: ' + algName)
      }
      return C.enc.Hex.stringify(wDec)
    } else {
      throw new Error('Cipher.decrypt: unsupported key or algorithm')
    }
  }

  rs.asn1.x509.OID.name2oidList['sm4-CBC'] = '1.2.156.10197.1.104.2'
}

function patch () {
  require('./cryptojs_sm3')
  require('./cryptojs_sm4')
  patchSM3()
  patchSM4()
  rs.KEYUTIL.parsePBES2 = parsePBES2
  rs.KEYUTIL.getDKFromPBES2Param = getDKFromPBES2Param
}

module.exports = {
  patch
}

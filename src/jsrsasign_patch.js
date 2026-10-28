const rs = require('jsrsasign')
const KJUR = rs.KJUR
const C = rs.CryptoJS
const CEnc = C.enc
const util = require('./util')

const originalParsePBES2 = rs.KEYUTIL.parsePBES2
const originalGetDKFromPBES2Param = rs.KEYUTIL.getDKFromPBES2Param

function parsePBES2 (hP8Prv) {
  const params = originalParsePBES2.call(rs.KEYUTIL, hP8Prv)
  const pASN = rs.ASN1HEX.parse(hP8Prv)
  const pASNKDF = rs.aryval(pASN, 'seq.0.seq.1.seq.0.seq.1.seq')
  params.prf = rs.aryval(pASNKDF, `${pASNKDF.length - 1}.seq.0.oid`, 'hmacWithSHA1')
  return params
}

function getDKFromPBES2Param (pPBES2, passcode) {
  const isGM = pPBES2.prf === 'hmacWithSM3' || pPBES2.encalg === 'sm4-CBC'
  if (!isGM) {
    try {
      return originalGetDKFromPBES2Param.call(rs.KEYUTIL, pPBES2, passcode)
    } catch (ex) {
      throw new Error('PBKDF2 error')
    }
  }
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
    throw new Error('PBKDF2 error')
  }
}

function patchSM3 () {
  KJUR.crypto.Util.DEFAULTPROVIDER.sm3 = 'cryptojs'
  KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME.sm3 = C.algo.SM3

  rs.asn1.x509.OID.name2oidList.sm3 = '1.2.156.10197.1.401.1'
  rs.asn1.x509.OID.name2oidList.hmacWithSM3 = '1.2.156.10197.1.401.2'
}

function sm4CipherParameters (hex, key, iv, decrypting = false) {
  const data = util.hexToUint8Array(hex)
  const keyBytes = util.hexToUint8Array(key)
  const ivBytes = util.hexToUint8Array(iv)
  if (keyBytes.length !== 16) {
    throw new Error('invalid sm4 key size')
  }
  if (ivBytes.length !== 16) {
    throw new Error('invalid sm4 iv size')
  }
  if (decrypting && (data.length === 0 || data.length % 16 !== 0)) {
    throw new Error('invalid sm4 ciphertext length')
  }
  return { data, keyBytes, ivBytes }
}

function patchSM4 () {
  let crypto
  let useNodeSM4 = false
  try {
    crypto = require('crypto')
    useNodeSM4 = crypto.getCiphers().indexOf('sm4-cbc') >= 0
  } catch (err) {
    console.log('crypto support is disabled!')
  }
  const originalEncrypt = KJUR.crypto.Cipher.encrypt
  const originalDecrypt = KJUR.crypto.Cipher.decrypt
  KJUR.crypto.Cipher.encrypt = function (s, keyObj, algName, param) {
    const algorithm = rs.aryval(param, 'encalg', algName)
    if (algorithm !== 'sm4-CBC') {
      return originalEncrypt.call(this, s, keyObj, algName, param)
    }
    const key = rs.aryval(param, 'key', keyObj)
    const input = sm4CipherParameters(s, key, rs.aryval(param, 'iv'))
    if (useNodeSM4) {
      const cipher = crypto.createCipheriv('sm4-cbc', input.keyBytes, input.ivBytes)
      return cipher.update(input.data, undefined, 'hex') + cipher.final('hex')
    }
    return C.SM4.encrypt(C.enc.Hex.parse(s), C.enc.Hex.parse(key), { iv: C.enc.Hex.parse(param.iv) }).ciphertext.toString(C.enc.Hex)
  }

  KJUR.crypto.Cipher.decrypt = function (hex, keyObj, algName, param) {
    const algorithm = rs.aryval(param, 'encalg', algName)
    if (algorithm !== 'sm4-CBC') {
      return originalDecrypt.call(this, hex, keyObj, algName, param)
    }
    const key = rs.aryval(param, 'key', keyObj)
    const input = sm4CipherParameters(hex, key, rs.aryval(param, 'iv'), true)
    if (useNodeSM4) {
      try {
        const cipher = crypto.createDecipheriv('sm4-cbc', input.keyBytes, input.ivBytes)
        return cipher.update(input.data, undefined, 'hex') + cipher.final('hex')
      } catch (err) {
        throw new Error('sm4: decryption error')
      }
    }
    const plaintext = C.SM4.decrypt({ ciphertext: C.enc.Hex.parse(hex) }, C.enc.Hex.parse(key), { iv: C.enc.Hex.parse(param.iv), padding: C.pad.NoPadding })
    const bytes = CEnc.Uint8Array.stringify(plaintext)
    const paddingLength = bytes[bytes.length - 1]
    let invalid = paddingLength < 1 || paddingLength > 16 ? 1 : 0
    for (let offset = 1; offset <= 16; offset++) {
      if (offset <= paddingLength) invalid |= bytes[bytes.length - offset] ^ paddingLength
    }
    if (invalid !== 0) {
      throw new Error('sm4: decryption error')
    }
    plaintext.sigBytes -= paddingLength
    plaintext.clamp()
    return C.enc.Hex.stringify(plaintext)
  }

  rs.asn1.x509.OID.name2oidList['sm4-CBC'] = '1.2.156.10197.1.104.2'
}

function patchEncUint8Array () {
  CEnc.Uint8Array = CEnc.Uint8Array || {
    stringify: function (wordArray) {
      const bytes = []
      const words = wordArray.words
      const sigBytes = wordArray.sigBytes
      for (let i = 0; i < sigBytes; i++) {
        bytes.push((words[i >>> 2] >>> (24 - (i % 4) * 8)) & 0xff)
      }
      return new Uint8Array(bytes)
    },

    parse: function (uint8Array) {
      const words = []
      const dataLen = uint8Array.length
      for (let i = 0; i < uint8Array.length; i++) {
        words[i >>> 2] |= uint8Array[i] << (24 - (i % 4) * 8)
      }
      return C.lib.WordArray.create(words, dataLen)
    }
  }
}

let patched = false
function patch () {
  if (patched) return
  patched = true
  patchEncUint8Array()
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

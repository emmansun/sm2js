const rs = require('jsrsasign')
const KJUR = rs.KJUR
const C = rs.CryptoJS
const CAlgo = C.algo
const CLib = C.lib
const BlockCipher = CLib.BlockCipher

/**
 * SM4 block cipher algorithm.
 */
const SM4 = (CAlgo.SM4 = BlockCipher.extend({
  _doReset: function () {
    if (!this._tables[0][0]) {
      this._precompute()
    }
    const key = this._key
    const keyWords = key.words
    if (keyWords.length !== 4) {
      throw new Error('invalid sm4 key size')
    }

    // Compute key schedule
    const keySchedule = keyWords.slice(0)
    const invKeySchedule = []
    // schedule encryption keys
    for (let i = 0; i < 4; i++) {
      keySchedule[i] ^= this._fk[i]
    }
    const sbox = this._tables[4]
    const rounds = this._rounds
    let tmp
    for (let i = 0; i < rounds; i++) {
      tmp =
        keySchedule[i + 1] ^
        keySchedule[i + 2] ^
        keySchedule[i + 3] ^
        this._ck[i]
      tmp =
        (sbox[tmp >>> 24] << 24) |
        (sbox[(tmp >> 16) & 255] << 16) |
        (sbox[(tmp >> 8) & 255] << 8) |
        sbox[tmp & 255]
      tmp ^= (tmp << 13) ^ (tmp >>> 19) ^ (tmp << 23) ^ (tmp >>> 9)
      keySchedule[i + 4] = keySchedule[i] ^ tmp
      invKeySchedule[rounds - i - 1] = keySchedule[i + 4]
    }
    this._invKeySchedule = invKeySchedule.slice(0)
    this._keySchedule = keySchedule.slice(4)
  },

  encryptBlock: function (M, offset) {
    this._doCryptBlock(M, offset, this._keySchedule)
  },

  decryptBlock: function (M, offset) {
    this._doCryptBlock(M, offset, this._invKeySchedule)
  },

  _doCryptBlock: function (M, offset, keySchedule) {
    let a = M[offset]
    let b = M[offset + 1]
    let c = M[offset + 2]
    let d = M[offset + 3]

    a ^= this._t(b ^ c ^ d ^ keySchedule[0])
    b ^= this._t(c ^ d ^ a ^ keySchedule[1])
    c ^= this._t(d ^ a ^ b ^ keySchedule[2])
    d ^= this._t(a ^ b ^ c ^ keySchedule[3])

    for (let i = 4; i < 28; i = i + 4) {
      a ^= this._precomputedT(b ^ c ^ d ^ keySchedule[i])
      b ^= this._precomputedT(c ^ d ^ a ^ keySchedule[i + 1])
      c ^= this._precomputedT(d ^ a ^ b ^ keySchedule[i + 2])
      d ^= this._precomputedT(a ^ b ^ c ^ keySchedule[i + 3])
    }

    a ^= this._t(b ^ c ^ d ^ keySchedule[28])
    b ^= this._t(c ^ d ^ a ^ keySchedule[29])
    c ^= this._t(d ^ a ^ b ^ keySchedule[30])
    d ^= this._t(a ^ b ^ c ^ keySchedule[31])

    // Set output
    M[offset] = d
    M[offset + 1] = c
    M[offset + 2] = b
    M[offset + 3] = a
  },

  _sm4L: function (x) {
    const y = (x ^=
      (x << 1) ^
      (x >> 7) ^
      ((x << 3) ^ (x >> 5)) ^
      ((x << 6) ^ (x >> 2)) ^
      ((x << 7) ^ (x >> 1)) ^
      0xd3)
    return y & 0xff
  },

  _precompute: function () {
    // generate ck
    for (let i = 0; i < 32; i++) {
      const j = 4 * i
      this._ck[i] =
        (((j * 7) & 0xff) << 24) |
        ((((j + 1) * 7) & 0xff) << 16) |
        ((((j + 2) * 7) & 0xff) << 8) |
        (((j + 3) * 7) & 0xff)
    }
    this._ck = this._ck.slice(0)

    const sbox = this._tables[4]
    const tmp = []
    const reverseTable = []
    // generate elements of GF(2^8)
    let x = 1
    for (let i = 0; i < 256; i++) {
      tmp[i] = x
      reverseTable[x] = i
      x ^= (x << 1) ^ ((x >> 7) * 0x1f5)
    }

    for (let i = 0; i < 256; i++) {
      const x = this._sm4L(i)
      if (x === 0) {
        sbox[i] = this._sm4L(0)
      } else {
        sbox[i] = this._sm4L(tmp[255 - reverseTable[x]])
      }
      let tEnc =
        sbox[i] ^
        ((sbox[i] << 2) | (sbox[i] >>> 30)) ^
        ((sbox[i] << 10) | (sbox[i] >>> 22)) ^
        ((sbox[i] << 18) | (sbox[i] >>> 14)) ^
        ((sbox[i] << 24) | (sbox[i] >>> 8))
      for (let j = 0; j < 4; j++) {
        this._tables[j][i] = tEnc = (tEnc << 24) ^ (tEnc >>> 8)
      }
    }

    // Compactify.  Considerable speedup on Firefox.
    for (let i = 0; i < 5; i++) {
      this._tables[i] = this._tables[i].slice(0)
    }
  },
  _t: function (x) {
    const sbox = this._tables[4]
    const tmp =
      (sbox[x >>> 24] << 24) |
      (sbox[(x >> 16) & 255] << 16) |
      (sbox[(x >> 8) & 255] << 8) |
      sbox[x & 255]

    return (
      tmp ^
      ((tmp << 2) | (tmp >>> 30)) ^
      ((tmp << 10) | (tmp >>> 22)) ^
      ((tmp << 18) | (tmp >>> 14)) ^
      ((tmp << 24) | (tmp >>> 8))
    )
  },

  _precomputedT: function (x) {
    const t0 = this._tables[0]
    const t1 = this._tables[1]
    const t2 = this._tables[2]
    const t3 = this._tables[3]
    return (
      t0[x >>> 24] ^ t1[(x >>> 16) & 255] ^ t2[(x >>> 8) & 255] ^ t3[x & 255]
    )
  },
  _rounds: 32,
  _fk: [0xa3b1bac6, 0x56aa3350, 0x677d9197, 0xb27022dc],
  _tables: [[], [], [], [], []],
  _ck: []
}))

/**
 * Shortcut functions to the cipher's object interface.
 *
 * @example
 *
 *     var ciphertext = CryptoJS.SM4.encrypt(message, key, cfg);
 *     var plaintext  = CryptoJS.SM4.decrypt(ciphertext, key, cfg);
 */
C.SM4 = BlockCipher._createHelper(SM4)

/**
 * Electronic Codebook block mode.
 */
C.mode.ECB = (function () {
  const ECB = CLib.BlockCipherMode.extend()

  ECB.Encryptor = ECB.extend({
    processBlock: function (words, offset) {
      this._cipher.encryptBlock(words, offset)
    }
  })

  ECB.Decryptor = ECB.extend({
    processBlock: function (words, offset) {
      this._cipher.decryptBlock(words, offset)
    }
  })

  return ECB
}())

/**
 * A noop padding strategy.
 */
C.pad.NoPadding = {
  pad: function () {
  },

  unpad: function () {
  }
}

function aryval (val, keys, def) {
  if (typeof val !== 'object') return undefined
  const keyArr = String(keys).split('.')
  for (let i = 0; i < keyArr.length && val; i++) {
    let key = keyArr[i]
    if (key.match(/^[0-9]+$/)) key = parseInt(key)
    val = val[key]
  }
  return val || val === false ? val : def
}

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
  if (aryval(param, 'enclag') !== undefined) algName = param.encalg

  if (typeof algName === 'string' && algName.substr(-4) === '-CBC') {
    let hKey = keyObj
    const hPlain = s
    if (aryval(param, 'key') !== undefined) hKey = param.key
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
  if (aryval(param, 'enclag') !== undefined) algName = param.encalg

  if (typeof algName === 'string' && algName.substr(-4) === '-CBC') {
    let hKey = keyObj
    const hEnc = hex
    if (aryval(param, 'key') !== undefined) hKey = param.key
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
    console.log(C.enc.Hex.stringify(wDec))
    return C.enc.Hex.stringify(wDec)
  } else {
    throw new Error('Cipher.decrypt: unsupported key or algorithm')
  }
}

rs.asn1.x509.OID.name2oidList['sm4-CBC'] = '1.2.156.10197.1.104.2'

module.exports = SM4

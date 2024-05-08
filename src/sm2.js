const rs = require('jsrsasign')
require('./jsrsasign_patch').patch()
const util = require('./util')

let crypto
let useNodeSM3 = false
try {
  crypto = require('crypto')
  useNodeSM3 = crypto.getHashes().indexOf('sm3') >= 0
} catch (err) {
  console.log('crypto support is disabled!')
}

const SM3_SIZE = 32
const SM3_SIZE_BIT_SIZE = 5

const SM2_BIT_SIZE = 256
const SM2_BYTE_SIZE = 32
const UNCOMPRESSED = 0x04
const SM2_SIGN_ALG = 'SM3withSM2'
const DEFAULT_UID = '1234567812345678'
const MAX_RETRY = 100

const SM2_CURVE_NAME = 'sm2p256v1'
const SM2_CURVE_PARAM_P = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF'
const SM2_CURVE_PARAM_A = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC'
const SM2_CURVE_PARAM_B = '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93'
const SM2_CURVE_PARAM_N = 'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123'
const SM2_CURVE_PARAM_GX = '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7'
const SM2_CURVE_PARAM_GY = 'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0'
const SM2_CURVE_PARAMS_FOR_ZA = util.hexToUint8Array('FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E9332C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0')

const CIPHERTEXT_ENCODING_PLAIN = 0
const CIPHERTEXT_ENCODING_ASN1 = 1

rs.crypto.ECParameterDB.regist(
  SM2_CURVE_NAME, // name / p = 2**256 - 2**224 - 2**96 + 2**64 - 1
  SM2_BIT_SIZE,
  SM2_CURVE_PARAM_P, // p
  SM2_CURVE_PARAM_A, // a
  SM2_CURVE_PARAM_B, // b
  SM2_CURVE_PARAM_N, // n
  '1', // h
  SM2_CURVE_PARAM_GX, // gx
  SM2_CURVE_PARAM_GY, // gy
  []) // alias

const getNameFunc = rs.ECDSA.getName
rs.ECDSA.getName = function (s) {
  // {1, 2, 156, 10197, 1, 301}
  if (s === '2a811ccf5501822d') {
    return SM2_CURVE_NAME
  }
  return getNameFunc(s)
}

rs.asn1.x509.OID.name2oidList[SM2_SIGN_ALG] = '1.2.156.10197.1.501'
rs.asn1.x509.OID.name2oidList[SM2_CURVE_NAME] = '1.2.156.10197.1.301'

/**
 * Returns a byte array representation of the big integer.
 *
 * This returns the absolute of the contained value in big endian
 * form. A value of zero results in an empty array.
 */
rs.BigInteger.prototype.toByteArrayUnsigned = rs.BigInteger.prototype.toByteArrayUnsigned || function () {
  const byteArray = this.toByteArray()
  return byteArray[0] === 0 ? byteArray.slice(1) : byteArray
}

class EncrypterOptions {
  constructor (encodingFormat) {
    if (encodingFormat !== CIPHERTEXT_ENCODING_PLAIN && encodingFormat !== CIPHERTEXT_ENCODING_ASN1) {
      throw new Error('sm2: unsupport ciphertext encoding format')
    }
    this.encodingFormat = encodingFormat
  }

  getEncodingFormat () {
    return this.encodingFormat
  }
}

const DEFAULT_SM2_ENCRYPT_OPTIONS = new EncrypterOptions(CIPHERTEXT_ENCODING_PLAIN)

const sm2 = Symbol('sm2')

function adaptSM2 (ecdsa) {
  if (!ecdsa[sm2]) {
    ecdsa[sm2] = true
    /**
     * Encrypt data with SM2 alg
     * @param {string|Uint8Array} data The data to be encrypted
     * @param {EncrypterOptions} opts options for ciphertext format, default is C1C3C2
     * @returns hex string of ciphertext
     */
    ecdsa.encrypt = function (data, opts = DEFAULT_SM2_ENCRYPT_OPTIONS) {
      const Q = rs.ECPointFp.decodeFromHex(this.ecparams.curve, this.pubKeyHex)
      return this.encryptRaw(data, Q, opts)
    }

    /**
     * Encrypt hex data with SM2 alg
     * @param {string} data The  hex data to be encrypted
     * @param {EncrypterOptions} opts options for ciphertext format, default is C1C3C2
     * @returns hex string of ciphertext
     */
    ecdsa.encryptHex = function (dataHex, opts = DEFAULT_SM2_ENCRYPT_OPTIONS) {
      return this.encrypt(util.hexToUint8Array(dataHex), opts)
    }

    /**
     * Encrypt raw data with SM2 alg (internal function)
     * @param {Uint8Array} data The raw data to be encrypted
     * @param {ECPointFp} Q The ecc point of the public key
     * @param {EncrypterOptions} opts options for ciphertext format, default is C1C3C2
     * @returns hex string of ciphertext
     */
    ecdsa.encryptRaw = function (data, Q, opts = DEFAULT_SM2_ENCRYPT_OPTIONS) {
      if (!opts || !(opts instanceof EncrypterOptions)) {
        opts = DEFAULT_SM2_ENCRYPT_OPTIONS
      }
      data = util.normalizeInput(data)
      const n = this.ecparams.n
      const G = this.ecparams.G
      const dataLen = data.length
      const md = new MessageDigest()
      let count = 0
      if (Q.isInfinity()) {
        throw new Error('sm2: invalid public key')
      }
      do {
        const k = this.getBigRandom(n)
        const c1 = G.multiply(k)
        const s = Q.multiply(k)
        const c2 = kdf(Uint8Array.from(util.integerToBytes(s.getX().toBigInteger(), SM2_BYTE_SIZE).concat(util.integerToBytes(s.getY().toBigInteger(), SM2_BYTE_SIZE))), dataLen)
        if (!c2) {
          if (count++ > MAX_RETRY) {
            throw new Error('sm2: A5, failed to calculate valid t')
          }
          continue
        }
        for (let i = 0; i < dataLen; i++) {
          c2[i] ^= data[i]
        }
        md.update(Uint8Array.from(util.integerToBytes(s.getX().toBigInteger(), SM2_BYTE_SIZE)))
        md.update(data)
        md.update(Uint8Array.from(util.integerToBytes(s.getY().toBigInteger(), SM2_BYTE_SIZE)))
        const c3 = md.digestRaw()
        if (opts.getEncodingFormat() === CIPHERTEXT_ENCODING_PLAIN) {
          return util.toHex(c1.getEncoded(false)) + util.toHex(c3) + util.toHex(c2)
        }
        const derX = new rs.asn1.DERInteger({ bigint: c1.getX().toBigInteger() })
        const derY = new rs.asn1.DERInteger({ bigint: c1.getY().toBigInteger() })
        const derC3 = new rs.asn1.DEROctetString({ hex: util.toHex(c3) })
        const derC2 = new rs.asn1.DEROctetString({ hex: util.toHex(c2) })
        const derSeq = new rs.asn1.DERSequence({ array: [derX, derY, derC3, derC2] })
        return derSeq.tohex()
      } while (true)
    }

    /**
     * SM2 decryption
     * @param {String|Uint8Array} data The data to be decrypted
     * @return {String} decrypted hex content
     */
    ecdsa.decrypt = function (data) {
      const d = new rs.BigInteger(this.prvKeyHex, 16)
      return this.decryptRaw(data, d)
    }

    /**
     * SM2 decryption
     * @param {string} dataHex The hex data to be decrypted
     * @return {string} decrypted hex content
     */
    ecdsa.decryptHex = function (dataHex) {
      return this.decrypt(util.hexToUint8Array(dataHex))
    }

    /**
     * SM2 decryption (internal function)
     * @param {Uint8Array} data The hex data to be decrypted
     * @param {BigInteger} d The SM2 private key
     * @return {string} decrypted hex content
     */
    ecdsa.decryptRaw = function (data, d) {
      data = util.normalizeInput(data)
      const dataLen = data.length

      if (data[0] !== UNCOMPRESSED) {
        throw new Error('sm2: unsupport point marshal mode')
      }
      if (dataLen < 97) {
        throw new Error('sm2: invalid cipher content length')
      }
      const c1 = rs.ECPointFp.decodeFrom(this.ecparams.curve, Array.from(data.subarray(0, 65)))
      const s = c1.multiply(d)
      const c2 = data.subarray(97)
      const c3 = data.subarray(65, 97)
      const plaintext = kdf(Uint8Array.from(util.integerToBytes(s.getX().toBigInteger(), SM2_BYTE_SIZE).concat(util.integerToBytes(s.getY().toBigInteger(), SM2_BYTE_SIZE))), dataLen - 97)
      if (!plaintext) {
        throw new Error('sm2: invalid cipher content')
      }
      for (let i = 0; i < c2.length; i++) {
        plaintext[i] ^= c2[i]
      }
      // check c3
      const md = new MessageDigest()
      md.update(Uint8Array.from(util.integerToBytes(s.getX().toBigInteger(), SM2_BYTE_SIZE)))
      md.update(plaintext)
      md.update(Uint8Array.from(util.integerToBytes(s.getY().toBigInteger(), SM2_BYTE_SIZE)))
      const hash = md.digestRaw()
      let difference = 0
      for (let i = 0; i < hash.length; i++) {
        difference |= hash[i] ^ c3[i]
      }
      if (difference !== 0) {
        throw new Error('sm2: decryption error')
      }

      return util.toHex(plaintext)
    }

    /**
     * Sign the hash of message with given private key
     * @param {String} hashHex the hex string of hash
     * @param {String} privHex the hex string of the private key
     * @returns the hex string of the signature with asn1 format
     */
    ecdsa.signHex = function (hashHex, privHex) {
      const d = new rs.BigInteger(privHex, 16)
      return this._signHexInternal(hashHex, d)
    }

    /**
     * Sign the hash of message
     * @param {String} hashHex the hex string of hash
     * @returns the hex string of the signature with asn1 format
     */
    ecdsa.signWithMessageHash = function (hashHex) {
      if (!this._d) {
        this._d = new rs.BigInteger(this.prvKeyHex, 16)
      }
      if (!this._dp1Inv) {
        const n = this.ecparams.n
        this._dp1Inv = this._d.add(rs.BigInteger.ONE).modInverse(n)
      }
      return this._signHexInternal(hashHex, this._d, this._dp1Inv)
    }

    ecdsa._signHexInternal = function (hashHex, d, dp1Inv) {
      const n = this.ecparams.n
      const G = this.ecparams.G
      // message hash is truncated with curve key length (FIPS 186-4 6.4)
      const e = new rs.BigInteger(hashHex.substring(0, this.ecparams.keylen / 4), 16)
      let r, s, k
      do {
        do {
          k = this.getBigRandom(n)
          const Q = G.multiply(k)
          r = Q.getX().toBigInteger().add(e).mod(n)
        } while (r.signum() === 0 || r.add(k).compareTo(n) === 0)
        s = k.subtract(d.multiply(r))
        if (!dp1Inv) {
          dp1Inv = d.add(rs.BigInteger.ONE).modInverse(n)
        }
        s = s.multiply(dp1Inv).mod(n)
      } while (s.signum() === 0)
      return rs.ECDSA.biRSSigToASN1Sig(r, s)
    }

    /**
     * Internal function, called by parent class ECDSA
     * @param {BigInteger} e The big integer from hash of the message
     * @param {BigInteger} r The big integer from signature r
     * @param {BigInteger} s The big integer from signature s
     * @param {ECPointFp} Q The ecc point of the public key
     * @returns ture or false
     */
    ecdsa.verifyRaw = function (e, r, s, Q) {
      const n = this.ecparams.n
      const G = this.ecparams.G

      if (r.compareTo(rs.BigInteger.ONE) < 0 ||
            r.compareTo(n) >= 0) { return false }

      if (s.compareTo(rs.BigInteger.ONE) < 0 ||
            s.compareTo(n) >= 0) { return false }

      const t = r.add(s).mod(n)
      if (t.signum() === 0) {
        return false
      }
      const point = G.multiply(s).add(Q.multiply(t))

      const v = point.getX().toBigInteger().add(e).mod(n)

      return v.equals(r)
    }

    /**
     * calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
     * @param {string|Uint8Array} uid The user id, use default if not specified
     * @returns Uint8Array of the result
     */
    ecdsa.calculateZA = function (uid) {
      if (!uid) {
        uid = DEFAULT_UID
      }
      uid = util.normalizeInput(uid)
      const uidLen = uid.length
      if (uidLen >= 0x2000) {
        throw new Error('sm2: the uid is too long')
      }
      const entla = uidLen << 3 // bit length
      const md = new MessageDigest()
      md.update(Uint8Array.from([0xff & (entla >>> 8), 0xff & entla]))
      md.update(uid)
      md.update(SM2_CURVE_PARAMS_FOR_ZA) // a||b||gx||gy
      let Q
      if (this.pubKeyHex) {
        Q = rs.ECPointFp.decodeFromHex(this.ecparams.curve, this.pubKeyHex)
      } else {
        const d = new rs.BigInteger(this.prvKeyHex, 16)
        const G = this.ecparams.G
        Q = G.multiply(d)
        this.pubKeyHex = util.toHex(Q.getEncoded())
      }
      md.update(Uint8Array.from(util.integerToBytes(Q.getX().toBigInteger(), SM2_BYTE_SIZE))) // x
      md.update(Uint8Array.from(util.integerToBytes(Q.getY().toBigInteger(), SM2_BYTE_SIZE))) // y
      return md.digestRaw()
    }
  }
}

/**
 * SM2 KDF function
 * @param {string|Uint8Array} data The salt for kdf
 * @param {number} len The request key bytes length
 * @returns Uint8Array of the generated key
 */
function kdf (data, len) {
  data = util.normalizeInput(data)
  const limit = (len + SM3_SIZE - 1) >>> SM3_SIZE_BIT_SIZE
  const countBytes = new Uint8Array(4)
  let ct = 1
  const k = new Uint8Array(len + SM3_SIZE - 1)
  const md = new MessageDigest()
  for (let i = 0; i < limit; i++) {
    countBytes[0] = (ct >>> 24) & 0xff
    countBytes[1] = (ct >>> 16) & 0xff
    countBytes[2] = (ct >>> 8) & 0xff
    countBytes[3] = ct & 0xff
    md.update(data)
    md.update(countBytes)
    const hash = md.digestRaw()
    for (let j = 0; j < SM3_SIZE; j++) {
      k[i * SM3_SIZE + j] = hash[j]
    }
    ct++
  }
  for (let i = 0; i < len; i++) {
    if (k[i] !== 0) {
      return k.subarray(0, len)
    }
  }
}

class MessageDigest {
  constructor () {
    if (useNodeSM3) {
      this.md = crypto.createHash('sm3')
    } else {
      this.md = rs.KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME.sm3.create()
    }
  }

  /**
   * Updates the hash content with the given data
   * @param {Uint8Array} data The Uint8Array to be hashed
   */
  update (data) {
    if (useNodeSM3) {
      this.md.update(data)
    } else {
      this.md.update(rs.CryptoJS.enc.Uint8Array.parse(util.normalizeInput(data)))
    }
  }

  /**
   * Updates the hash content with the given hex data
   * @param {Uint8Array} hex The hex data
   */
  updateHex (hex) {
    if (useNodeSM3) {
      this.md.update(util.hexToUint8Array(hex))
    } else {
      this.md.update(rs.CryptoJS.enc.Hex.parse(hex))
    }
  }

  digestRaw () {
    if (useNodeSM3) {
      const h = this.md.digest()
      this.md = crypto.createHash('sm3')
      return h
    } else {
      const hash = this.md.finalize()
      this.md = rs.KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME.sm3.create()
      return rs.CryptoJS.enc.Uint8Array.stringify(hash)
    }
  }

  digest (data) {
    if (data) {
      this.update(data)
    }
    if (!useNodeSM3) {
      const hash = this.md.finalize()
      this.md = rs.KJUR.crypto.Util.CRYPTOJSMESSAGEDIGESTNAME.sm3.create()
      return hash.toString(rs.CryptoJS.enc.Hex)
    } else {
      const h = this.md.digest('hex')
      this.md = crypto.createHash('sm3')
      return h
    }
  }

  digestHex (hex) {
    this.updateHex(hex)
    return this.digest()
  }
}

/**
 * Signature class which is very similar to KJUR.crypto.Signature
 */
class Signature {
  constructor (params) {
    this.initParams = params
    if (params.alg !== undefined) {
      this.algName = params.alg
      this._setAlgNames()
    }
    if (this.mdAlgName !== 'sm3') {
      this.fallbackSig = new rs.Signature(params)
    } else {
      this.md = new MessageDigest()
    }
  }

  _setAlgNames () {
    const matchResult = this.algName.match(/^(.+)with(.+)$/)
    if (matchResult) {
      this.mdAlgName = matchResult[1].toLowerCase()
      this.pubkeyAlgName = matchResult[2].toLowerCase()
      if (this.pubkeyAlgName === 'rsaandmgf1' &&
                this.mdAlgName === 'sha') {
        this.mdAlgName = 'sha1'
      }
    }
  }

  init (keyparam, pass, hextype) {
    if (this.fallbackSig) {
      return this.fallbackSig.init(keyparam, pass)
    }
    let keyObj = null
    try {
      keyObj = rs.KEYUTIL.getKey(keyparam, pass, hextype)
    } catch (ex) {
      throw new Error('init failed:' + ex)
    }

    if (keyObj.isPrivate === true) {
      this.prvKey = keyObj
      this.state = 'SIGN'
      adaptSM2(this.prvKey)
    } else if (keyObj.isPublic === true) {
      this.pubKey = keyObj
      this.state = 'VERIFY'
      adaptSM2(this.pubKey)
    } else {
      throw new Error('init failed.:' + keyObj)
    }
  }

  update (data) {
    if (this.md) {
      this.md.update(data)
    } else if (typeof data === 'string') {
      this.fallbackSig.updateString(data)
    } else {
      throw new Error('do not support this data type')
    }
  }

  // Deprecated
  updateString (str) {
    this.update(str)
  }

  updateHex (hex) {
    if (this.md) {
      this.md.updateHex(hex)
    } else {
      this.fallbackSig.updateHex(hex)
    }
  }

  signWithMessageHash (sHashHex) {
    if (this.fallbackSig) {
      return this.fallbackSig.prvKey.signWithMessageHash(sHashHex)
    }
    // hex parameter EC public key
    if (this.prvKey === undefined &&
        this.ecprvhex !== undefined &&
        this.eccurvename !== undefined &&
        rs.ECDSA !== undefined) {
      this.prvKey = new rs.ECDSA({
        curve: this.eccurvename,
        prv: this.ecprvhex
      })
      adaptSM2(this.prvKey)
    }

    if (this.prvKey instanceof rs.ECDSA) {
      this.hSign = this.prvKey.signWithMessageHash(sHashHex)
    } else {
      throw new Error('Signature: unsupported private key alg: ' + this.pubkeyAlgName)
    }
    return this.hSign
  }

  sign (data) {
    if (data) {
      this.update(data)
    }
    if (this.fallbackSig) {
      return this.fallbackSig.sign()
    }
    this.sHashHex = this.md.digest()
    return this.signWithMessageHash(this.sHashHex)
  }

  // Deprecated
  signString (str) {
    return this.sign(str)
  }

  signHex (hex) {
    this.updateHex(hex)
    return this.sign()
  }

  sm2Hash (data, uid) {
    if (this.pubKey) {
      this.update(this.pubKey.calculateZA(uid))
    } else {
      this.update(this.prvKey.calculateZA(uid))
    }
    this.update(data)
    return this.md.digest()
  }

  sm2Sign (data, uid) {
    if (!data) {
      throw new Error('sm2: please do not call update before sign')
    }
    if (this.fallbackSig || !(this.prvKey instanceof rs.ECDSA)) {
      throw new Error('sm2: no valid SM2 private key')
    }
    return this.signWithMessageHash(this.sm2Hash(data, uid))
  }

  verifyWithMessageHash (sHashHex, hSigVal) {
    if (this.fallbackSig) {
      return this.fallbackSig.pubKey.verifyWithMessageHash(sHashHex, hSigVal)
    }
    // hex parameter EC public key
    if (this.pubKey === undefined &&
            this.ecpubhex !== undefined &&
            this.eccurvename !== undefined &&
            rs.ECDSA !== undefined) {
      this.pubKey = new rs.ECDSA({
        curve: this.eccurvename,
        pub: this.ecpubhex
      })
      adaptSM2(this.pubKey)
    }

    if (rs.ECDSA !== undefined &&
            this.pubKey instanceof rs.ECDSA) {
      return this.pubKey.verifyWithMessageHash(sHashHex, hSigVal)
    } else {
      throw new Error('Signature: unsupported public key alg: ' + this.pubkeyAlgName)
    }
  }

  verify (hSigVal) {
    if (this.fallbackSig) {
      return this.fallbackSig.verify(hSigVal)
    }
    return this.verifyWithMessageHash(this.md.digest(), hSigVal)
  }

  sm2Verify (hSigVal, data, uid) {
    if (!data) {
      throw new Error('sm2: please do not call update before verify')
    }
    if (this.fallbackSig || !(this.pubKey instanceof rs.ECDSA)) {
      throw new Error('sm2: no valid SM2 public key')
    }
    return this.pubKey.verifyWithMessageHash(this.sm2Hash(data, uid), hSigVal)
  }
}

/**
 * SM2 encryption function
 *
 * @param {string|object} pubkey hex public key string or ECDSA object
 * @param {string|Uint8Array} data plaintext data
 * @param {EncrypterOptions} opts options, just support encodingFormat now, default is plain encoding format
 * @returns hex plain format ciphertext
 */
function encrypt (pubkey, data, opts = DEFAULT_SM2_ENCRYPT_OPTIONS) {
  if (typeof pubkey === 'string') {
    pubkey = new rs.ECDSA({
      curve: SM2_CURVE_NAME,
      pub: pubkey
    })
  }
  if (!(pubkey instanceof rs.ECDSA) || pubkey.curveName !== SM2_CURVE_NAME) {
    throw new Error('sm2: invalid ec public key')
  }
  adaptSM2(pubkey)
  return pubkey.encrypt(data, opts)
}

/**
 * Convert hex plain format ciphertext to hex asn.1 format ciphertext
 *
 * @param {string} data hex plain format ciphertext
 * @returns hex ans.1 format ciphertext
 */
function plainCiphertext2ASN1 (data) {
  data = util.hexToUint8Array(data)
  const dataLen = data.length

  if (data[0] !== UNCOMPRESSED) {
    throw new Error('sm2: unsupport point marshal mode')
  }
  if (dataLen < 97) {
    throw new Error('sm2: invalid cipher content')
  }
  const point1 = rs.ECPointFp.decodeFrom(rs.crypto.ECParameterDB.getByName(SM2_CURVE_NAME).curve, Array.from(data.subarray(0, 65)))
  const c2 = data.subarray(97)
  const c3 = data.subarray(65, 97)
  const derX = new rs.asn1.DERInteger({ bigint: point1.getX().toBigInteger() })
  const derY = new rs.asn1.DERInteger({ bigint: point1.getY().toBigInteger() })
  const derC3 = new rs.asn1.DEROctetString({ hex: util.toHex(c3) })
  const derC2 = new rs.asn1.DEROctetString({ hex: util.toHex(c2) })
  const derSeq = new rs.asn1.DERSequence({ array: [derX, derY, derC3, derC2] })

  return derSeq.getEncodedHex()
}

function _getASN1Values (hexASN1Data, aIdx, aTag) {
  const aValue = []
  for (let i = 0; i < aIdx.length; i++) {
    const idx = aIdx[i]
    const tag = hexASN1Data.substring(idx, idx + 2)
    if (tag !== aTag[i]) {
      throw new Error('sm2: invalid asn1 format ciphertext, want ' + aTag[i] + ', get ' + tag)
    }
    aValue.push(rs.ASN1HEX.getV(hexASN1Data, idx))
  }
  return aValue
}

/**
 * Convert hex asn.1 format ciphertext to hex plain format ciphertext
 *
 * @param {string} hexASN1Data hex asn.1 data
 * @returns hex plain format cipher text
 */
function asn1Ciphertext2Plain (hexASN1Data) {
  if (!hexASN1Data || !rs.ASN1HEX.isASN1HEX(hexASN1Data)) {
    throw new Error('sm2: invalid asn1 format ciphertext')
  }
  const idx = 0
  const tag = hexASN1Data.substring(idx, idx + 2)
  if (tag !== '30') {
    throw new Error('sm2: invalid asn1 format ciphertext')
  }
  const aIdx = rs.ASN1HEX.getChildIdx(hexASN1Data, idx)
  if (aIdx.length !== 4) {
    throw new Error('sm2: invalid asn1 format ciphertext')
  }
  const aValue = _getASN1Values(hexASN1Data, aIdx, ['02', '02', '04', '04'])
  const curve = rs.crypto.ECParameterDB.getByName(SM2_CURVE_NAME).curve
  const x = new rs.BigInteger(aValue[0], 16)
  const y = new rs.BigInteger(aValue[1], 16)
  const point = new rs.ECPointFp(curve, curve.fromBigInteger(x), curve.fromBigInteger(y))
  const c3 = aValue[2]
  const c2 = aValue[3]

  return util.toHex(point.getEncoded(false)) + c3 + c2
}

/**
 * SM2 encryption function
 *
 * @param {string|object} pubkey hex public key string or ECDSA object
 * @param {string} data hex plaintext
 * @param {EncrypterOptions} opts options, just support encodingFormat now, default is plain encoding format
 * @returns hex plain format ciphertext
 */
function encryptHex (pubkey, data, opts = DEFAULT_SM2_ENCRYPT_OPTIONS) {
  return encrypt(pubkey, util.hexToUint8Array(data), opts)
}

/**
 * SM2 decrypt function
 *
 * @param {string|object} prvKey private key used to decrypt, private key hex string or ECDSA object.
 * @param {string|Uint8Array} data plain format (C1||C3|C2) ciphertext data
 * @returns hex plaintext
 */
function decrypt (prvKey, data) {
  if (typeof prvKey === 'string') {
    prvKey = new rs.ECDSA({
      curve: SM2_CURVE_NAME,
      prv: prvKey
    })
  }
  if (!(prvKey instanceof rs.ECDSA) || prvKey.curveName !== SM2_CURVE_NAME) {
    throw new Error('sm2: invalid ec public key')
  }
  adaptSM2(prvKey)
  return prvKey.decrypt(data)
}

/**
 * SM2 Decrypt function
 *
 * @param {string|object} prvKey private key used to decrypt, private key hex string or ECDSA object.
 * @param {string} data hex plain/asn.1 format ciphertext data
 * @returns hex plaintext
 */
function decryptHex (prvKey, data) {
  if (typeof data !== 'string' || data.length < 98 * 2) {
    throw new Error('sm2: invalid chiphertext length')
  }
  const tag = data.substring(0, 2)
  if (tag !== '30' && tag !== '04') {
    throw new Error(`sm2: invalid ciphertext encoding format ${tag}`)
  }
  if (tag === '30') {
    data = asn1Ciphertext2Plain(data)
  }
  return decrypt(prvKey, util.hexToUint8Array(data))
}

function getCurveName () {
  return SM2_CURVE_NAME
}

function getSignAlg () {
  return SM2_SIGN_ALG
}

function createSM2Signature () {
  return new Signature({ alg: SM2_SIGN_ALG })
}

rs.asn1.csr.CSRUtil.newCSRPEM = function (param) {
  const csr = new rs.asn1.csr.CertificationRequest(param)
  if (param.sigalg === SM2_SIGN_ALG) {
    csr.sign = function () {
      const hCSRI = (new rs.asn1.csr.CertificationRequestInfo(this.params)).getEncodedHex()
      const sig = new Signature({ alg: this.params.sigalg })
      sig.init(this.params.sbjprvkey)
      const sighex = sig.sm2Sign(util.hexToUint8Array(hCSRI))
      this.params.sighex = sighex
    }
  }
  const pem = csr.getPEM()
  return pem
}

function createX509 () {
  const x = new rs.X509()
  const oldVerifySigFunc = x.verifySignature
  x.verifySignature = function (pubKey) {
    const algName = this.getSignatureAlgorithmField()
    if (algName !== SM2_SIGN_ALG) {
      return oldVerifySigFunc.call(x, pubKey)
    }
    const hSigVal = this.getSignatureValueHex()
    const hTbsCert = rs.ASN1HEX.getTLVbyList(this.hex, 0, [0], '30')

    const sig = new Signature({ alg: algName })
    sig.init(pubKey)
    return sig.sm2Verify(hSigVal, util.hexToUint8Array(hTbsCert))
  }
  return x
}

function asn1EncrypterOptions () {
  return new EncrypterOptions(CIPHERTEXT_ENCODING_ASN1)
}

function plainEncrypterOptions () {
  return new EncrypterOptions(CIPHERTEXT_ENCODING_PLAIN)
}

module.exports = {
  Signature,
  createSM2Signature,
  getCurveName,
  getSignAlg,
  encrypt,
  encryptHex,
  decrypt,
  decryptHex,
  createX509,
  plainCiphertext2ASN1,
  asn1Ciphertext2Plain,
  asn1EncrypterOptions,
  plainEncrypterOptions
}

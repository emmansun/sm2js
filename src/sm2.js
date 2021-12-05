require('./cryptojs_sm3')
const rs = require('jsrsasign')
const sm3 = require('gmsm-sm3js')
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

const defaultEncryptFunc = rs.Cipher.encrypt
rs.Cipher.encrypt = function (s, keyObj, algName) {
  if (keyObj instanceof rs.ECDSA && keyObj.isPublic && keyObj.curveName === SM2_CURVE_NAME) {
    return encrypt(keyObj, s)
  }
  return defaultEncryptFunc(s, keyObj, algName)
}

const defaultDecryptFunc = rs.Cipher.decrypt
rs.Cipher.decrypt = function (hex, keyObj, algName) {
  if (keyObj instanceof rs.ECDSA && keyObj.isPrivate && keyObj.curveName === SM2_CURVE_NAME) {
    return decryptHex(keyObj, hex)
  }
  return defaultDecryptFunc(hex, keyObj, algName)
}

if (!rs.BigInteger.prototype.toByteArrayUnsigned) {
  /**
 * Returns a byte array representation of the big integer.
 *
 * This returns the absolute of the contained value in big endian
 * form. A value of zero results in an empty array.
 */
  rs.BigInteger.prototype.toByteArrayUnsigned = function () {
    const byteArray = this.toByteArray()
    return byteArray[0] === 0 ? byteArray.slice(1) : byteArray
  }
}

const sm2 = Symbol('sm2')

function adaptSM2 (ecdsa) {
  // SM2 encryption
  // @param {data} to be encrypted, can be string/Uint8array/buffer
  // @return {string} encrypted hex content
  if (!ecdsa[sm2]) {
    ecdsa[sm2] = true
    ecdsa.encrypt = function (data) {
      const Q = rs.ECPointFp.decodeFromHex(this.ecparams.curve, this.pubKeyHex)
      return this.encryptRaw(data, Q)
    }

    ecdsa.encryptHex = function (dataHex) {
      return this.encrypt(sm3.fromHex(dataHex))
    }

    ecdsa.encryptRaw = function (data, Q) {
      data = sm3.normalizeInput(data)
      const n = this.ecparams.n
      const G = this.ecparams.G
      const dataLen = data.length
      let md = new MessageDigest()
      let count = 0
      if (Q.isInfinity()) {
        throw new Error('SM2: invalid public key')
      }
      do {
        const k = this.getBigRandom(n)
        const point1 = G.multiply(k)
        const point2 = Q.multiply(k)
        const t = kdf(new Uint8Array(util.integerToBytes(point2.getX().toBigInteger(), SM2_BYTE_SIZE).concat(util.integerToBytes(point2.getY().toBigInteger(), SM2_BYTE_SIZE))), dataLen)
        if (!t) {
          if (count++ > MAX_RETRY) {
            throw new Error('SM2: A5, failed to calculate valid t')
          }
          md = new MessageDigest()
          continue
        }
        for (let i = 0; i < dataLen; i++) {
          t[i] ^= data[i]
        }
        md.update(new Uint8Array(util.integerToBytes(point2.getX().toBigInteger(), SM2_BYTE_SIZE)))
        md.update(data)
        md.update(new Uint8Array(util.integerToBytes(point2.getY().toBigInteger(), SM2_BYTE_SIZE)))
        const hash = md.digestRaw()
        return sm3.toHex(new Uint8Array(point1.getEncoded(false))) + sm3.toHex(hash) + sm3.toHex(t)
      } while (true)
    }

    // SM2 decryption
    // @param {data} to be decrypted, can be string/Uint8array/buffer
    // @return {string} decrypted hex content
    ecdsa.decrypt = function (data) {
      const d = new rs.BigInteger(this.prvKeyHex, 16)
      return this.decryptRaw(data, d)
    }

    ecdsa.decryptHex = function (dataHex) {
      return this.decrypt(sm3.fromHex(dataHex))
    }

    ecdsa.decryptRaw = function (data, d) {
      data = sm3.normalizeInput(data)
      const dataLen = data.length

      if (data[0] !== UNCOMPRESSED) {
        throw new Error('Unsupport point marshal mode')
      }
      if (dataLen < 97) {
        throw new Error('Invalid cipher content')
      }
      const point1 = rs.ECPointFp.decodeFrom(this.ecparams.curve, Array.from(data.subarray(0, 65)))
      const point2 = point1.multiply(d)
      const c2 = data.subarray(97)
      const c3 = data.subarray(65, 97)
      const t = sm3.kdf(new Uint8Array(util.integerToBytes(point2.getX().toBigInteger(), SM2_BYTE_SIZE).concat(util.integerToBytes(point2.getY().toBigInteger(), SM2_BYTE_SIZE))), dataLen - 97)
      if (!t) {
        throw new Error('Invalid cipher content')
      }
      for (let i = 0; i < c3.length; i++) {
        c2[i] ^= t[i]
      }
      return sm3.toHex(c2)
    }

    ecdsa.signHex = function (hashHex, privHex) {
      const d = new rs.BigInteger(privHex, 16)
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
        const dp1Inv = d.add(rs.BigInteger.ONE).modInverse(n)
        s = s.multiply(dp1Inv).mod(n)
      } while (s.signum() === 0)
      return rs.ECDSA.biRSSigToASN1Sig(r, s)
    }

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

    // calculateZA ZA = H256(ENTLA || IDA || a || b || xG || yG || xA || yA)
    ecdsa.calculateZA = function (uid) {
      if (!uid) {
        uid = DEFAULT_UID
      }
      uid = sm3.normalizeInput(uid)
      const uidLen = uid.length
      if (uidLen >= 0x2000) {
        throw new Error('the uid is too long')
      }
      const entla = uidLen << 3
      const md = new MessageDigest()
      md.update(new Uint8Array([0xff & (entla >>> 8), 0xff & entla]))
      md.update(uid)
      md.update(sm3.fromHex(SM2_CURVE_PARAM_A)) // a
      md.update(sm3.fromHex(SM2_CURVE_PARAM_B)) // b
      md.update(sm3.fromHex(SM2_CURVE_PARAM_GX)) // gx
      md.update(sm3.fromHex(SM2_CURVE_PARAM_GY)) // gy
      let Q
      if (this.pubKeyHex) {
        Q = rs.ECPointFp.decodeFromHex(this.ecparams.curve, this.pubKeyHex)
      } else {
        const d = new rs.BigInteger(this.prvKeyHex, 16)
        const G = this.ecparams.G
        Q = G.multiply(d)
      }
      md.update(new Uint8Array(util.integerToBytes(Q.getX().toBigInteger(), SM2_BYTE_SIZE))) // x
      md.update(new Uint8Array(util.integerToBytes(Q.getY().toBigInteger(), SM2_BYTE_SIZE))) // y
      return md.digestRaw()
    }
  }
}

function kdf (data, len) {
  data = sm3.normalizeInput(data)
  const limit = (len + SM3_SIZE - 1) >>> SM3_SIZE_BIT_SIZE
  const countBytes = new Uint8Array(4)
  let ct = 1
  const k = new Uint8Array(len + SM3_SIZE - 1)
  let md = new MessageDigest()
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
    md = new MessageDigest()
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
      this.md = sm3.create()
    }
  }

  update (data) {
    this.md.update(data)
  }

  updateHex (hex) {
    this.md.update(sm3.fromHex(hex))
  }

  digestRaw () {
    return useNodeSM3 ? this.md.digest() : this.md.finalize()
  }

  digest (data) {
    if (data) {
      this.update(data)
    }
    if (!useNodeSM3) {
      const hash = this.md.finalize()
      this.md.reset()
      return sm3.toHex(hash)
    } else {
      return this.md.digest('hex')
    }
  }

  digestHex (hex) {
    this.updateHex(hex)
    return this.digest()
  }
}

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

  init (keyparam, pass) {
    if (this.fallbackSig) {
      return this.fallbackSig.init(keyparam, pass)
    }
    let keyObj = null
    try {
      if (pass === undefined) {
        keyObj = rs.KEYUTIL.getKey(keyparam)
      } else {
        keyObj = rs.KEYUTIL.getKey(keyparam, pass)
      }
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

  sm2Sign (data, uid) {
    if (!data) {
      throw new Error('SM2 sign, please do not call update before sign')
    }
    if (this.fallbackSig || !(this.prvKey instanceof rs.ECDSA)) {
      throw new Error('No valid SM2 private key')
    }
    this.update(this.prvKey.calculateZA(uid))
    this.update(data)
    this.sHashHex = this.md.digest()
    return this.signWithMessageHash(this.sHashHex)
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
    this.sHashHex = this.md.digest()
    return this.verifyWithMessageHash(this.sHashHex, hSigVal)
  }

  sm2Verify (hSigVal, data, uid) {
    if (!data) {
      throw new Error('SM2 verify, please do not call update before verify')
    }
    if (this.fallbackSig || !(this.pubKey instanceof rs.ECDSA)) {
      throw new Error('No valid SM2 public key')
    }
    this.update(this.pubKey.calculateZA(uid))
    this.update(data)
    this.sHashHex = this.md.digest()
    return this.pubKey.verifyWithMessageHash(this.sHashHex, hSigVal)
  }
}

function encrypt (pubkey, data) {
  if (typeof pubkey === 'string') {
    pubkey = new rs.ECDSA({
      curve: SM2_CURVE_NAME,
      pub: pubkey
    })
  }
  if (!(pubkey instanceof rs.ECDSA) || pubkey.curveName !== SM2_CURVE_NAME) {
    throw new Error('Invalid ec public key')
  }
  adaptSM2(pubkey)
  return pubkey.encrypt(data)
}

function plainCiphertext2ASN1 (data) {
  data = sm3.fromHex(data)
  const dataLen = data.length

  if (data[0] !== UNCOMPRESSED) {
    throw new Error('Unsupport point marshal mode')
  }
  if (dataLen < 97) {
    throw new Error('Invalid cipher content')
  }
  const point1 = rs.ECPointFp.decodeFrom(rs.crypto.ECParameterDB.getByName(SM2_CURVE_NAME).curve, Array.from(data.subarray(0, 65)))
  const c2 = data.subarray(97)
  const c3 = data.subarray(65, 97)
  const derX = new rs.asn1.DERInteger({ bigint: point1.getX().toBigInteger() })
  const derY = new rs.asn1.DERInteger({ bigint: point1.getY().toBigInteger() })
  const derC3 = new rs.asn1.DEROctetString({ hex: sm3.toHex(c3) })
  const derC2 = new rs.asn1.DEROctetString({ hex: sm3.toHex(c2) })
  const derSeq = new rs.asn1.DERSequence({ array: [derX, derY, derC3, derC2] })

  return derSeq.getEncodedHex()
}

function encryptHex (pubkey, data) {
  return encrypt(pubkey, sm3.fromHex(data))
}

function decrypt (prvKey, data) {
  if (typeof prvKey === 'string') {
    prvKey = new rs.ECDSA({
      curve: SM2_CURVE_NAME,
      prv: prvKey
    })
  }
  if (!(prvKey instanceof rs.ECDSA) || prvKey.curveName !== SM2_CURVE_NAME) {
    throw new Error('Invalid ec public key')
  }
  adaptSM2(prvKey)
  return prvKey.decrypt(data)
}

function decryptHex (prvKey, data) {
  return decrypt(prvKey, sm3.fromHex(data))
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
      const sighex = sig.sm2Sign(sm3.fromHex(hCSRI))
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
    return sig.sm2Verify(hSigVal, sm3.fromHex(hTbsCert))
  }
  return x
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
  CIPHERTEXT_ENCODING_PLAIN,
  CIPHERTEXT_ENCODING_ASN1,
  plainCiphertext2ASN1
}

const rs = require('jsrsasign')
const sm3 = require('gmsm-sm3js')

rs.crypto.ECParameterDB.regist(
  'sm2p256v1', // name / p = 2**256 - 2**224 - 2**96 + 2**64 - 1
  256,
  'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFF', // p
  'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF00000000FFFFFFFFFFFFFFFC', // a
  '28E9FA9E9D9F5E344D5A9E4BCF6509A7F39789F515AB8F92DDBCBD414D940E93', // b
  'FFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFF7203DF6B21C6052B53BBF40939D54123', // n
  '1', // h
  '32C4AE2C1F1981195F9904466A39C9948FE30BBFF2660BE1715A4589334C74C7', // gx
  'BC3736A2F4F6779C59BDCEE36B692153D0A9877CC62A474002DF32E52139F0A0', // gy
  []) // alias

const getNameFunc = rs.ECDSA.getName
rs.ECDSA.getName = function (s) {
  // {1, 2, 156, 10197, 1, 301}
  if (s === '2a811ccf5501822d') {
    return 'sm2p256v1'
  }
  return getNameFunc(s)
}

function adaptSM2 (ecdsa) {
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
}

class MessageDigest {
  constructor () {
    this.md = sm3.create()
  }

  updateString (str) {
    this.md.update(str)
  }

  updateHex (hex) {
    this.md.update(sm3.fromHex(hex))
  }

  digest () {
    const hash = this.md.finalize()
    this.md.reset()
    return sm3.toHex(hash)
  }

  digestString (str) {
    this.updateString(str)
    return this.digest()
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

  updateString (str) {
    if (this.md) {
      this.md.updateString(str)
    } else {
      this.fallbackSig.updateString(str)
    }
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

  sign () {
    if (this.fallbackSig) {
      return this.fallbackSig.sign()
    }
    this.sHashHex = this.md.digest()
    return this.signWithMessageHash(this.sHashHex)
  }

  signString (str) {
    this.updateString(str)
    return this.sign()
  }

  signHex (hex) {
    this.updateHex(hex)
    return this.sign()
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
}

module.exports = {
  Signature
}

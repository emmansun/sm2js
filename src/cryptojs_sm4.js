const rs = require('jsrsasign')
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

  /**
   * Encrypt an array of 4 big-endian words.
   * @param {Array} data The plaintext.
   * @return {Array} The ciphertext.
   */
  encrypt: function (data) {
    return this._crypt(data, this._keySchedule)
  },

  /**
     * Decrypt an array of 4 big-endian words.
     * @param {Array} data The ciphertext.
     * @return {Array} The plaintext.
     */
  decrypt: function (data) {
    return this._crypt(data, this._invKeySchedule)
  },

  /**
   * Encryption and decryption core.
   * @param {Array} input Four words to be encrypted or decrypted.
   * @param keySchedule The scheduled keys.
   * @return {Array} The four encrypted or decrypted words.
   * @private
   */
  _crypt: function (input, keySchedule) {
    if (input.length !== 4) {
      throw new Error('invalid sm4 block size')
    }
    let a = input[0]
    let b = input[1]
    let c = input[2]
    let d = input[3]

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

    return [d, c, b, a]
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

module.exports = SM4

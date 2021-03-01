const C = require('jsrsasign').CryptoJS
const CLib = C.lib
const WordArray = CLib.WordArray
const Hasher = CLib.Hasher
const CAlgo = C.algo

const SM3_IV32 = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
]

const SM3_T = [0x79cc4519, 0x7a879d8a]

// Reusable object
const W = []
const W1 = []

/**
     * SM3 hash algorithm.
     */
const SM3 = CAlgo.SM3 = Hasher.extend({
  rotateLeft32: function (x, k) {
    const n = 32
    const s = k & (n - 1)
    return (x << s) | (x >>> (n - s))
  },

  _t: function (j) {
    j = j & 0xff
    if (j < 16) {
      return SM3_T[0]
    }
    return SM3_T[1]
  },

  _p0: function (x) {
    return x ^ this.rotateLeft32(x, 9) ^ this.rotateLeft32(x, 17)
  },

  _p1: function (x) {
    return x ^ this.rotateLeft32(x, 15) ^ this.rotateLeft32(x, 23)
  },

  _ff: function (j, x, y, z) {
    if (j < 16) {
      return x ^ y ^ z
    }
    return (x & y) | (x & z) | (y & z)
  },

  _gg: function (j, x, y, z) {
    if (j < 16) {
      return x ^ y ^ z
    }
    return (x & y) | (~x & z)
  },

  _doReset: function () {
    this._hash = WordArray.create(SM3_IV32.slice(0))
  },

  _doProcessBlock: function (M, offset) {
    // Shortcut
    const H = this._hash.words

    // Working variables
    let a = H[0]
    let b = H[1]
    let c = H[2]
    let d = H[3]
    let e = H[4]
    let f = H[5]
    let g = H[6]
    let h = H[7]

    // Computation
    for (let i = 0; i < 16; i++) {
      W[i] = M[offset + i] | 0
    }
    for (let i = 16; i < 68; i++) {
      W[i] = this._p1(W[i - 16] ^ W[i - 9] ^ this.rotateLeft32(W[i - 3], 15)) ^ this.rotateLeft32(W[i - 13], 7) ^ W[i - 6]
    }
    for (let i = 0; i < 64; i++) {
      W1[i] = W[i] ^ W[i + 4]
    }
    for (let i = 0; i < 64; i++) {
      const ss1 = this.rotateLeft32(this.rotateLeft32(a, 12) + e + this.rotateLeft32(this._t(i), i), 7)
      const ss2 = ss1 ^ this.rotateLeft32(a, 12)
      const tt1 = this._ff(i, a, b, c) + d + ss2 + W1[i]
      const tt2 = this._gg(i, e, f, g) + h + ss1 + W[i]
      d = c
      c = this.rotateLeft32(b, 9)
      b = a
      a = tt1 | 0
      h = g
      g = this.rotateLeft32(f, 19)
      f = e
      e = this._p0(tt2)
    }
    // Intermediate hash value
    H[0] = (H[0] ^ a)
    H[1] = (H[1] ^ b)
    H[2] = (H[2] ^ c)
    H[3] = (H[3] ^ d)
    H[4] = (H[4] ^ e)
    H[5] = (H[5] ^ f)
    H[6] = (H[6] ^ g)
    H[7] = (H[7] ^ h)
  },

  _doFinalize: function () {
    // Shortcuts
    const data = this._data
    const dataWords = data.words

    const nBitsTotal = this._nDataBytes * 8
    const nBitsLeft = data.sigBytes * 8
    // Add padding
    dataWords[nBitsLeft >>> 5] |= 0x80 << (24 - nBitsLeft % 32)
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 14] = Math.floor(nBitsTotal / 0x100000000)
    dataWords[(((nBitsLeft + 64) >>> 9) << 4) + 15] = nBitsTotal
    data.sigBytes = dataWords.length * 4

    // Hash final blocks
    this._process()

    // Return final computed hash
    return this._hash
  },

  clone: function () {
    const clone = Hasher.clone.call(this)
    clone._hash = this._hash.clone()

    return clone
  }
})

/**
     * Shortcut function to the hasher's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     *
     * @return {WordArray} The hash.
     *
     * @static
     *
     * @example
     *
     *     var hash = CryptoJS.SM3('message');
     *     var hash = CryptoJS.SM3(wordArray);
     */
C.SM3 = Hasher._createHelper(SM3)

/**
     * Shortcut function to the HMAC's object interface.
     *
     * @param {WordArray|string} message The message to hash.
     * @param {WordArray|string} key The secret key.
     *
     * @return {WordArray} The HMAC.
     *
     * @static
     *
     * @example
     *
     *     var hmac = CryptoJS.HmacSM3(message, key);
     */
C.HmacSM3 = Hasher._createHmacHelper(SM3)

module.exports = SM3

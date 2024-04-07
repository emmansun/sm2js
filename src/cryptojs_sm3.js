const rs = require('jsrsasign')
const C = rs.CryptoJS
const CLib = C.lib
const WordArray = CLib.WordArray
const Hasher = CLib.Hasher
const CAlgo = C.algo

const SM3_IV32 = [
  0x7380166f, 0x4914b2b9, 0x172442d7, 0xda8a0600,
  0xa96f30bc, 0x163138aa, 0xe38dee4d, 0xb0fb0e4e
]

const SM3_T = [
  0x79cc4519, 0xf3988a32, 0xe7311465, 0xce6228cb, 0x9cc45197, 0x3988a32f, 0x7311465e, 0xe6228cbc,
  0xcc451979, 0x988a32f3, 0x311465e7, 0x6228cbce, 0xc451979c, 0x88a32f39, 0x11465e73, 0x228cbce6,
  0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
  0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5,
  0x7a879d8a, 0xf50f3b14, 0xea1e7629, 0xd43cec53, 0xa879d8a7, 0x50f3b14f, 0xa1e7629e, 0x43cec53d,
  0x879d8a7a, 0xf3b14f5, 0x1e7629ea, 0x3cec53d4, 0x79d8a7a8, 0xf3b14f50, 0xe7629ea1, 0xcec53d43,
  0x9d8a7a87, 0x3b14f50f, 0x7629ea1e, 0xec53d43c, 0xd8a7a879, 0xb14f50f3, 0x629ea1e7, 0xc53d43ce,
  0x8a7a879d, 0x14f50f3b, 0x29ea1e76, 0x53d43cec, 0xa7a879d8, 0x4f50f3b1, 0x9ea1e762, 0x3d43cec5]

/**
 * SM3 hash algorithm.
 */
const SM3 = CAlgo.SM3 = Hasher.extend({
  rotateLeft32: function (x, k) {
    const n = 32
    return (x << k) | (x >>> (n - k))
  },

  _p0: function (x) {
    return x ^ this.rotateLeft32(x, 9) ^ this.rotateLeft32(x, 17)
  },

  _p1: function (x) {
    return x ^ this.rotateLeft32(x, 15) ^ this.rotateLeft32(x, 23)
  },

  _ff: function (x, y, z) {
    return (x & y) | (x & z) | (y & z)
  },

  _gg: function (x, y, z) {
    return ((y ^ z) & x) ^ z
  },

  _doReset: function () {
    this._hash = WordArray.create(SM3_IV32.slice(0))
  },

  _doProcessBlock: function (M, offset) {
    // Shortcut
    const H = this._hash.words
    const W = []

    // Working variables
    let a = H[0]
    let b = H[1]
    let c = H[2]
    let d = H[3]
    let e = H[4]
    let f = H[5]
    let g = H[6]
    let h = H[7]
    let ss1, ss2, tt1, tt2
    // Computation
    for (let i = 0; i < 4; i++) {
      W[i] = M[offset + i] | 0
    }
    for (let i = 0; i < 12; i++) {
      W[i + 4] = M[offset + i + 4] | 0
      tt2 = this.rotateLeft32(a, 12)
      ss1 = this.rotateLeft32(tt2 + e + SM3_T[i], 7)
      ss2 = ss1 ^ tt2
      tt1 = (a ^ b ^ c) + d + ss2 + (W[i] ^ W[i + 4])
      tt2 = (e ^ f ^ g) + h + ss1 + W[i]
      d = c
      c = this.rotateLeft32(b, 9)
      b = a
      a = tt1 | 0
      h = g
      g = this.rotateLeft32(f, 19)
      f = e
      e = this._p0(tt2)
    }
    for (let i = 12; i < 16; i++) {
      W[i + 4] = this._p1(W[i - 12] ^ W[i - 5] ^ this.rotateLeft32(W[i + 1], 15)) ^ this.rotateLeft32(W[i - 9], 7) ^ W[i - 2]
      tt2 = this.rotateLeft32(a, 12)
      ss1 = this.rotateLeft32(tt2 + e + SM3_T[i], 7)
      ss2 = ss1 ^ tt2
      tt1 = (a ^ b ^ c) + d + ss2 + (W[i] ^ W[i + 4])
      tt2 = (e ^ f ^ g) + h + ss1 + W[i]
      d = c
      c = this.rotateLeft32(b, 9)
      b = a
      a = tt1 | 0
      h = g
      g = this.rotateLeft32(f, 19)
      f = e
      e = this._p0(tt2)
    }
    for (let i = 16; i < 64; i++) {
      W[i + 4] = this._p1(W[i - 12] ^ W[i - 5] ^ this.rotateLeft32(W[i + 1], 15)) ^ this.rotateLeft32(W[i - 9], 7) ^ W[i - 2]
      tt2 = this.rotateLeft32(a, 12)
      ss1 = this.rotateLeft32(tt2 + e + SM3_T[i], 7)
      ss2 = ss1 ^ tt2
      tt1 = this._ff(a, b, c) + d + ss2 + (W[i] ^ W[i + 4])
      tt2 = this._gg(e, f, g) + h + ss1 + W[i]
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

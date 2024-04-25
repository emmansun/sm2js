function integerToBytes (i, len) {
  let bytes = i.toByteArrayUnsigned()

  if (len < bytes.length) {
    bytes = bytes.slice(bytes.length - len)
  } else {
    while (len > bytes.length) {
      bytes.unshift(0)
    }
  }
  return bytes
}

/**
 * Convert byte array or Uint8Array to hex string
 * @param {Uint8Array|Array} bytes byte array or Uint8Array
 * @returns {string} hex string
 */
function toHex (bytes) {
  const isUint8Array = bytes instanceof Uint8Array
  if (!isUint8Array) {
    bytes = Uint8Array.from(bytes)
  }
  return Array.prototype.map
    .call(bytes, function (n) {
      return (n < 16 ? '0' : '') + n.toString(16)
    })
    .join('')
}

/**
 * Convert a hex string to a Uint8Array.
 * @param {string} hexStr - Hex string to convert
 * @return {Uint8Array} Uint8Array containing the converted hex string.
 */
function hexToUint8Array (hexStr) {
  if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
    throw new Error('Invalid hex string')
  }
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substring(i, i + 2), 16))
  }
  return Uint8Array.from(bytes)
}

const hasBuffer = typeof Buffer !== 'undefined'
const hasTextEncoder = typeof TextEncoder !== 'undefined'

function _normalizeInputWithBuffer (input) {
  if (input instanceof Uint8Array) {
    return input
  }
  if (input instanceof Buffer) {
    return Uint8Array.from(input)
  }
  if (typeof input === 'string') {
    return hasTextEncoder ? new TextEncoder().encode(input) : Uint8Array.from(Buffer.from(input, 'utf8'))
  }
  throw new Error('Input must be an utf8 string, Buffer or Uint8Array')
}

function _normalizeInputWithoutBuffer (input) {
  if (input instanceof Uint8Array) {
    return input
  }

  if (typeof input === 'string') {
    if (hasTextEncoder) {
      return new TextEncoder().encode(input)
    }
    input = unescape(encodeURIComponent(input))
    const array = new Uint8Array(input.length)
    for (let i = 0; i < input.length; i++) {
      array[i] = input.charCodeAt(i)
    }
    return Uint8Array.from(array)
  }
  throw new Error('Input must be an utf8 string or Uint8Array')
}

const normalizeInput = hasBuffer ? _normalizeInputWithBuffer : _normalizeInputWithoutBuffer

module.exports = {
  integerToBytes,
  normalizeInput,
  hexToUint8Array,
  toHex
}

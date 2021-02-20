function integerToByteHex (i) {
  let h = i.toString(16)
  if ((h.length % 2) === 1) h = '0' + h
  return h
}

function fromHex (hexStr) {
  if (typeof hexStr !== 'string' || hexStr.length % 2 === 1) {
    throw new Error('Invalid hex string')
  }
  const bytes = []
  for (let i = 0; i < hexStr.length; i += 2) {
    bytes.push(parseInt(hexStr.substr(i, 2), 16))
  }
  return bytes
}

// seems there are no toByteArrayUnsigned() method
function toBytes (bigInt, byteSize) {
  let bytes = fromHex(integerToByteHex(bigInt))

  if (byteSize < bytes.length) {
    bytes = bytes.slice(bytes.length - byteSize)
  } else {
    while (byteSize > bytes.length) {
      bytes.unshift(0)
    }
  }
  return bytes
}

function getEncoded (point, byteSize, compressed = false) {
  const x = point.getX().toBigInteger()
  const y = point.getY().toBigInteger()

  // Get value as a 32-byte Buffer
  // Fixed length based on a patch by bitaddress.org and Casascius
  let enc = toBytes(x, byteSize)
  if (compressed) {
    if (y.isEven()) {
      // Compressed even pubkey
      // M = 02 || X
      enc.unshift(0x02)
    } else {
      // Compressed uneven pubkey
      // M = 03 || X
      enc.unshift(0x03)
    }
  } else {
    // Uncompressed pubkey
    // M = 04 || X || Y
    enc.unshift(0x04)
    enc = enc.concat(toBytes(y, byteSize))
  }
  return enc
}

module.exports = {
  toBytes: toBytes,
  getEncoded
}

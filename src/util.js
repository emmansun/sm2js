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

function getEncoded (point, byteSize, compressed = false) {
  const x = point.getX().toBigInteger()
  const y = point.getY().toBigInteger()

  // Get value as a 32-byte Buffer
  // Fixed length based on a patch by bitaddress.org and Casascius
  let enc = integerToBytes(x, byteSize)
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
    enc = enc.concat(integerToBytes(y, byteSize))
  }
  return enc
}

module.exports = {
  integerToBytes: integerToBytes,
  getEncoded
}

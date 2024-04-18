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

// For convenience, let people hash a string, not just a Uint8Array
function normalizeInput (input) {
  let ret
  if (input instanceof Uint8Array) {
    ret = input
  } else if (input instanceof Buffer) {
    ret = new Uint8Array(input)
  } else if (typeof input === 'string') {
    ret = new Uint8Array(Buffer.from(input, 'utf8'))
  } else {
    throw new Error('Input must be an string, Buffer or Uint8Array')
  }
  return ret
}

module.exports = {
  integerToBytes,
  normalizeInput
}

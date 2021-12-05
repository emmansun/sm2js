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

module.exports = {
  integerToBytes
}

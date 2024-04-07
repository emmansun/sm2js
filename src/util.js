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

function aryval (val, keys, def) {
  if (typeof val !== 'object') return undefined
  keys = String(keys).split('.')
  for (let i = 0; i < keys.length && val; i++) {
    let key = keys[i]
    if (key.match(/^[0-9]+$/)) key = parseInt(key)
    val = val[key]
  }
  return val || val === false ? val : def
}

module.exports = {
  integerToBytes,
  aryval
}

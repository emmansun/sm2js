const test = require('tape')
const util = require('../src/util')

test('UTF8 string to Uint8Array test', function (t) {
  const chinese = '你好世界'
  const result = util.toHex(util.normalizeInput(chinese))
  t.equals(result, 'e4bda0e5a5bde4b896e7958c')
  t.end()
})

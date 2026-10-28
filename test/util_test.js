const test = require('tape')
const util = require('../src/util')

test('hex decoding rejects invalid input without partial parsing', function (t) {
  for (const input of ['zz', '1g', '0x', ' 0', '00\n', '000\n', 'abc\r', '0', null, undefined, 12]) {
    t.throws(() => util.hexToUint8Array(input), /Invalid hex string/)
  }
  t.deepEqual(util.hexToUint8Array(''), new Uint8Array())
  t.equal(util.toHex(util.hexToUint8Array('00aAFF')), '00aaff')
  t.end()
})

test('UTF8 string to Uint8Array test', function (t) {
  const chinese = '你好世界'
  const result = util.toHex(util.normalizeInput(chinese))
  t.equals(result, 'e4bda0e5a5bde4b896e7958c')
  t.end()
})

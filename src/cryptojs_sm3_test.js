require('./cryptojs_sm3')
const test = require('tape')
const rs = require('jsrsasign')

test('SM3 basic', function (t) {
  t.equal(rs.CryptoJS.enc.Hex.stringify(rs.CryptoJS.SM3('abc')),
    '66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0')

  t.equal(rs.CryptoJS.enc.Hex.stringify(rs.CryptoJS.SM3('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')),
    'debe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732')

  t.equal(rs.CryptoJS.enc.Hex.stringify(rs.CryptoJS.SM3('abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd')),
    '6888fa292df4b51341e82e3072fbdd63598439c64eda318a81756ca71a7a6c15')

  t.end()
})

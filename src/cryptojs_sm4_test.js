require('./cryptojs_sm4')
const test = require('tape')
const rs = require('jsrsasign')
const C = rs.CryptoJS

test('test sample 1', (t) => {
  const ciphertext = C.SM4.encrypt(
    C.enc.Hex.parse('0123456789abcdeffedcba9876543210'),
    C.enc.Hex.parse('0123456789abcdeffedcba9876543210'),
    { mode: C.mode.ECB, padding: C.pad.NoPadding }
  ).ciphertext.toString()
  t.equal(ciphertext, '681edf34d206965e86b3e94f536e4246')

  const plaintext = C.SM4.decrypt(
    { ciphertext: C.enc.Hex.parse('681edf34d206965e86b3e94f536e4246') },
    C.enc.Hex.parse('0123456789abcdeffedcba9876543210'),
    { mode: C.mode.ECB, padding: C.pad.NoPadding }
  )
  t.equal(plaintext.toString(), '0123456789abcdeffedcba9876543210')
  t.end()
})

test('test sm4-cbc', (t) => {
  const cases = [
    {
      key: '30313233343536373839414243444546',
      iv: '30313233343536373839414243444546',
      plaintext: '48656c6c6f20576f726c64',
      ciphertext: '0a67062f0cd2dce26a7b978ebf2134f9'
    },
    {
      key: '30313233343536373839414243444546',
      iv: '30313233343536373839414243444546',
      plaintext:
        '48656c6c6f20576f726c642048656c6c6f20576f726c642048656c6c6f20576f726c642048656c6c6f20576f726c6464',
      ciphertext:
        'd31e3683e4fc9b516a2c0f983676a9eb1fdcc32af38408978157a2065de34c6a068d0fef4e2bfab4bcaba66441fde0fe92c164eca170247572de1202952ec727'
    },
    {
      key: '0123456789abcdeffedcba9876543210',
      iv: '00000000000000000000000000000000',
      plaintext: '0123456789abcdeffedcba9876543210',
      ciphertext:
        '681edf34d206965e86b3e94f536e4246677d307e844d7aa24579d556490dc7aa'
    }
  ]
  for (const c of cases) {
    const ciphertext = C.SM4.encrypt(
      C.enc.Hex.parse(c.plaintext),
      C.enc.Hex.parse(c.key),
      { mode: C.mode.CBC, padding: C.pad.Pkcs7, iv: C.enc.Hex.parse(c.iv) }
    ).ciphertext.toString()
    t.equal(ciphertext, c.ciphertext)
    const plaintext = C.SM4.decrypt(
      { ciphertext: C.enc.Hex.parse(c.ciphertext) },
      C.enc.Hex.parse(c.key),
      { mode: C.mode.CBC, padding: C.pad.Pkcs7, iv: C.enc.Hex.parse(c.iv) }
    )
    t.equal(plaintext.toString(), c.plaintext)
  }
  t.end()
})
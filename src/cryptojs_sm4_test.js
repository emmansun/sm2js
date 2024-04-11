require('./cryptojs_sm4')
const test = require('tape')
const sjcl = require('sjcl-with-all')
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

test('test sm4-gcm', (t) => {
  const cases = [
    {
      key: '00000000000000000000000000000000',
      nonce: '000000000000000000000000',
      plaintext: '00000000000000000000000000000000',
      ad: undefined,
      ciphertext:
        '7de2aa7f1110188218063be1bfeb6d89b851b5f39493752be508f1bb4482c557'
    },
    {
      key: '7fddb57453c241d03efbed3ac44e371c',
      nonce: 'ee283a3fc75575e33efd4887',
      plaintext: 'd5de42b461646c255c87bd2962d3b9a2',
      ad: undefined,
      ciphertext:
        '15e29a2a64bfc2974286e0cb84cfc7fa6c5ed60f77e0832fbbd81f07958f3934'
    },
    {
      key: 'fe47fcce5fc32665d2ae399e4eec72ba',
      nonce: '5adb9609dbaeb58cbd6e7275',
      plaintext:
        '7c0e88c88899a779228465074797cd4c2e1498d259b54390b85e3eef1c02df60e743f1b840382c4bccaf3bafb4ca8429bea063',
      ad: '88319d6e1d3ffa5f987199166c8a9b56c2aeba5a',
      ciphertext:
        '2276da0e9a4ccaa2a5934c96ba1dc6b0a52b3430ca011b4db4bf6e298b3a58425402952806350fdda7ac20bc38838d7124ee7c333e395b9a94c508b6bf0ce6b2d10d61'
    },
    {
      key: 'ec0c2ba17aa95cd6afffe949da9cc3a8',
      nonce: '296bce5b50b7d66096d627ef',
      plaintext:
        'b85b3753535b825cbe5f632c0b843c741351f18aa484281aebec2f45bb9eea2d79d987b764b9611f6c0f8641843d5d58f3a242',
      ad: 'f8d00f05d22bf68599bcdeb131292ad6e2df5d14',
      ciphertext:
        '3175cd3cb772af34490e4f5203b6a5743cd9b3798c387b7bda2708ff82d520c35d3022767b2d0fe4addff59fb25ead69ca3dd4d73ce1b4cb53a7c4cdc6a4c1fb06c316'
    },
    {
      key: '2c1f21cf0f6fb3661943155c3e3d8492',
      nonce: '23cb5ff362e22426984d1907',
      plaintext:
        '42f758836986954db44bf37c6ef5e4ac0adaf38f27252a1b82d02ea949c8a1a2dbc0d68b5615ba7c1220ff6510e259f06655d8',
      ad: '5d3624879d35e46849953e45a32a624d6a6c536ed9857c613b572b0333e701557a713e3f010ecdf9a6bd6c9e3e44b065208645aff4aabee611b391528514170084ccf587177f4488f33cfb5e979e42b6e1cfc0a60238982a7aec',
      ciphertext:
        '9db299bb7f9d6914c4a13589cf41ab014445e4914c1571745d50508bf0f6adeaa41aa4b081a444ee82fed6769da92f5e727d004b21791f961e212a69bfe80af14e7adf'
    },
    {
      key: '9a4fea86a621a91ab371e492457796c0',
      nonce: '75',
      plaintext:
        'ca6131faf0ff210e4e693d6c31c109fc5b6f54224eb120f37de31dc59ec669b6',
      ad: '4f6e2585c161f05a9ae1f2f894e9f0ab52b45d0f',
      ciphertext:
        'b86d6055e7e07a664801ccce38172bf7d91dc20babf2c0662d635cc9111ffefb308ee64ce01afe544b6ee1a65b803cb9'
    },
    {
      key: '0123456789abcdeffedcba9876543210',
      nonce: '00001234567800000000abcd',
      plaintext:
        'aaaaaaaaaaaaaaaabbbbbbbbbbbbbbbbccccccccccccccccddddddddddddddddeeeeeeeeeeeeeeeeffffffffffffffffeeeeeeeeeeeeeeeeaaaaaaaaaaaaaaaa',
      ad: 'feedfacedeadbeeffeedfacedeadbeefabaddad2',
      ciphertext:
        '17f399f08c67d5ee19d0dc9969c4bb7d5fd46fd3756489069157b282bb200735d82710ca5c22f0ccfa7cbf93d496ac15a56834cbcf98c397b4024a2691233b8d83de3541e4c2b58177e065a9bf7b62ec'
    }
  ]
  for (const c of cases) {
    const sm4 = C.algo.SM4.createEncryptor(C.enc.Hex.parse(c.key))
    const got = sjcl.mode.gcm.encrypt(
      sm4,
      sjcl.codec.hex.toBits(c.plaintext),
      sjcl.codec.hex.toBits(c.nonce),
      c.ad ? sjcl.codec.hex.toBits(c.ad) : undefined,
      128
    )
    t.equal(sjcl.codec.hex.fromBits(got), c.ciphertext)
    const opened = sjcl.mode.gcm.decrypt(
      sm4,
      sjcl.codec.hex.toBits(c.ciphertext),
      sjcl.codec.hex.toBits(c.nonce),
      c.ad ? sjcl.codec.hex.toBits(c.ad) : undefined,
      128
    )
    t.equal(sjcl.codec.hex.fromBits(opened), c.plaintext)
  }
  t.end()
})

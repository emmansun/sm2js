const test = require('tape')
const { spawnSync } = require('node:child_process')
const path = require('node:path')
const rs = require('jsrsasign')
const KJUR = rs.KJUR
const originalEncrypt = KJUR.crypto.Cipher.encrypt
const originalDecrypt = KJUR.crypto.Cipher.decrypt
const originalDerive = rs.KEYUTIL.getDKFromPBES2Param
require('../src/jsrsasign_patch').patch()

test('patch is idempotent and preserves non-GM behavior', (t) => {
  const encrypt = KJUR.crypto.Cipher.encrypt
  require('../src/jsrsasign_patch').patch()
  t.equal(KJUR.crypto.Cipher.encrypt, encrypt)
  const plaintext = '48656c6c6f20576f726c64'
  const iv = '30313233343536373839414243444546'
  for (const [algorithm, key] of [
    ['aes128-CBC', iv],
    ['aes256-CBC', iv + iv],
    ['des-EDE3-CBC', iv + '3031323334353637']
  ]) {
    const expected = originalEncrypt(plaintext, key, algorithm, { iv })
    t.equal(KJUR.crypto.Cipher.encrypt(plaintext, key, algorithm, { iv }), expected)
    t.equal(KJUR.crypto.Cipher.decrypt(expected, key, algorithm, { iv }), originalDecrypt(expected, key, algorithm, { iv }))
  }
  const params = { salt: '0123456789abcdef', iter: 2, prf: 'hmacWithSHA256', encalg: 'aes128-CBC' }
  t.equal(rs.KEYUTIL.getDKFromPBES2Param(params, 'test'), originalDerive(params, 'test'))
  t.end()
})

test('test sm4-cbc with KJUR.crypto.Cipher', (t) => {
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
    const ciphertext = KJUR.crypto.Cipher.encrypt(
      c.plaintext,
      c.key,
      'sm4-CBC',
      { iv: c.iv }
    )
    t.equal(ciphertext, c.ciphertext)
    const plaintext = KJUR.crypto.Cipher.decrypt(
      c.ciphertext,
      c.key,
      'sm4-CBC',
      { iv: c.iv }
    )
    t.equal(plaintext, c.plaintext)
    t.equal(KJUR.crypto.Cipher.encrypt(c.plaintext, null, null, { encalg: 'sm4-CBC', key: c.key, iv: c.iv }), c.ciphertext)
    t.equal(KJUR.crypto.Cipher.decrypt(c.ciphertext, null, null, { encalg: 'sm4-CBC', key: c.key, iv: c.iv }), c.plaintext)
  }
  t.end()
})

test('SM4 rejects malformed input and invalid PKCS7 padding', (t) => {
  const key = '30313233343536373839414243444546'
  const iv = key
  const cipher = KJUR.crypto.Cipher
  for (const invalidKey of ['', key.slice(2), key + '00', 'zz'.repeat(16)]) {
    t.throws(() => cipher.encrypt('00', invalidKey, 'sm4-CBC', { iv }))
    t.throws(() => cipher.decrypt('00'.repeat(16), invalidKey, 'sm4-CBC', { iv }))
  }
  for (const invalidIV of ['', iv.slice(2), iv + '00', 'zz'.repeat(16), undefined]) {
    t.throws(() => cipher.encrypt('00', key, 'sm4-CBC', { iv: invalidIV }))
    t.throws(() => cipher.decrypt('00'.repeat(16), key, 'sm4-CBC', { iv: invalidIV }))
  }
  for (const invalidHex of ['1g', 'zz', '0', '00\n', '000\n']) {
    t.throws(() => cipher.encrypt(invalidHex, key, 'sm4-CBC', { iv }), /Invalid hex string/)
    t.throws(() => cipher.decrypt(invalidHex, key, 'sm4-CBC', { iv }), /Invalid hex string/)
  }
  for (const ciphertext of ['', '00', '00'.repeat(15), '00'.repeat(17)]) {
    t.throws(() => cipher.decrypt(ciphertext, key, 'sm4-CBC', { iv }), /invalid sm4 ciphertext length/)
  }
  for (const block of ['00'.repeat(16), '00'.repeat(15) + '11', '00'.repeat(15) + '02']) {
    const ciphertext = rs.CryptoJS.SM4.encrypt(rs.CryptoJS.enc.Hex.parse(block), rs.CryptoJS.enc.Hex.parse(key), {
      iv: rs.CryptoJS.enc.Hex.parse(iv), padding: rs.CryptoJS.pad.NoPadding
    }).ciphertext.toString()
    t.throws(() => cipher.decrypt(ciphertext, key, 'sm4-CBC', { iv }), /sm4: decryption error/)
  }
  for (const plaintext of ['', '00', '00'.repeat(15), '00'.repeat(16), '00'.repeat(17)]) {
    t.equal(cipher.decrypt(cipher.encrypt(plaintext, key, 'sm4-CBC', { iv }), key, 'sm4-CBC', { iv }), plaintext)
  }
  t.throws(() => rs.CryptoJS.algo.SM4.createEncryptor(rs.CryptoJS.enc.Hex.parse(key.slice(2))), /invalid sm4 key size/)
  t.end()
})

if (process.env.SM2JS_TEST_FALLBACK !== '1') {
  test('SM2 and SM4 suites also pass without native SM3/SM4', (t) => {
    const code = [
      'const crypto = require("node:crypto")',
      'crypto.getCiphers = () => []',
      'crypto.getHashes = () => []',
      'require("./test/jsrsasign_patch_test")',
      'require("./test/sm2_test")'
    ].join(';')
    const result = spawnSync(process.execPath, ['-e', code], {
      cwd: path.resolve(__dirname, '..'),
      env: { ...process.env, SM2JS_TEST_FALLBACK: '1' },
      encoding: 'utf8',
      timeout: 30000
    })
    t.error(result.error)
    t.equal(result.status, 0, 'pure JavaScript suites pass')
    if (result.status !== 0) t.comment(result.stdout + result.stderr)
    t.end()
  })
}

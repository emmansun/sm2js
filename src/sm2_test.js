const test = require('tape')
const rs = require('jsrsasign')
const sm2 = require('./sm2')

const publicKeyPemFromAliKmsForSign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX
6TCKAmQJArAO7VOtZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEA==
-----END PUBLIC KEY-----
`

const signatureHex = '30450220757984e0a063394ee0792b52172dd4273c05e2a66d734ff804a37b9ac639c098022100d9739a8d7a37fc88a1b4210998da489ad5b0dee1c8cb9097e532318aded5d204'

test('SM2 P-256 encrypt/decrypt local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })
  const plainText = 'emmansun'
  const expected = '656d6d616e73756e'
  const keypair = ec.generateKeyPairHex()

  const ciphertext = sm2.encrypt(keypair.ecpubhex, plainText)
  console.log('ciphertext=' + ciphertext)
  const result = sm2.decryptHex(keypair.ecprvhex, ciphertext)

  t.equal(result, expected)
  t.end()
})

test('SM2 P-256 sign/verify local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })

  const keypair = ec.generateKeyPairHex()

  const sig1 = new sm2.Signature({ alg: 'SM3withECDSA' })
  sig1.init({ curve: sm2.getCurveName(), d: keypair.ecprvhex })
  sig1.updateString('emmansun')
  const hSig = sig1.sign()
  console.log(hSig)
  const sig2 = new sm2.Signature({ alg: 'SM3withECDSA' })
  sig2.init({ curve: sm2.getCurveName(), xy: keypair.ecpubhex })
  sig2.updateString('emmansun')
  t.true(sig2.verify(hSig))
  t.end()
})

test('NIST P-256 sign/verify local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })

  const keypair = ec.generateKeyPairHex()
  const sig1 = new sm2.Signature({ alg: 'SHA256withECDSA' })
  sig1.init({ curve: sm2.getCurveName(), d: keypair.ecprvhex })
  sig1.updateString('emmansun')
  const hSig = sig1.sign()
  console.log(hSig)
  const sig2 = new sm2.Signature({ alg: 'SHA256withECDSA' })
  sig2.init({ curve: sm2.getCurveName(), xy: keypair.ecpubhex })
  sig2.updateString('emmansun')
  t.true(sig2.verify(hSig))
  t.end()
})

test('SM2 parse public key pem, verify signature, both from ali KMS', function (t) {
  const sig = new sm2.Signature({ alg: 'SM3withECDSA' })
  sig.init(publicKeyPemFromAliKmsForSign)
  t.equal(sig.pubKey.curveName, sm2.getCurveName())
  t.true(sig.verifyWithMessageHash('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', signatureHex))
  t.end()
})

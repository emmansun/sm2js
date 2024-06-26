const test = require('tape')
const rs = require('jsrsasign')
const sm2 = require('../src/sm2')
const util = require('../src/util')

const publicKeyPemFromAliKmsForSign = `-----BEGIN PUBLIC KEY-----
MFkwEwYHKoZIzj0CAQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX
6TCKAmQJArAO7VOtZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEA==
-----END PUBLIC KEY-----
`
const sm2PKIXPublicKeyHex = '3059301306072a8648ce3d020106082a811ccf5501822d03420004ef7db908af06082ef4a30e0ec28623371c106a53296a7b0e1a9b5717bd9cb81beb20d094aba685fd0f6a7ecc007ccf797ba634476326723b303d9dec873f440b'

const signatureHex = '30450220757984e0a063394ee0792b52172dd4273c05e2a66d734ff804a37b9ac639c098022100d9739a8d7a37fc88a1b4210998da489ad5b0dee1c8cb9097e532318aded5d204'

const csrFromAli = `-----BEGIN CERTIFICATE REQUEST-----
MIIBYjCCAQkCAQAwRzELMAkGA1UEBhMCQ04xEzARBgNVBAMMCkNhcmdvU21hcnQx
DzANBgNVBAcMBlpodWhhaTESMBAGA1UECAwJR3Vhbmdkb25nMFkwEwYHKoZIzj0C
AQYIKoEcz1UBgi0DQgAERrsLH25zLm2LIo6tivZM9afLprSX6TCKAmQJArAO7VOt
ZyW4PQwfaTsUIF7IXEFG4iI8bNuTQwMykUzLu2ypEKBgMC4GCSqGSIb3DQEJDjEh
MB8wHQYDVR0OBBYEFA3FO8vT+8qZBfGZa2TRhLRbme+9MC4GCSqGSIb3DQEJDjEh
MB8wHQYDVR0RBBYwFIESZW1tYW4uc3VuQGlxYXguY29tMAoGCCqBHM9VAYN1A0cA
MEQCIBQx6yv3rzfWCkKqDZQOfNKESQc6NtpQbeVvcxfBrciwAiAj78kkrF5R3g4l
bxIHjKZHc2sztHCXe7cseWGiLq0syg==
-----END CERTIFICATE REQUEST-----
`
// CA was from https://www.gmcert.org/
const CA_CERT = `-----BEGIN CERTIFICATE-----
MIICIzCCAcigAwIBAgIJAKun/ZLoSXfeMAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT
AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK
DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X
DTE5MTAyNDEyMzEzM1oXDTM5MDcxMTEyMzEzM1owZzELMAkGA1UEBhMCQ04xEDAO
BgNVBAgMB0JlaWppbmcxEDAOBgNVBAcMB0hhaURpYW4xEzARBgNVBAoMCkdNQ2Vy
dC5vcmcxHzAdBgNVBAMMFkdNQ2VydCBHTSBSb290IENBIC0gMDEwWTATBgcqhkjO
PQIBBggqgRzPVQGCLQNCAASXWWtv+ifV7dJHqPNXwcmioh/48Wg3IuI+o11nLEOD
zljxL2yMxoQM6xfNJHuqadXXNZv3D2rml5Pk0W/tmfHEo10wWzAdBgNVHQ4EFgQU
f1peOwCEWSoPmL6hDm85lUMQTQcwHwYDVR0jBBgwFoAUf1peOwCEWSoPmL6hDm85
lUMQTQcwDAYDVR0TBAUwAwEB/zALBgNVHQ8EBAMCAQYwCgYIKoEcz1UBg3UDSQAw
RgIhAJ7AZAC0i+4OyfxDuvPIg0I7ZtqL2kII2f1syaIW4C6iAiEAlHuUu0TMrOAr
sU47scL1B9BhyEh5tbEjsKLHia3K0YU=
-----END CERTIFICATE-----
`

// cert was generated from https://www.gmcert.org/
const cert = `-----BEGIN CERTIFICATE-----
MIICDTCCAbOgAwIBAgIJAOWoGwJCnVw5MAoGCCqBHM9VAYN1MGcxCzAJBgNVBAYT
AkNOMRAwDgYDVQQIDAdCZWlqaW5nMRAwDgYDVQQHDAdIYWlEaWFuMRMwEQYDVQQK
DApHTUNlcnQub3JnMR8wHQYDVQQDDBZHTUNlcnQgR00gUm9vdCBDQSAtIDAxMB4X
DTIxMDIyNDA3NTgxMloXDTIyMDIyNDA3NTgxMlowIjELMAkGA1UEBhMCQ04xEzAR
BgNVBAMMCkNhcmdvU21hcnQwWTATBgcqhkjOPQIBBggqgRzPVQGCLQNCAATi93H1
6+sN4/e6ksqPb/yAaR5/ewgO0PVAtAqMXV3IIZsug/VgFrduCzE71PKHHKKrY3MA
d1pP8ozvDIGpoYJ8o4GMMIGJMAwGA1UdEwEB/wQCMAAwCwYDVR0PBAQDAgeAMCwG
CWCGSAGG+EIBDQQfFh1HTUNlcnQub3JnIFNpZ25lZCBDZXJ0aWZpY2F0ZTAdBgNV
HQ4EFgQUPY0wMfEXn8wNhQTy7bL/dNJcA1UwHwYDVR0jBBgwFoAUf1peOwCEWSoP
mL6hDm85lUMQTQcwCgYIKoEcz1UBg3UDSAAwRQIgQsJ/kjgsc5cDavOvLvAOn2c9
u1EHM5QIWn58/xlMu1gCIQDk7Kp4A/c+W2lr93yFHiTPxwtKIz/nwtH4GRAcxeiM
iA==
-----END CERTIFICATE-----
`

const sm2PrivateKeyEncryptedPKCS8 = `
-----BEGIN ENCRYPTED PRIVATE KEY-----
MIH2MGEGCSqGSIb3DQEFDTBUMDQGCSqGSIb3DQEFDDAnBBDa6ckWJNP3QBD7MIF8
4nVqAgEQAgEQMA0GCSqBHM9VAYMRAgUAMBwGCCqBHM9VAWgCBBDMUgr+5Y/XN2g9
mPGiISzGBIGQytwK98/ET4WrS0H7AsUri6FTqztrzAvgzFl3+s9AsaYtUlzE3EzE
x6RWxo8kpKO2yj0a/Jh9WZCD4XAcoZ9aMopiWlOdpXJr/iQlMGdirCYIoF37lHMc
jZHNffmk4ii7NxCfjrzpiFq4clYsNMXeSEnq1tuOEur4kYcjHYSIFc9bPG656a60
+SIJsJuPFi0f
-----END ENCRYPTED PRIVATE KEY-----`

const sm2PrivateKeyPlainPKCS8 = `-----BEGIN PRIVATE KEY-----
MIGHAgEAMBMGByqGSM49AgEGCCqBHM9VAYItBG0wawIBAQQgbFoKCy7tPL7D5PEl
K/4OKMUEoca/GZnuuwr57w+ObIWhRANCAASDVuZCpA69GNKbo1MvvZ87vujwJ8P2
85pbovhwNp+ZiJgfXv5V0cXN9sDvKwcIR6FPf99CcqjfCcRC8wWK+Uuh
-----END PRIVATE KEY-----`

const pkcs8SM2P256PrivateKeyHex = '308187020100301306072a8648ce3d020106082a811ccf5501822d046d306b0201010420b26da57ba53004ddcd387ad46a361b51b308481f2327d47fb10c5fb3a8c86b92a144034200040d5365bfdbdc564c5b0eda0a85ddbd753821a709de90efe0666ba2544766acf1100ac0484d166842011da5cd6139e53dedb99ce37cea9edf4941628066e861bf'

const sec1SM2PrivateKeyHex = '30770201010420857dd87970aab4328dad891c781e3b270742aa9cf5d3d3764efe77f6c3d6e33aa00a06082a811ccf5501822da14403420004ced963a5705a0490ff13dde893cbda6de61f41fcaf917a5b4007d30cdec46426bc39b9c18d15b2a68a64dc333f262e600b675856285b42296f24741ee6f562a0'

test('SM2 P-256 encrypt/decrypt local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })
  const plainText = 'send reinforcements, we\'re going to advance'
  const expected = '73656e64207265696e666f7263656d656e74732c20776527726520676f696e6720746f20616476616e6365'
  const keypair = ec.generateKeyPairHex()

  const ciphertext = sm2.encrypt(keypair.ecpubhex, plainText)
  const asn1text = sm2.plainCiphertext2ASN1(ciphertext)
  console.log('ciphertext=' + ciphertext)
  console.log('asn.1 ciphertext=' + asn1text)
  const ciphertext1 = sm2.asn1Ciphertext2Plain(asn1text)
  t.equal(ciphertext1, ciphertext)
  const result = sm2.decryptHex(keypair.ecprvhex, ciphertext)
  t.equal(result, expected)
  const result2 = sm2.decryptHex(keypair.ecprvhex, asn1text)
  t.equal(result2, expected)
  t.end()
})

test('SM2 P-256 encrypt, output hex asn.1 ciphertext', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })
  const plainText = 'send reinforcements, we\'re going to advance'
  const expected = '73656e64207265696e666f7263656d656e74732c20776527726520676f696e6720746f20616476616e6365'
  const keypair = ec.generateKeyPairHex()
  const ciphertext = sm2.encrypt(keypair.ecpubhex, plainText, sm2.asn1EncrypterOptions())
  const tag = ciphertext.substring(0, 2)
  t.equal(tag, '30')
  const result = sm2.decryptHex(keypair.ecprvhex, ciphertext)
  t.equal(result, expected)
  t.end()
})

test('SM2 P-256 sign/verify local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })

  const keypair = ec.generateKeyPairHex()

  const sig1 = sm2.createSM2Signature()
  sig1.init({ curve: sm2.getCurveName(), d: keypair.ecprvhex })
  sig1.updateString('emmansun')
  const hSig = sig1.sign()
  console.log('hSig=' + hSig)
  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: keypair.ecpubhex })
  sig2.updateString('emmansun')
  t.true(sig2.verify(hSig))
  t.end()
})

test('SM2 P-256 sm2 specific sign/verify', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })

  const keypair = ec.generateKeyPairHex()

  const sig1 = sm2.createSM2Signature()
  sig1.init({ curve: sm2.getCurveName(), d: keypair.ecprvhex })

  const hSig = sig1.sm2Sign('emmansun')
  const hSig1 = sig1.sm2Sign('emmansun 1')
  console.log('hSig=' + hSig)
  console.log('hSig1=' + hSig1)
  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: keypair.ecpubhex })
  t.true(sig2.sm2Verify(hSig, 'emmansun'))
  t.true(sig2.sm2Verify(hSig1, 'emmansun 1'))
  t.end()
})

test('NIST P-256 sign/verify local', function (t) {
  const ec = new rs.ECDSA({ curve: sm2.getCurveName() })

  const keypair = ec.generateKeyPairHex()
  const sig1 = new sm2.Signature({ alg: 'SHA256withECDSA' })
  sig1.init({ curve: sm2.getCurveName(), d: keypair.ecprvhex })
  sig1.updateString('emmansun')
  const hSig = sig1.sign()
  console.log('hSig=' + hSig)
  const sig2 = new sm2.Signature({ alg: 'SHA256withECDSA' })
  sig2.init({ curve: sm2.getCurveName(), xy: keypair.ecpubhex })
  sig2.updateString('emmansun')
  t.true(sig2.verify(hSig))
  t.end()
})

test('SM2 parse public key pem, verify signature, both from ali KMS', function (t) {
  const sig = sm2.createSM2Signature()
  sig.init(publicKeyPemFromAliKmsForSign)
  t.equal(sig.pubKey.curveName, sm2.getCurveName())
  t.true(sig.verifyWithMessageHash('66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0', signatureHex))
  t.end()
})

test('SM2 calculate ZA', function (t) {
  const sig = sm2.createSM2Signature()
  sig.init(publicKeyPemFromAliKmsForSign)
  const za = util.toHex(sig.pubKey.calculateZA())
  t.equal(za, '17e7fc071f1418200aeead3c5118a2f18381431d92b808a3bd1ba2d8270c2914')
  t.end()
})

test('SM2 parse CSR from ALI KMS', function (t) {
  const result = rs.asn1.csr.CSRUtil.getParam(csrFromAli)
  t.equal(result.sigalg, sm2.getSignAlg())
  t.end()
})

test('SM2 gen CSR', function (t) {
  const kp = rs.KEYUTIL.generateKeypair('EC', sm2.getCurveName())
  const prvKey = kp.prvKeyObj
  const pubKey = kp.pubKeyObj

  const csr = rs.asn1.csr.CSRUtil.newCSRPEM({
    subject: { str: '/C=US/O=TEST' },
    sbjpubkey: pubKey,
    sigalg: sm2.getSignAlg(),
    sbjprvkey: prvKey
  })
  console.log(csr)
  const result = rs.asn1.csr.CSRUtil.getParam(csr)
  console.log(JSON.stringify(result))
  t.end()
})

test('SM2 read cert', function (t) {
  const x = sm2.createX509()
  x.readCertPEM(cert)
  t.equal(x.getSignatureAlgorithmField(), sm2.getSignAlg())
  t.true(x.verifySignature(rs.KEYUTIL.getKey(CA_CERT)))
  t.end()
})

test('Parse PKCS8 encrypted SM2 private key', function (t) {
  const key = rs.KEYUTIL.getKeyFromEncryptedPKCS8PEM(sm2PrivateKeyEncryptedPKCS8, 'Password1')
  t.equal(key.curveName, 'sm2p256v1')
  t.equal(key.prvKeyHex, '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  t.equal(key.pubKeyHex, '048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1')
  t.end()
})

test('Parse PKCS8 unencrypted SM2 private key', function (t) {
  const key = rs.KEYUTIL.getKeyFromPlainPrivatePKCS8PEM(sm2PrivateKeyPlainPKCS8)
  t.equal(key.curveName, 'sm2p256v1')
  t.equal(key.prvKeyHex, '6c5a0a0b2eed3cbec3e4f1252bfe0e28c504a1c6bf1999eebb0af9ef0f8e6c85')
  t.equal(key.pubKeyHex, '048356e642a40ebd18d29ba3532fbd9f3bbee8f027c3f6f39a5ba2f870369f9988981f5efe55d1c5cdf6c0ef2b070847a14f7fdf4272a8df09c442f3058af94ba1')
  t.end()
})

test('Parse PKCS8 unencrypted SM2 private key with Signature', function (t) {
  const sig1 = sm2.createSM2Signature()
  sig1.init(sm2PrivateKeyPlainPKCS8)

  const hSig = sig1.sm2Sign('emmansun')
  console.log('hSig=' + hSig)

  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: sig1.prvKey.pubKeyHex })
  t.true(sig2.sm2Verify(hSig, 'emmansun'))

  t.end()
})

test('Parse PKCS8 encrypted SM2 private key with Signature', function (t) {
  const sig1 = sm2.createSM2Signature()
  sig1.init(sm2PrivateKeyEncryptedPKCS8, 'Password1')

  const hSig = sig1.sm2Sign('emmansun')
  console.log('hSig=' + hSig)

  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: sig1.prvKey.pubKeyHex })
  t.true(sig2.sm2Verify(hSig, 'emmansun'))

  t.end()
})

test('Parse PKCS8 unencrypted SM2 private key (hex) with Signature', function (t) {
  const sig1 = sm2.createSM2Signature()
  sig1.init(pkcs8SM2P256PrivateKeyHex, undefined, 'pkcs8prv')

  const hSig = sig1.sm2Sign('emmansun')
  console.log('hSig=' + hSig)

  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: sig1.prvKey.pubKeyHex })
  t.true(sig2.sm2Verify(hSig, 'emmansun'))

  t.end()
})

test('Parse SEC1 SM2 private key (hex) with Signature', function (t) {
  const sig1 = sm2.createSM2Signature()
  sig1.init(sec1SM2PrivateKeyHex, undefined, 'pkcs5prv')

  const hSig = sig1.sm2Sign('emmansun')
  console.log('hSig=' + hSig)

  const sig2 = sm2.createSM2Signature()
  sig2.init({ curve: sm2.getCurveName(), xy: sig1.prvKey.pubKeyHex })
  t.true(sig2.sm2Verify(hSig, 'emmansun'))

  t.end()
})

test('Parse SM2 PKIX public key (hex) with Signature', function (t) {
  const sig1 = sm2.createSM2Signature()
  sig1.init(sm2PKIXPublicKeyHex, undefined, 'pkcs8pub')
  t.equals(sig1.pubKey.pubKeyHex, '04ef7db908af06082ef4a30e0ec28623371c106a53296a7b0e1a9b5717bd9cb81beb20d094aba685fd0f6a7ecc007ccf797ba634476326723b303d9dec873f440b')
  t.end()
})

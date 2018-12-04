const Crypto = require('./crypto')

let AESInstance = null
let cryptoKeyAES = null

const debug = (str) => {
  if (process.env.NODE_ENV !== 'production') console.log(str)
}

document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('generateAESKeyTrue')
  if (el) {
    el.addEventListener('click', function (e) {
      console.log('To disable debug print, remove --mode=development from webpack command in package.json')
      generateAESKey(true)
    })
  }
  el = document.getElementById('generateAESKeyFalse')
  if (el) {
    el.addEventListener('click', function (e) {
      console.log('To disable debug print, remove --mode=development from webpack command in package.json')
      generateAESKey(false)
    })
  }
  el = document.getElementById('exportAESKey')
  if (el) {
    el.addEventListener('click', function (e) {
      exportAESKey()
    })
  }
  el = document.getElementById('encryptDecrypt')
  if (el) {
    el.addEventListener('click', function (e) {
      encryptDecrypt(cryptoKeyAES)
    })
  }
  el = document.getElementById('deriveKey')
  if (el) {
    el.addEventListener('click', function (e) {
      deriveKey()
    })
  }
})

const generateAESKey = async (extractable) => {
  debug('generateAESKey')
  const mode = 'aes-gcm'
  const keySize = 128
  AESInstance = new Crypto()
  AESInstance.genAESKey(extractable, mode, keySize)
    .then(AESCryptoKey => {
      cryptoKeyAES = AESCryptoKey
      // We print the key
      console.log(AESCryptoKey)
      let el = document.getElementById('step1KeyGeneration')
      el.innerHTML = fillElement(`Now, key successfully generated, open the developer console, and check the cryptokey. Yous must obtain something like this : 
  \n CryptoKey { type: "secret", extractable: ${extractable}, algorithm: {…}, usages:  }`)
    })
    .catch(err => {
      console.log(err)
    })
}

const exportAESKey = () => {
  let messageToPrint = null
  let el = document.getElementById('step2KeyExport')
  // choose either 'raw' or 'jwk' format
  AESInstance.exportKey(cryptoKeyAES,'jwk')
    .then(exportedKey => {
      console.log(exportedKey)
      messageToPrint = 'Successfully exported. Now try again, relaod the page but choose to  generate the AES key with the extractable property set to false.'
      el.innerHTML = fillElement(`${messageToPrint}`)
    })
    .catch(err => {
      console.log(err)
      messageToPrint = err
      el.innerHTML = fillElement(`You generate a non extractable AES key, the export is not authorized. <br/>${messageToPrint}`)
    })
}

const encryptDecrypt = (encryptionKey) => {
  let data = { username: 'bob' }
  console.log(`Initial message: ${JSON.stringify(data)}`)
  AESInstance.encrypt(encryptionKey, data)
    .then(ciphertext => {
    // console.log(ciphertext.ciphertext)
      let el = document.getElementById('step3Encrypt')
      el.innerHTML = fillElement(`
  No matter if the generated AES key is extractable or not, you can encrypt/dectypt data using a black box. <br/>
  Initial message : ${JSON.stringify(data)}<br/>
  Encrypted msg : ${ciphertext.ciphertext.slice(0, 10)}...`)
      return AESInstance.decrypt(encryptionKey, ciphertext)
    })
    .then(plaintext => {
      console.log('Decrypted message', plaintext)
      let el = document.getElementById('step3Decrypt')
      el.innerHTML = (`<p>
    Decrypted message : ${plaintext}</p>`)
    })
    .catch(err => console.log(err))
}

const deriveKey = () => {
  let messageToPrint = null
  let el = document.getElementById('step4Derive')
  const passPhrase = 'hello'
  const iterations = 100000
  const mode = 'aes-gcm'
  const type = 'jwk'
  // const type = 'raw'
  return AESInstance.deriveKey(passPhrase, mode, Buffer.from('theSalt'), iterations)
    .then(wrappingKey => {
      console.log('Salt : ', Buffer.from('theSalt'))
      console.log('Iterations : ', iterations)
      console.log('Wrapping key : ', wrappingKey)
      el.innerHTML = fillElement(`Passphrase derivation succesfully done. `)
      AESInstance.wrapKey(cryptoKeyAES, wrappingKey, 128, type, mode)
        .then(wrappedKey => {
          console.log('Wrapped key', wrappedKey)
          let el = document.getElementById('step4WrapSuccess')
          el.innerHTML = (`<p>
          Wrapping of AES key : ok</p>`)
          AESInstance.unwrapKey(wrappedKey.encryptedMasterKey, wrappingKey, wrappedKey.iv, 128, type, mode)
            .then(unwrappedKey => {
              console.log('Unwrapped key', unwrappedKey)
              // encryptDecrypt(unwrappedKey)
            }).catch(err => console.log(err))
        }).catch(err => {
          console.log(err)
          let el = document.getElementById('step4WrapFail')
          el.innerHTML = (`<p>
          You generate a non extractable AES key, the wrap opertion is not authorized.<br/>
          Wrapping of AES key : fail</p>`)
        })
    }).catch(err => console.log(err))

    .catch(err => console.log(err))
}

const fillElement = (str) => {
  return `<h3>Output</h3><p>${str}</p>`
}

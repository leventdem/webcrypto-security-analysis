const EventEmitter = require('events')

const debug = console.log

/**
 @typedef HashedPassphrase
 @type {Object}
 @property {string} storedHash - The hash of the derived key (format: hex string)
 @property {string} hashAlgo - The hash algo for the PBKDF2 and the final hash to store it
 @property {sring} salt - The salt used to derive the key (format: hex string)
 @property {Number} iterations - The iteration # used during key derivation
 */

/**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation
 * @returns {Promise<Uint8Array>}   A promise that contains the derived key
 */
const deriveBits = (passPhrase, salt, iterations, hash) => {
  // Always specify a strong salt
  if (iterations < 10000) { console.warn('The iteration number is less than 10000, increase it !') }

  return window.crypto.subtle.importKey(
    'raw',
    (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase,
    'PBKDF2',
    false,
    ['deriveBits', 'deriveKey']
  )
    .then(baseKey => {
      return window.crypto.subtle.deriveBits({
        name: 'PBKDF2',
        salt: salt || new Uint8Array([]),
        iterations: iterations || 100000,
        hash: hash || 'sha-256'
      }, baseKey, 128)
    })
    .then(derivedKey => new Uint8Array(derivedKey))
}

/**
 * Hash of a string or arrayBuffer
 *
 * @param {string | arrayBuffer} msg The message
 * @param {string} [type] The hash name (SHA-256 by default)
 * @returns {Promise}   A promise that contains the hash as a Uint8Array
 */
const hash256 = (msg, type = 'SHA-256') => {
  return window.crypto.subtle.digest(
    {
      name: 'SHA-256'
    },
    (typeof msg === 'string') ? Buffer.from(msg) : msg
  )
    .then(digest => new Uint8Array(digest))
}

/**
 * Derive a passphrase and return the object to store
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
const derivePassphrase = (passPhrase) => {
  let hashedPassphrase = {}
  const salt = window.crypto.getRandomValues(new Uint8Array(16))
  const iterations = 100000
  hashedPassphrase.salt = Buffer.from(salt).toString('hex')
  hashedPassphrase.iterations = iterations
  hashedPassphrase.hashAlgo = 'sha-256'
  return deriveBitsAndHash(passPhrase, salt, iterations)
    .then(hashedValue => {
      hashedPassphrase.storedHash = Buffer.from(hashedValue).toString('hex')
      return hashedPassphrase
    })
    .catch(err => console.log(err)
    )
}

/**
 * Derive the passphrase with PBKDF2 and hash the output with the given hash function
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {arrayBuffer} [salt] The salt
 * @param {Number} [iterations] The iterations number
 * @param {string} [hash] The hash function used for derivation and final hash computing
 * @returns {Promise<Uint8Array>}   A promise that contains the hashed derived key
 */
const deriveBitsAndHash = (passPhrase, salt, iterations, hash) => {
  return deriveBits(passPhrase, salt, iterations, hash)
    .then(hash256)
}

/**
 * Check a given passphrase by comparing it to the stored hash value (in HashedPassphrase object)
 *
 * @param {string} passphrase The passphrase
 * @param {HashedPassphrase} hashedPassphrase The HashedPassphrase object
 * @returns {Promise<HashedPassphrase>}   A promise that contains the derived key
 */
const checkPassphrase = (passPhrase, hashedPassphrase) => {
  const { salt, iterations, storedHash, hashAlgo } = hashedPassphrase
  return deriveBitsAndHash(passPhrase, Buffer.from(salt, 'hex'), iterations, hashAlgo)
    .then(hashedValue => {
      return Buffer.from(hashedValue).toString('hex') === storedHash
    })
}

/**
 * Decrypt data
 *
 * @param {ArrayBuffer} data - Data to decrypt
 * @param {ArrayBuffer} key - The AES key as raw data. 128 or 256 bits
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The decrypted buffer
 */
const decryptBuffer = (data, key, cipherContext) => {
  // TODO: test input params
  return window.crypto.subtle.decrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
}

/**
 * Encrypt data
 *
 * @param {ArrayBuffer} data - Data to encrypt
 * @param {ArrayBuffer} key - The AES CryptoKey
 * @param {Object} cipherContext - The AES cipher parameters
 * @param {ArrayBuffer} cipherContext.iv - The IV
 * @param {string} cipherContext.name - The encryption mode
 * @param {ArrayBuffer} [cipherContext.additionalData] - The non-secret authenticated data (only aes-gcm)
 * @param {ArrayBuffer} [cipherContext.counter] - The counter used for aes-ctr mode
 * @returns {ArrayBuffer} - The encrypted buffer
 */
const encryptBuffer = (data, key, cipherContext) => {
  return window.crypto.subtle.encrypt(cipherContext, key, data)
    .then(result => new Uint8Array(result))
}

class Crypto extends EventEmitter {
  /**
   * constructor
   */
  constructor (params = {}) {
    super()
    this.mode = params.mode || 'aes-gcm'
    this.keySize = params.keySize || 128
    this.IV = params.iv || null
    this.key = params.key || null
  }

  async init () {
  }

  /**
   * Generate an AES key based on the cipher mode and keysize
   * Cipher mode and key size are initialized at cipher AES instance creation.
   * @param {boolean} extractable - Specify if the generated key is extractable
   * @param {string} [mode] - The aes mode of the generated key
   * @param {Number} [keySize] - Specify if the generated key is extractable
   * @returns {CryptoKey} - The generated AES key.
   */
  genAESKey (extractable, mode, keySize) {
    return window.crypto.subtle.generateKey({
      name: mode || 'aes-gcm',
      length: keySize || 128
    }, extractable, ['decrypt', 'encrypt'])
  }

  /**
  * Transform a CryptoKey into a raw key
  *
  * @param {CryptoKey} key - The CryptoKey
  * @returns {arrayBuffer|Object} - The raw key or the key as a jwk format
  */
  exportKey (key = this._key, type = 'raw') {
    return window.crypto.subtle.exportKey(type, key)
      .then(key => {
        if (type === 'raw') return new Uint8Array(key)
        return key
      })
  }

  encrypt (key, data) {
    let context = {}
    let cipherContext = {}
    context.iv = window.crypto.getRandomValues(new Uint8Array(16))
    context.plaintext = Buffer.from(JSON.stringify(data))
    console.log('Encrypted message', context.plaintext)

    // Prepare cipher context, depends on cipher mode
    cipherContext.name = this.mode
    cipherContext.iv = context.iv
    return encryptBuffer(context.plaintext, key, cipherContext)
      .then(result => {
        return {
          ciphertext: Buffer.from(result).toString('hex'),
          iv: Buffer.from(context.iv).toString('hex')
        }
      })
  }

  decrypt (key, ciphertext) {
    let context = {}
    let cipherContext = {}
    context.ciphertext = ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, ('hex')) : ''
    // IV is 128 bits long === 16 bytes
    context.iv = ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, ('hex')) : ''
    // Prepare cipher context, depends on cipher mode
    cipherContext.name = this.mode
    cipherContext.iv = context.iv
    return decryptBuffer(context.ciphertext, key, cipherContext)
      .then(res => Buffer.from(res).toString())
  }

  /**
 * Generate a PBKDF2 derived key based on user given passPhrase
 *
 * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
 * @param {string} mode The mode of the derived key
 * @param {arrayBuffer} [salt] The passphrase length
 * @param {Number} [iteration] The iteration number
 * @returns {Promise}   A promise that contains the derived key
 */
  deriveKey (passPhrase, mode, salt, iterations) {
  // Always specify a strong salt
    if (iterations < 10000) { console.warn('The iteration number is less than 10000, increase it !') }

    return window.crypto.subtle.importKey(
      'raw',
      (typeof passPhrase === 'string') ? Buffer.from(passPhrase) : passPhrase,
      'PBKDF2',
      false,
      ['deriveBits', 'deriveKey']
    )
      .then(baseKey => {
        return window.crypto.subtle.deriveKey({
          name: 'PBKDF2',
          salt: salt || new Uint8Array([]),
          iterations: iterations || 100000,
          hash: 'sha-256'
        },
        baseKey,
        { name: mode || 'aes-gcm',
          length: 128
        },
        false,
        ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']
        )
      })
  }

  /**
  * Wrap the given key. All cipher context information of the wrapping key
  * have been initialized at object creation (default or parameter)
  * Return the wrappedKey and the associated iv.
  *
  * @param {CryptoKey} toBeWrappedKey - The key we want to wrap
  * @param {CryptoKey} wrappingKey - The wrappingKey
  * @param {string} [keySize] - The size of the key we want to wrap
  * @param {string} [exportType] - The export format of the toBeWrappedKey
  * @param {string} [mode] - The mode of the toBeWrappedKey
  * @returns {Uint8Array} - The wrapped key
  */
  wrapKey (toBeWrappedKey, wrappingKey, keySize, exportType, mode) {
    let iv = window.crypto.getRandomValues(new Uint8Array(mode === 'aes-gcm' ? 12 : 16))
    console.log([toBeWrappedKey, wrappingKey, iv])
    return window.crypto.subtle.wrapKey(exportType || 'raw',
      toBeWrappedKey,
      wrappingKey,
      {
        name: mode || 'aes-gcm',
        iv: iv,
        additionalData: Buffer.from('')
      })
      .then(wrappedKey => {
        return {
          encryptedMasterKey: (!exportType || exportType === 'raw') ? new Uint8Array(wrappedKey) : wrappedKey,
          iv: iv,
          keySize: keySize || 128
        }
      })
  }

  /**
  * Unwrap the given key. All cipher context information of the wrapping key
  * have been initialized at object creation (default or parameter)
  *
  * @param {Uint8array} wrappedKey - The wrapped key
  * @param {CryptoKey} wrappingKey - The wrappingKey
  * @param {Uint8Array} iv - The iv
  * @param {Uint8Array} keySize - The size of the unwrapped key (same as before wrapping)
  * @param {string} [importType] - The import format of the wrappedKey, must be the same as in wrap.
  * @param {string} [mode] - The mode of the wrappedKey, must be the same as in wrap.
  * @returns {CryptoKey} - The decrypted input
  */
  unwrapKey (wrappedKey, wrappringKey, iv, keySize, importType, mode) {
    return window.crypto.subtle.unwrapKey(importType || 'raw',
      wrappedKey,
      wrappringKey,
      {
        name: mode || 'aes-gcm',
        iv: iv,
        additionalData: Buffer.from('')
      },
      {
        name: mode || 'aes-gcm',
        length: keySize || 128
      },
      false,
      ['encrypt', 'decrypt'])
  }
}

module.exports = { Crypto, derivePassphrase, checkPassphrase }

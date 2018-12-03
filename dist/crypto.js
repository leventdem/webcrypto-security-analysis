'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

var _classCallCheck2 = require('babel-runtime/helpers/classCallCheck');

var _classCallCheck3 = _interopRequireDefault(_classCallCheck2);

var _createClass2 = require('babel-runtime/helpers/createClass');

var _createClass3 = _interopRequireDefault(_createClass2);

var _possibleConstructorReturn2 = require('babel-runtime/helpers/possibleConstructorReturn');

var _possibleConstructorReturn3 = _interopRequireDefault(_possibleConstructorReturn2);

var _inherits2 = require('babel-runtime/helpers/inherits');

var _inherits3 = _interopRequireDefault(_inherits2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var EventEmitter = require('events');

var debug = console.log;

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
var decryptBuffer = function decryptBuffer(data, key, cipherContext) {
  // TODO: test input params
  return window.crypto.subtle.decrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

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
var encryptBuffer = function encryptBuffer(data, key, cipherContext) {
  return window.crypto.subtle.encrypt(cipherContext, key, data).then(function (result) {
    return new Uint8Array(result);
  });
};

var Crypto = function (_EventEmitter) {
  (0, _inherits3.default)(Crypto, _EventEmitter);

  /**
   * constructor
   */
  function Crypto() {
    var params = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : {};
    (0, _classCallCheck3.default)(this, Crypto);

    var _this = (0, _possibleConstructorReturn3.default)(this, (Crypto.__proto__ || Object.getPrototypeOf(Crypto)).call(this));

    _this.mode = params.mode || 'aes-cbc';
    _this.keySize = params.keySize || 128;
    _this.IV = params.iv || null;
    _this.key = params.key || null;
    return _this;
  }

  (0, _createClass3.default)(Crypto, [{
    key: 'init',
    value: function () {
      var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee() {
        return _regenerator2.default.wrap(function _callee$(_context) {
          while (1) {
            switch (_context.prev = _context.next) {
              case 0:
              case 'end':
                return _context.stop();
            }
          }
        }, _callee, this);
      }));

      function init() {
        return _ref.apply(this, arguments);
      }

      return init;
    }()

    /**
     * Generate an AES key based on the cipher mode and keysize
     * Cipher mode and key size are initialized at cipher AES instance creation.
     * @param {boolean} extractable - Specify if the generated key is extractable
     * @returns {CryptoKey} - The generated AES key.
     */

  }, {
    key: 'genAESKey',
    value: function genAESKey(extractable) {
      return window.crypto.subtle.generateKey({
        name: this.mode || 'aes-cbc',
        length: this.keySize || 128
      }, extractable, ['decrypt', 'encrypt']);
    }

    /**
    * Transform a CryptoKey into a raw key
    *
    * @param {CryptoKey} key - The CryptoKey
    * @returns {arrayBuffer} - The raw key
    */

  }, {
    key: 'exportKeyRaw',
    value: function exportKeyRaw() {
      var key = arguments.length > 0 && arguments[0] !== undefined ? arguments[0] : this._key;
      var type = arguments.length > 1 && arguments[1] !== undefined ? arguments[1] : 'raw';

      return window.crypto.subtle.exportKey(type, key).then(function (key) {
        return new Uint8Array(key);
      });
    }
  }, {
    key: 'encrypt',
    value: function encrypt(key, data) {
      var context = {};
      var cipherContext = {};
      context.iv = window.crypto.getRandomValues(new Uint8Array(16));
      context.plaintext = Buffer.from(JSON.stringify(data));
      console.log('Encrypted message', context.plaintext);

      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode;
      cipherContext.iv = context.iv;
      return encryptBuffer(context.plaintext, key, cipherContext).then(function (result) {
        return {
          ciphertext: Buffer.from(result).toString('hex'),
          iv: Buffer.from(context.iv).toString('hex')
        };
      });
    }
  }, {
    key: 'decrypt',
    value: function decrypt(key, ciphertext) {
      var context = {};
      var cipherContext = {};
      context.ciphertext = ciphertext.hasOwnProperty('ciphertext') ? Buffer.from(ciphertext.ciphertext, 'hex') : '';
      // IV is 128 bits long === 16 bytes
      context.iv = ciphertext.hasOwnProperty('iv') ? Buffer.from(ciphertext.iv, 'hex') : '';
      // Prepare cipher context, depends on cipher mode
      cipherContext.name = this.mode;
      cipherContext.iv = context.iv;
      return decryptBuffer(context.ciphertext, key, cipherContext).then(function (res) {
        return Buffer.from(res).toString();
      });
    }

    /**
    * Generate a PBKDF2 derived key based on user given passPhrase
    *
    * @param {string | arrayBuffer} passPhrase The passphrase that is used to derive the key
    * @param {arrayBuffer} [salt] The passphrase length
    * @returns {Promise}   A promise that contains the derived key
    */

  }, {
    key: 'deriveKey',
    value: function deriveKey(passPhrase, salt) {
      var iterations = arguments.length > 2 && arguments[2] !== undefined ? arguments[2] : 10000;
      var mode = arguments[3];

      // Always specify a strong salt
      if (iterations < 10000) {
        console.warn('The iteration number is less than 10000, increase it !');
      }

      return window.crypto.subtle.importKey('raw', typeof passPhrase === 'string' ? Buffer.from(passPhrase) : passPhrase, 'PBKDF2', false, ['deriveBits', 'deriveKey']).then(function (baseKey) {
        return window.crypto.subtle.deriveKey({
          name: 'PBKDF2',
          salt: salt || new Uint8Array([]),
          iterations: iterations,
          hash: 'sha-256'
        }, baseKey, { name: mode || 'aes-gcm',
          length: 128
        }, false, ['encrypt', 'decrypt', 'wrapKey', 'unwrapKey']);
      });
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

  }, {
    key: 'wrapKey',
    value: function wrapKey(toBeWrappedKey, wrappingKey, keySize, exportType, mode) {
      console.log('crypto1');
      var iv = window.crypto.getRandomValues(new Uint8Array(mode === 'aes-gcm' ? 12 : 16));
      console.log([toBeWrappedKey, wrappingKey, iv]);
      return window.crypto.subtle.wrapKey(exportType || 'raw', toBeWrappedKey, wrappingKey, {
        name: mode || 'aes-gcm',
        iv: iv,
        additionalData: Buffer.from('')
        // additionalData: toArray('')
      }).then(function (wrappedKey) {
        console.log('crypto2');

        console.log(new Uint8Array(wrappedKey));
        console.log(new Uint8Array(wrappedKey).toString());

        return {
          encryptedMasterKey: !exportType || exportType === 'raw' ? new Uint8Array(wrappedKey) : wrappedKey,
          iv: iv,
          keySize: keySize || 128
        };
      });
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

  }, {
    key: 'unwrapKey',
    value: function unwrapKey(wrappedKey, wrappringKey, iv, keySize, importType, mode) {
      return window.crypto.subtle.unwrapKey(importType || 'raw', wrappedKey, wrappringKey, {
        name: mode || 'aes-gcm',
        iv: iv,
        additionalData: Buffer.from('')
      }, {
        name: mode || 'aes-gcm',
        length: keySize || 128
      }, false, ['encrypt', 'decrypt']);
    }
  }]);
  return Crypto;
}(EventEmitter);

/**
 * Convert ascii to ArrayBufffer
 * ex : "bonjour" -> Uint8Array [ 98, 111, 110, 106, 111, 117, 114 ]
 *
 * @param {String} str
 * @returns {ArrayBuffer}
 */


var toArray = function toArray(str) {
  if (typeof str !== 'string') {
    throw new Error('toArray accepts only string');
  }
  var chars = [];
  for (var i = 0; i < str.length; ++i) {
    chars.push(str.charCodeAt(i));
  }
  return new Uint8Array(chars);
};

module.exports = Crypto;
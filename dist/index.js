'use strict';

var _regenerator = require('babel-runtime/regenerator');

var _regenerator2 = _interopRequireDefault(_regenerator);

var _asyncToGenerator2 = require('babel-runtime/helpers/asyncToGenerator');

var _asyncToGenerator3 = _interopRequireDefault(_asyncToGenerator2);

function _interopRequireDefault(obj) { return obj && obj.__esModule ? obj : { default: obj }; }

var Crypto = require('./crypto');

var AESInstance = null;
var cryptoKeyAES = null;

var debug = function debug(str) {
  if (process.env.NODE_ENV !== 'production') console.log(str);
};

document.addEventListener('DOMContentLoaded', function () {
  var el = document.getElementById('generateAESKeyTrue');
  if (el) {
    el.addEventListener('click', function (e) {
      console.log('To disable debug print, remove --mode=development from webpack command in package.json');
      generateAESKey(true);
    });
  }
  el = document.getElementById('generateAESKeyFalse');
  if (el) {
    el.addEventListener('click', function (e) {
      console.log('To disable debug print, remove --mode=development from webpack command in package.json');
      generateAESKey(false);
    });
  }
  el = document.getElementById('exportAESKey');
  if (el) {
    el.addEventListener('click', function (e) {
      exportAESKey();
    });
  }
  el = document.getElementById('encryptDecrypt');
  if (el) {
    el.addEventListener('click', function (e) {
      encryptDecrypt();
    });
  }
  el = document.getElementById('deriveKey');
  if (el) {
    el.addEventListener('click', function (e) {
      deriveKey();
    });
  }
});

var generateAESKey = function () {
  var _ref = (0, _asyncToGenerator3.default)( /*#__PURE__*/_regenerator2.default.mark(function _callee(extractable) {
    return _regenerator2.default.wrap(function _callee$(_context) {
      while (1) {
        switch (_context.prev = _context.next) {
          case 0:
            debug('generateAESKey');

            AESInstance = new Crypto({ mode: 'aes-gcm' });
            AESInstance.genAESKey(extractable).then(function (AESCryptoKey) {
              // We print the key
              cryptoKeyAES = AESCryptoKey;
              console.log(AESCryptoKey);

              var el = document.getElementById('step1KeyGeneration');
              el.innerHTML = fillElement('Now, key successfully generated, open the developer console, and check the cryptokey. Yous must obtain something like this : \n  \n CryptoKey { type: "secret", extractable: ' + extractable + ', algorithm: {\u2026}, usages:  }');
            }).catch(function (err) {
              console.log(err);
            });

          case 3:
          case 'end':
            return _context.stop();
        }
      }
    }, _callee, undefined);
  }));

  return function generateAESKey(_x) {
    return _ref.apply(this, arguments);
  };
}();

var exportAESKey = function exportAESKey() {
  var messageToPrint = null;
  var el = document.getElementById('step2KeyExport');
  AESInstance.exportKeyRaw(cryptoKeyAES).then(function (exportedKey) {
    console.log(exportedKey);
    messageToPrint = 'Successfully exported. Now try again, relaod the page but choose to  generate the AES key with the extractable property set to false.';
    el.innerHTML = fillElement('' + messageToPrint);
  }).catch(function (err) {
    console.log(err);
    messageToPrint = err;
    el.innerHTML = fillElement('You generate a non extractable AES key, the export is not authorized. <br/>' + messageToPrint);
  });
};

var encryptDecrypt = function encryptDecrypt() {
  var data = { username: 'bob' };
  console.log('Initial message: ' + JSON.stringify(data));
  AESInstance.encrypt(cryptoKeyAES, data).then(function (ciphertext) {
    // console.log(ciphertext.ciphertext)
    var el = document.getElementById('step3Encrypt');
    el.innerHTML = fillElement('\n  No matter if the generated AES key is extractable or not, you can encrypt/dectypt data using a black box. <br/>\n  Initial message : ' + JSON.stringify(data) + '<br/>\n  Encrypted msg : ' + ciphertext.ciphertext.slice(0, 10) + '...');
    return AESInstance.decrypt(cryptoKeyAES, ciphertext);
  }).then(function (plaintext) {
    console.log('Decrypted message', plaintext);
    var el = document.getElementById('step3Decrypt');
    el.innerHTML = '<p>\n    Decrypted message : ' + plaintext + '</p>';
  }).catch(function (err) {
    return console.log(err);
  });
};

var deriveKey = function deriveKey() {
  var messageToPrint = null;
  var el = document.getElementById('step4Derive');
  var passPhrase = 'hello';
  var iterations = 100000;
  // const mode = 'aes-cbc'
  var mode = 'aes-gcm';
  var type = 'raw';
  return AESInstance.deriveKey(passPhrase, mode, Buffer.from('theSalt'), iterations).then(function (wrappingKey) {
    console.log('Salt : ', Buffer.from('theSalt'));
    console.log('Iterations : ', iterations);
    console.log('Wrapping key : ', wrappingKey);
    el.innerHTML = fillElement('Passphrase derivation succesfully done. ');
    AESInstance.wrapKey(cryptoKeyAES, wrappingKey, 128, type, mode).then(function (wrappedKey) {
      console.log('Wrapped key', wrappedKey);
      var el = document.getElementById('step4WrapSuccess');
      el.innerHTML = '<p>\n          Wrapping of AES key : ok</p>';
      AESInstance.unwrapKey(wrappedKey.encryptedMasterKey, wrappingKey, wrappedKey.iv, 128, type, mode).then(function (unwrappedKey) {
        console.log('Unwrapped key', unwrappedKey);
      }).catch(function (err) {
        return console.log(err);
      });
    }).catch(function (err) {
      console.log(err);
      var el = document.getElementById('step4WrapFail');
      el.innerHTML = '<p>\n          You generate a non extractable AES key, the wrap opertion is not authorized.<br/>\n          Wrapping of AES key : fail</p>';
    });
  }).catch(function (err) {
    return console.log(err);
  }).catch(function (err) {
    return console.log(err);
  });
};

var fillElement = function fillElement(str) {
  return '<h3>Output</h3><p>' + str + '</p>';
};
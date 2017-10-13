(function(e, a) { for(var i in a) e[i] = a[i]; }(this, /******/ (function(modules) { // webpackBootstrap
/******/ 	// The module cache
/******/ 	var installedModules = {};
/******/
/******/ 	// The require function
/******/ 	function __webpack_require__(moduleId) {
/******/
/******/ 		// Check if module is in cache
/******/ 		if(installedModules[moduleId]) {
/******/ 			return installedModules[moduleId].exports;
/******/ 		}
/******/ 		// Create a new module (and put it into the cache)
/******/ 		var module = installedModules[moduleId] = {
/******/ 			i: moduleId,
/******/ 			l: false,
/******/ 			exports: {}
/******/ 		};
/******/
/******/ 		// Execute the module function
/******/ 		modules[moduleId].call(module.exports, module, module.exports, __webpack_require__);
/******/
/******/ 		// Flag the module as loaded
/******/ 		module.l = true;
/******/
/******/ 		// Return the exports of the module
/******/ 		return module.exports;
/******/ 	}
/******/
/******/
/******/ 	// expose the modules object (__webpack_modules__)
/******/ 	__webpack_require__.m = modules;
/******/
/******/ 	// expose the module cache
/******/ 	__webpack_require__.c = installedModules;
/******/
/******/ 	// define getter function for harmony exports
/******/ 	__webpack_require__.d = function(exports, name, getter) {
/******/ 		if(!__webpack_require__.o(exports, name)) {
/******/ 			Object.defineProperty(exports, name, {
/******/ 				configurable: false,
/******/ 				enumerable: true,
/******/ 				get: getter
/******/ 			});
/******/ 		}
/******/ 	};
/******/
/******/ 	// getDefaultExport function for compatibility with non-harmony modules
/******/ 	__webpack_require__.n = function(module) {
/******/ 		var getter = module && module.__esModule ?
/******/ 			function getDefault() { return module['default']; } :
/******/ 			function getModuleExports() { return module; };
/******/ 		__webpack_require__.d(getter, 'a', getter);
/******/ 		return getter;
/******/ 	};
/******/
/******/ 	// Object.prototype.hasOwnProperty.call
/******/ 	__webpack_require__.o = function(object, property) { return Object.prototype.hasOwnProperty.call(object, property); };
/******/
/******/ 	// __webpack_public_path__
/******/ 	__webpack_require__.p = "";
/******/
/******/ 	// Load entry module and return exports
/******/ 	return __webpack_require__(__webpack_require__.s = 0);
/******/ })
/************************************************************************/
/******/ ([
/* 0 */
/***/ (function(module, __webpack_exports__, __webpack_require__) {

"use strict";
Object.defineProperty(__webpack_exports__, "__esModule", { value: true });
/* harmony import */ var __WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__ = __webpack_require__(1);
/* harmony import */ var __WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js___default = __webpack_require__.n(__WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__);


const { classes: Cc, interfaces: Ci, utils: Cu } = Components;
Cu.import("resource://gre/modules/Services.jsm");
Cu.import("resource://gre/modules/XPCOMUtils.jsm");

const { TelemetryController } = Cu.import("resource://gre/modules/TelemetryController.jsm", null);
const { generateUUID } = Cc["@mozilla.org/uuid-generator;1"].getService(Ci.nsIUUIDGenerator);



// The public key used for encryption
const PUBLIC_KEY = __webpack_require__(7);

// The encryption key ID from the server
const ENCRYPTION_KEY_ID = "pioneer-20170905";

const PIONEER_ID_PREF = "extensions.pioneer.cachedClientID";

// Make crypto available and make jose use it.
Components.utils.importGlobalProperties(["crypto"]);
Object(__WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__["setCrypto"])(crypto);


class PioneerUtils {
  constructor(config) {
    this.config = config;
    this.encrypter = null;
  }

  setupEncrypter() {
    if (this.encrypter === null) {
      const rsa_key = __WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__["Jose"].Utils.importRsaPublicKey(PUBLIC_KEY, "RSA-OAEP");
      const cryptographer = new __WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__["Jose"].WebCryptographer();
      this.encrypter = new __WEBPACK_IMPORTED_MODULE_0_jose_jwe_jws_dist_jose_commonjs_js__["JoseJWE"].Encrypter(cryptographer, rsa_key);
    }
  }

  getPioneerId() {
    let id = Services.prefs.getCharPref(PIONEER_ID_PREF, "");

    if (!id) {
      // generateUUID adds leading and trailing "{" and "}". strip them off.
      id = generateUUID().toString().slice(1, -1);
      Services.prefs.setCharPref(PIONEER_ID_PREF, id);
    }

    return id;
  }

  async encryptData(data) {
    this.setupEncrypter();
    return await this.encrypter.encrypt(data);
  }

  async submitEncryptedPing(data) {
    const payload = {
      encryptedData: await this.encryptData(JSON.stringify(data)),
      encryptionKeyId: ENCRYPTION_KEY_ID,
      pioneerId: this.getPioneerId(),
      studyName: this.config.studyName,
      studyVersion: this.config.studyVersion,
    };

    const telOptions = {
      addClientId: true,
      addEnvironment: true,
    };

    return TelemetryController.submitExternalPing("pioneer-study", payload, telOptions);
  }
}

this.PioneerUtils = PioneerUtils;
this.EXPORTED_SYMBOLS = ["PioneerUtils"];


/***/ }),
/* 1 */
/***/ (function(module, exports, __webpack_require__) {

/* WEBPACK VAR INJECTION */(function(Buffer) {/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

var Jose = {};

/**
 * Javascript Object Signing and Encryption library.
 *
 * @author Alok Menghrajani <alok@squareup.com>
 */

/**
 * Initializes a JoseJWE object.
 */
var JoseJWE = {};

/**
 * Initializes a JoseJWS object.
 */
var JoseJWS = {};

/**
 * Set crypto provider to use (window.crypto, node-webcrypto-ossl, node-webcrypto-pkcs11 etc.).
 */
exports.setCrypto = function (cp) {
  Jose.crypto = cp;
};

/**
 * Default to the global "crypto" variable
 */
if (typeof(crypto) !== 'undefined') {
  exports.setCrypto(crypto);
}

/**
 * Use Node versions of atob, btoa functions outside the browser
 */
if (typeof atob !== "function") {
  atob = function (str) {
    return new Buffer(str, 'base64').toString('binary');
  };
}

if (typeof btoa !== "function") {
  btoa = function (str) {
    var buffer;
    if (str instanceof Buffer) {
      buffer = str;
    } else {
      buffer = new Buffer(str.toString(), 'binary');
    }
    return buffer.toString('base64');
  };
}

/**
 * Checks if we have all the required APIs.
 *
 * It might make sense to take a Cryptographer and delegate some of the checks
 * to the cryptographer. I however wanted to keep things simple, so I put all
 * the checks here for now.
 *
 * This list is generated manually and needs to be kept up-to-date.
 *
 * Casual testing shows that:
 * - things work in Chrome 40.0.2214.115
 * - things work in Firefox 35.0.1
 * - Safari 7.1.3 doesn't support JWK keys.
 * - Internet Explorer doesn't support Promises.
 *
 * Note: We don't check if the browser supports specific crypto operations.
 *       I.e. it's possible for this function to return true, but encryption or
 *       decryption to subsequently fail because the browser does not support a
 *       given encryption, decryption, key wrapping, key unwrapping or hmac
 *       operation.
 *
 * @return bool
 */
Jose.caniuse = function() {
  var r = true;

  // Promises/A+ (https://promisesaplus.com/)
  r = r && (typeof Promise == "function");
  r = r && (typeof Promise.reject == "function");
  r = r && (typeof Promise.prototype.then == "function");
  r = r && (typeof Promise.all == "function");

  // Crypto (http://www.w3.org/TR/WebCryptoAPI/)
  r = r && (typeof Jose.crypto == "object");
  r = r && (typeof Jose.crypto.subtle == "object");
  r = r && (typeof Jose.crypto.getRandomValues == "function");
  r = r && (typeof Jose.crypto.subtle.importKey == "function");
  r = r && (typeof Jose.crypto.subtle.generateKey == "function");
  r = r && (typeof Jose.crypto.subtle.exportKey == "function");
  r = r && (typeof Jose.crypto.subtle.wrapKey == "function");
  r = r && (typeof Jose.crypto.subtle.unwrapKey == "function");
  r = r && (typeof Jose.crypto.subtle.encrypt == "function");
  r = r && (typeof Jose.crypto.subtle.decrypt == "function");
  r = r && (typeof Jose.crypto.subtle.sign == "function");

  // ArrayBuffer (http://people.mozilla.org/~jorendorff/es6-draft.html#sec-arraybuffer-constructor)
  r = r && (typeof ArrayBuffer == "function");
  r = r && (typeof Uint8Array == "function" || typeof Uint8Array == "object"); // Safari uses "object"
  r = r && (typeof Uint32Array == "function" || typeof Uint32Array == "object"); // Safari uses "object"
  // skipping Uint32Array.prototype.buffer because https://people.mozilla.org/~jorendorff/es6-draft.html#sec-properties-of-the-%typedarrayprototype%-object

  // JSON (http://www.ecma-international.org/ecma-262/5.1/#sec-15.12.3)
  r = r && (typeof JSON == "object");
  r = r && (typeof JSON.parse == "function");
  r = r && (typeof JSON.stringify == "function");

  // Base64 (http://www.w3.org/TR/html5/webappapis.html#dom-windowbase64-atob)
  r = r && (typeof atob == "function");
  r = r && (typeof btoa == "function");

  // skipping Array functions (map, join, push, length, etc.)
  // skipping String functions (split, charCodeAt, fromCharCode, replace, etc.)
  // skipping regexp.test and parseInt

  return r;
};

/**
 * Feel free to override this function.
 */
Jose.assert = function(expr, msg) {
  if (!expr) {
    throw new Error(msg);
  }
};

exports.Jose = Jose;
exports.JoseJWE = JoseJWE;
exports.JoseJWS = JoseJWS;
/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * The WebCryptographer uses http://www.w3.org/TR/WebCryptoAPI/ to perform
 * various crypto operations. In theory, this should help build the library with
 * different underlying crypto APIs. I'm however unclear if we'll run into code
 * duplication or callback vs Promise based API issues.
 */
var WebCryptographer = function() {
  this.setKeyEncryptionAlgorithm("RSA-OAEP");
  this.setContentEncryptionAlgorithm("A256GCM");
  this.setContentSignAlgorithm("RS256");
};

Jose.WebCryptographer = WebCryptographer;

/**
 * Overrides the default key encryption algorithm
 * @param alg  string
 */
WebCryptographer.prototype.setKeyEncryptionAlgorithm = function(alg) {
  this.key_encryption = getCryptoConfig(alg);
};

WebCryptographer.prototype.getKeyEncryptionAlgorithm = function() {
  return this.key_encryption.jwe_name;
};

/**
 * Overrides the default content encryption algorithm
 * @param alg  string
 */
WebCryptographer.prototype.setContentEncryptionAlgorithm = function(alg) {
  this.content_encryption = getCryptoConfig(alg);
};

WebCryptographer.prototype.getContentEncryptionAlgorithm = function() {
  return this.content_encryption.jwe_name;
};

/**
 * Overrides the default content sign algorithm
 * @param alg  string
 */
WebCryptographer.prototype.setContentSignAlgorithm = function(alg) {
  this.content_sign = getSignConfig(alg);
};

WebCryptographer.prototype.getContentSignAlgorithm = function() {
  return this.content_sign.jwa_name;
};

/**
 * Generates an IV.
 * This function mainly exists so that it can be mocked for testing purpose.
 *
 * @return Uint8Array with random bytes
 */
WebCryptographer.prototype.createIV = function() {
  var iv = new Uint8Array(new Array(this.content_encryption.iv_bytes));
  return Jose.crypto.getRandomValues(iv);
};

/**
 * Creates a random content encryption key.
 * This function mainly exists so that it can be mocked for testing purpose.
 *
 * @return Promise<CryptoKey>
 */
WebCryptographer.prototype.createCek = function() {
  var hack = getCekWorkaround(this.content_encryption);
  return Jose.crypto.subtle.generateKey(hack.id, true, hack.enc_op);
};

WebCryptographer.prototype.wrapCek = function(cek, key) {
  return Jose.crypto.subtle.wrapKey("raw", cek, key, this.key_encryption.id);
};

WebCryptographer.prototype.unwrapCek = function(cek, key) {
  var hack = getCekWorkaround(this.content_encryption);
  var extractable = (this.content_encryption.specific_cek_bytes > 0);
  var key_encryption = this.key_encryption.id;

  return Jose.crypto.subtle.unwrapKey("raw", cek, key, key_encryption, hack.id, extractable, hack.dec_op);
};

/**
 * Returns algorithm and operation needed to create a CEK.
 *
 * In some cases, e.g. A128CBC-HS256, the CEK gets split into two keys. The Web
 * Crypto API does not allow us to generate an arbitrary number of bytes and
 * then create a CryptoKey without any associated algorithm. We therefore piggy
 * back on AES-CBS and HMAC which allows the creation of CEKs of size 16, 32, 64
 * and 128 bytes.
 */
var getCekWorkaround = function(alg) {
  var len = alg.specific_cek_bytes;
  if (len) {
    if (len == 16) {
      return {id: {name: "AES-CBC", length: 128}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
    } else if (len == 32) {
      return {id: {name: "AES-CBC", length: 256}, enc_op: ["encrypt"], dec_op: ["decrypt"]};
    } else if (len == 64) {
      return {id: {name: "HMAC", hash: {name: "SHA-256"}}, enc_op: ["sign"], dec_op: ["verify"]};
    } else if (len == 128) {
      return {id: {name: "HMAC", hash: {name: "SHA-384"}}, enc_op: ["sign"], dec_op: ["verify"]};
    } else {
      Jose.assert(false, "getCekWorkaround: invalid len");
    }
  }
  return {id: alg.id, enc_op: ["encrypt"], dec_op: ["decrypt"]};
};

/**
 * Encrypts plain_text with cek.
 *
 * @param iv          Uint8Array
 * @param aad         Uint8Array
 * @param cek_promise Promise<CryptoKey>
 * @param plain_text  Uint8Array
 * @return Promise<json>
 */
WebCryptographer.prototype.encrypt = function(iv, aad, cek_promise, plain_text) {
  var config = this.content_encryption;
  if (iv.length != config.iv_bytes) {
    return Promise.reject(Error("invalid IV length"));
  }
  if (config.auth.aead) {
    var tag_bytes = config.auth.tag_bytes;

    var enc = {
      name: config.id.name,
      iv: iv,
      additionalData: aad,
      tagLength: tag_bytes * 8
    };

    return cek_promise.then(function(cek) {
      return Jose.crypto.subtle.encrypt(enc, cek, plain_text).then(function(cipher_text) {
        var offset = cipher_text.byteLength - tag_bytes;
        return {
          cipher: cipher_text.slice(0, offset),
          tag: cipher_text.slice(offset)
        };
      });
    });
  } else {
    var keys = splitKey(config, cek_promise, ["encrypt"]);
    var mac_key_promise = keys[0];
    var enc_key_promise = keys[1];

    // Encrypt the plain text
    var cipher_text_promise = enc_key_promise.then(function(enc_key) {
      var enc = {
        name: config.id.name,
        iv: iv
      };
      return Jose.crypto.subtle.encrypt(enc, enc_key, plain_text);
    });

    // compute MAC
    var mac_promise = cipher_text_promise.then(function(cipher_text) {
      return truncatedMac(
        config,
        mac_key_promise,
        aad,
        iv,
        cipher_text);
    });

    return Promise.all([cipher_text_promise, mac_promise]).then(function(all) {
      var cipher_text = all[0];
      var mac = all[1];
      return {
        cipher: cipher_text,
        tag: mac
      };
    });
  }
};

/**
 * Decrypts cipher_text with cek. Validates the tag.
 *
 * @param cek_promise    Promise<CryptoKey>
 * @param aad protected header
 * @param iv IV
 * @param cipher_text text to be decrypted
 * @param tag to be verified
 * @return Promise<string>
 */
WebCryptographer.prototype.decrypt = function(cek_promise, aad, iv, cipher_text, tag) {
  /**
   * Compares two Uint8Arrays in constant time.
   *
   * @return Promise<void>
   */
  var compare = function(config, mac_key_promise, arr1, arr2) {
    Jose.assert(arr1 instanceof Uint8Array, "compare: invalid input");
    Jose.assert(arr2 instanceof Uint8Array, "compare: invalid input");

    return mac_key_promise.then(function(mac_key) {
      var hash1 = Jose.crypto.subtle.sign(config.auth.id, mac_key, arr1);
      var hash2 = Jose.crypto.subtle.sign(config.auth.id, mac_key, arr2);
      return Promise.all([hash1, hash2]).then(function(all) {
        var hash1 = new Uint8Array(all[0]);
        var hash2 = new Uint8Array(all[1]);
        if (hash1.length != hash2.length) {
          throw new Error("compare failed");
        }
        for (var i = 0; i < hash1.length; i++) {
          if (hash1[i] != hash2[i]) {
            throw new Error("compare failed");
          }
        }
        return Promise.resolve(null);
      });
    });
  };

  if (iv.length != this.content_encryption.iv_bytes) {
    return Promise.reject(Error("decryptCiphertext: invalid IV"));
  }

  var config = this.content_encryption;
  if (config.auth.aead) {
    var dec = {
      name: config.id.name,
      iv: iv,
      additionalData: aad,
      tagLength: config.auth.tag_bytes * 8
    };

    return cek_promise.then(function(cek) {
      var buf = Utils.arrayBufferConcat(cipher_text, tag);
      return Jose.crypto.subtle.decrypt(dec, cek, buf);
    });
  } else {
    var keys = splitKey(config, cek_promise, ["decrypt"]);
    var mac_key_promise = keys[0];
    var enc_key_promise = keys[1];

    // Validate the MAC
    var mac_promise = truncatedMac(
      config,
      mac_key_promise,
      aad,
      iv,
      cipher_text);

    return Promise.all([enc_key_promise, mac_promise]).then(function(all) {
      var enc_key = all[0];
      var mac = all[1];

      return compare(config, mac_key_promise, new Uint8Array(mac), tag).then(function() {
        var dec = {
          name: config.id.name,
          iv: iv
        };
        return Jose.crypto.subtle.decrypt(dec, enc_key, cipher_text);
      }).catch(function(err) {
        return Promise.reject(Error("decryptCiphertext: MAC failed."));
      });
    });
  }
};

/**
 * Signs plain_text.
 *
 * @param aad         json
 * @param payload     String or json
 * @param key_promise Promise<CryptoKey>
 * @return Promise<ArrayBuffer>
 */
WebCryptographer.prototype.sign = function(aad, payload, key_promise) {
  var config = this.content_sign;

  if (aad.alg) {
    config = getSignConfig(aad.alg);
  }

  // Encrypt the plain text
  return key_promise.then(function(key) {
    return Jose.crypto.subtle.sign(config.id, key, Utils.arrayFromString(Utils.Base64Url.encode(JSON.stringify(aad)) + '.' + Utils.Base64Url.encodeArray(payload)));
  });
};

/**
 * Verify JWS.
 *
 * @param payload     Base64Url encoded payload
 * @param aad         String Base64Url encoded JSON representation of the protected JWS header
 * @param signature   Uint8Array containing the signature
 * @param key_promise Promise<CryptoKey>
 * @param key_id      value of the kid JoseHeader, it'll be passed as part of the result to the returned promise
 * @return Promise<json>
 */
WebCryptographer.prototype.verify = function(aad, payload, signature, key_promise, key_id) {
  var config = this.content_sign;

  return key_promise.then(function(key) {
    config = getSignConfig(getJwaNameForSignKey(key));
    return Jose.crypto.subtle.verify(config.id, key, signature, Utils.arrayFromString(aad + "." + payload)).then(function(res) {
      return {kid: key_id, verified: res};
    });
  });
};

Jose.WebCryptographer.keyId = function(rsa_key) {
  return Utils.sha256(rsa_key.n + "+" + rsa_key.d);
};

/**
 * Splits a CEK into two pieces: a MAC key and an ENC key.
 *
 * This code is structured around the fact that the crypto API does not provide
 * a way to validate truncated MACs. The MAC key is therefore always imported to
 * sign data.
 *
 * @param config (used for key lengths & algorithms)
 * @param cek_promise Promise<CryptoKey>  CEK key to split
 * @param purpose Array<String> usages of the imported key
 * @return [Promise<mac key>, Promise<enc key>]
 */
var splitKey = function(config, cek_promise, purpose) {
  // We need to split the CEK key into a MAC and ENC keys
  var cek_bytes_promise = cek_promise.then(function(cek) {
    return Jose.crypto.subtle.exportKey("raw", cek);
  });
  var mac_key_promise = cek_bytes_promise.then(function(cek_bytes) {
    if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
      return Promise.reject(Error("encryptPlainText: incorrect cek length"));
    }
    var bytes = cek_bytes.slice(0, config.auth.key_bytes);
    return Jose.crypto.subtle.importKey("raw", bytes, config.auth.id, false, ["sign"]);
  });
  var enc_key_promise = cek_bytes_promise.then(function(cek_bytes) {
    if (cek_bytes.byteLength * 8 != config.id.length + config.auth.key_bytes * 8) {
      return Promise.reject(Error("encryptPlainText: incorrect cek length"));
    }
    var bytes = cek_bytes.slice(config.auth.key_bytes);
    return Jose.crypto.subtle.importKey("raw", bytes, config.id, false, purpose);
  });
  return [mac_key_promise, enc_key_promise];
};

/**
 * Converts the Jose web algorithms into data which is
 * useful for the Web Crypto API.
 *
 * length = in bits
 * bytes = in bytes
 */
var getCryptoConfig = function(alg) {
  switch (alg) {
    // Key encryption
    case "RSA-OAEP":
      return {
        jwe_name: "RSA-OAEP",
        id: {name: "RSA-OAEP", hash: {name: "SHA-1"}}
      };
    case "RSA-OAEP-256":
      return {
        jwe_name: "RSA-OAEP-256",
        id: {name: "RSA-OAEP", hash: {name: "SHA-256"}}
      };
    case "A128KW":
      return {
        jwe_name: "A128KW",
        id: {name: "AES-KW", length: 128}
      };
    case "A256KW":
      return {
        jwe_name: "A256KW",
        id: {name: "AES-KW", length: 256}
      };
    case "dir":
      return {
        jwe_name: "dir"
      };

    // Content encryption
    case "A128CBC-HS256":
      return {
        jwe_name: "A128CBC-HS256",
        id: {name: "AES-CBC", length: 128},
        iv_bytes: 16,
        specific_cek_bytes: 32,
        auth: {
          key_bytes: 16,
          id: {name: "HMAC", hash: {name: "SHA-256"}},
          truncated_bytes: 16
        }
      };
    case "A256CBC-HS512":
      return {
        jwe_name: "A256CBC-HS512",
        id: {name: "AES-CBC", length: 256},
        iv_bytes: 16,
        specific_cek_bytes: 64,
        auth: {
          key_bytes: 32,
          id: {name: "HMAC", hash: {name: "SHA-512"}},
          truncated_bytes: 32
        }
      };
    case "A128GCM":
      return {
        jwe_name: "A128GCM",
        id: {name: "AES-GCM", length: 128},
        iv_bytes: 12,
        auth: {
          aead: true,
          tag_bytes: 16
        }
      };
    case "A256GCM":
      return {
        jwe_name: "A256GCM",
        id: {name: "AES-GCM", length: 256},
        iv_bytes: 12,
        auth: {
          aead: true,
          tag_bytes: 16
        }
      };
    default:
      throw Error("unsupported algorithm: " + alg);
  }
};

/**
 * Computes a truncated MAC.
 *
 * @param config              configuration
 * @param mac_key_promise     Promise<CryptoKey>  mac key
 * @param aad                 Uint8Array
 * @param iv                  Uint8Array
 * @param cipher_text         Uint8Array
 * @return Promise<buffer>    truncated MAC
 */
var truncatedMac = function(config, mac_key_promise, aad, iv, cipher_text) {
  return mac_key_promise.then(function(mac_key) {
    var al = new Uint8Array(Utils.arrayFromInt32(aad.length * 8));
    var al_full = new Uint8Array(8);
    al_full.set(al, 4);
    var buf = Utils.arrayBufferConcat(aad, iv, cipher_text, al_full);
    return Jose.crypto.subtle.sign(config.auth.id, mac_key, buf).then(function(bytes) {
      return bytes.slice(0, config.auth.truncated_bytes);
    });
  });
};

/**
 * Converts the Jose web algorithms into data which is
 * useful for the Web Crypto API.
 */
var getSignConfig = function(alg) {

  switch (alg) {
    case "RS256":
      return {
        jwa_name: "RS256",
        id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-256"}}
      };
    case "RS384":
      return {
        jwa_name: "RS384",
        id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-384"}}
      };
    case "RS512":
      return {
        jwa_name: "RS512",
        id: {name: "RSASSA-PKCS1-v1_5", hash: {name: "SHA-512"}}
      };
    case "PS256":
      return {
        jwa_name: "PS256",
        id: {name: "RSA-PSS", hash: {name: "SHA-256"}, saltLength: 20}
      };
    case "PS384":
      return {
        jwa_name: "PS384",
        id: {name: "RSA-PSS", hash: {name: "SHA-384"}, saltLength: 20}
      };
    case "PS512":
      return {
        jwa_name: "PS512",
        id: {name: "RSA-PSS", hash: {name: "SHA-512"}, saltLength: 20}
      };
    case "HS256":
      return {
        jwa_name: "HS256",
        id: {name: "HMAC", hash: {name: "SHA-256"}}
      };
    case "HS384":
      return {
        jwa_name: "HS384",
        id: {name: "HMAC", hash: {name: "SHA-384"}}
      };
    case "HS512":
      return {
        jwa_name: "HS512",
        id: {name: "HMAC", hash: {name: "SHA-512"}}
      };
    case "ES256":
      return {
        jwa_name: "ES256",
        id: {name: "ECDSA", hash: {name: "SHA-256"}}
      };
    case "ES384":
      return {
        jwa_name: "ES384",
        id: {name: "ECDSA", hash: {name: "SHA-384"}}
      };
    case "ES512":
      return {
        jwa_name: "ES512",
        id: {name: "ECDSA", hash: {name: "SHA-512"}}
      };
    default:
      throw Error("unsupported algorithm: " + alg);
  }
};

/**
 * Returns JWA name for a given CryptoKey
 * @param key CryptoKey
 */
var getJwaNameForSignKey = function(key) {

  var rv = "",
    sign_algo = key.algorithm.name,
    hash_algo = key.algorithm.hash.name;

  if(sign_algo == "RSASSA-PKCS1-v1_5") {
    rv = "R";
  } else if(sign_algo == "RSA-PSS") {
    rv = "P";
  } else {
    throw new Error("unsupported sign/verify algorithm " + sign_algo);
  }

  if(hash_algo.indexOf("SHA-") === 0) {
    rv += "S";
  } else {
    throw new Error("unsupported hash algorithm " + sign_algo);
  }

  rv += hash_algo.substring(4);

  return rv;
};

/**
 * Derives key usage from algorithm's name
 *
 * @param alg String algorithm name
 * @returns {*}
 */
var getKeyUsageByAlg = function(alg) {

  switch (alg) {
    // signature
    case "RS256":
    case "RS384":
    case "RS512":
    case "PS256":
    case "PS384":
    case "PS512":
    case "HS256":
    case "HS384":
    case "HS512":
    case "ES256":
    case "ES384":
    case "ES512":
      return {
        publicKey: "verify",
        privateKey: "sign"
      };
    // key encryption
    case "RSA-OAEP":
    case "RSA-OAEP-256":
    case "A128KW":
    case "A256KW":
      return {
        publicKey: "wrapKey",
        privateKey: "unwrapKey"
      };
    default:
      throw Error("unsupported algorithm: " + alg);
  }
};

/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

Jose.Utils = {};
var Utils = {};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsa_key  public RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */
Jose.Utils.importRsaPublicKey = function(rsa_key, alg) {
  var jwk;
  var config;
  var usage = getKeyUsageByAlg(alg);

  if (usage.publicKey == "wrapKey") {
    if (!rsa_key.alg) {
      rsa_key.alg = alg;
    }
    jwk = Utils.convertRsaKey(rsa_key, ["n", "e"]);
    config = getCryptoConfig(alg);
  } else {
    var rk = {};
    for (var name in rsa_key) {
      if (rsa_key.hasOwnProperty(name)) {
        rk[name] = rsa_key[name];
      }
    }

    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    config = getSignConfig(rk.alg);
    jwk = Utils.convertRsaKey(rk, ["n", "e"]);
    jwk.ext = true;
  }
  return Jose.crypto.subtle.importKey("jwk", jwk, config.id, false, [usage.publicKey]);
};

/**
 * Converts the output from `openssl x509 -text` or `openssl rsa -text` into a
 * CryptoKey which can then be used with RSA-OAEP and RSA. Also accepts (and validates)
 * JWK keys.
 *
 * TODO: this code probably belongs in the webcryptographer.
 *
 * @param rsa_key  private RSA key in json format. Parameters can be base64
 *                 encoded, strings or number (for 'e').
 * @param alg      String, name of the algorithm
 * @return Promise<CryptoKey>
 */
Jose.Utils.importRsaPrivateKey = function(rsa_key, alg) {
  var jwk;
  var config;
  var usage = getKeyUsageByAlg(alg);

  if (usage.privateKey == "unwrapKey") {
    if (!rsa_key.alg) {
      rsa_key.alg = alg;
    }
    jwk = Utils.convertRsaKey(rsa_key, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);
    config = getCryptoConfig("RSA-OAEP");
  } else {
    var rk = {};
    for (var name in rsa_key) {
      if (rsa_key.hasOwnProperty(name)) {
        rk[name] = rsa_key[name];
      }
    }
    config = getSignConfig(alg);
    if (!rk.alg && alg) {
      rk.alg = alg;
    }
    jwk = Utils.convertRsaKey(rk, ["n", "e", "d", "p", "q", "dp", "dq", "qi"]);
    jwk.ext = true;
  }
  return Jose.crypto.subtle.importKey("jwk", jwk, config.id, false, [usage.privateKey]);
};

// Private functions

Utils.isString = function(str) {
  return ((typeof(str) == "string") || (str instanceof String));
};

/**
 * Takes an arrayish (an array, ArrayBuffer or Uint8Array)
 * and returns an array or a Uint8Array.
 *
 * @param arr  arrayish
 * @return array or Uint8Array
 */
Utils.arrayish = function(arr) {
  if (arr instanceof Array) {
    return arr;
  }
  if (arr instanceof Uint8Array) {
    return arr;
  }
  if (arr instanceof ArrayBuffer) {
    return new Uint8Array(arr);
  }
  Jose.assert(false, "arrayish: invalid input");
};

/**
 * Checks if an RSA key contains all the expected parameters. Also checks their
 * types. Converts hex encoded strings (or numbers) to base64.
 *
 * @param rsa_key     RSA key in json format. Parameters can be base64 encoded,
 *                    strings or number (for 'e').
 * @param parameters  array<string>
 * @return json
 */
Utils.convertRsaKey = function(rsa_key, parameters) {
  var r = {};
  var alg;

  // Check that we have all the parameters
  var missing = [];
  parameters.map(function(p){if (typeof(rsa_key[p]) == "undefined") { missing.push(p); }});

  if (missing.length > 0) {
    Jose.assert(false, "convertRsaKey: Was expecting " + missing.join());
  }

  // kty is either missing or is set to "RSA"
  if (typeof(rsa_key.kty) != "undefined") {
    Jose.assert(rsa_key.kty == "RSA", "convertRsaKey: expecting rsa_key['kty'] to be 'RSA'");
  }
  r.kty = "RSA";

  try {
    getSignConfig(rsa_key.alg);
    alg = rsa_key.alg;
  } catch (err) {
    try {
      getCryptoConfig(rsa_key.alg);
      alg = rsa_key.alg;
    } catch (er) {
      Jose.assert(alg, "convertRsaKey: expecting rsa_key['alg'] to have a valid value");
    }
  }
  r.alg = alg;

  // note: we punt on checking key_ops

  var intFromHex = function(e) {
    return parseInt(e, 16);
  };
  for (var i = 0; i < parameters.length; i++) {
    var p = parameters[i];
    var v = rsa_key[p];
    if (p == "e") {
      if (typeof(v) == "number") {
        v = Utils.Base64Url.encodeArray(Utils.stripLeadingZeros(Utils.arrayFromInt32(v)));
      }
    } else if (/^([0-9a-fA-F]{2}:)+[0-9a-fA-F]{2}$/.test(v)) {
      var arr = v.split(":").map(intFromHex);
      v = Utils.Base64Url.encodeArray(Utils.stripLeadingZeros(arr));
    } else if (typeof(v) != "string") {
      Jose.assert(false, "convertRsaKey: expecting rsa_key['" + p + "'] to be a string");
    }
    r[p] = v;
  }

  return r;
};

/**
 * Converts a string into an array of ascii codes.
 *
 * @param str  ascii string
 * @return Uint8Array
 */
Utils.arrayFromString = function(str) {
  Jose.assert(Utils.isString(str), "arrayFromString: invalid input");
  var arr = str.split('').map(function(c) {
    return c.charCodeAt(0);
  });
  return new Uint8Array(arr);
};

/**
 * Converts a string into an array of utf-8 codes.
 *
* @param str  utf-8 string
 * @return Uint8Array
 */
Utils.arrayFromUtf8String = function(str) {
  Jose.assert(Utils.isString(str), "arrayFromUtf8String: invalid input");
  // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.
  str = unescape(encodeURIComponent(str));
  return Utils.arrayFromString(str);
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  arrayish
 * @return ascii string
 */
Utils.stringFromArray = function(arr) {
  arr = Utils.arrayish(arr);
  var r = '';
  for (var i = 0; i < arr.length; i++) {
    r += String.fromCharCode(arr[i]);
  }

  return r;
};

/**
 * Converts an array of ascii bytes into a string.
 *
 * @param arr  ArrayBuffer
 * @return ascii string
 */
Utils.utf8StringFromArray = function(arr) {
  Jose.assert(arr instanceof ArrayBuffer, "utf8StringFromArray: invalid input");

  // javascript represents strings as utf-16. Jose imposes the use of
  // utf-8, so we need to convert from one representation to the other.
  var r = Utils.stringFromArray(arr);
  return decodeURIComponent(escape(r));
};

/**
 * Strips leading zero in an array.
 *
 * @param arr  arrayish
 * @return array
 */
Utils.stripLeadingZeros = function(arr) {
  if (arr instanceof ArrayBuffer) {
    arr = new Uint8Array(arr);
  }
  var is_leading_zero = true;
  var r = [];
  for (var i = 0; i < arr.length; i++) {
    if (is_leading_zero && arr[i] === 0) {
      continue;
    }
    is_leading_zero = false;
    r.push(arr[i]);
  }
  return r;
};

/**
 * Converts a number into an array of 4 bytes (big endian).
 *
 * @param i  number
 * @return ArrayBuffer
 */
Utils.arrayFromInt32 = function(i) {
  Jose.assert(typeof(i) == "number", "arrayFromInt32: invalid input");
  Jose.assert(i == i | 0, "arrayFromInt32: out of range");

  var buf = new Uint8Array(new Uint32Array([i]).buffer);
  var r = new Uint8Array(4);
  for (var j = 0; j < 4; j++) {
    r[j] = buf[3 - j];
  }
  return r.buffer;
};

/**
 * Concatenates arrayishes.
 *
 * @param arguments two or more arrayishes
 * @return Uint8Array
 */
Utils.arrayBufferConcat = function(/* ... */) {
  // Compute total size
  var args = [];
  var total = 0;
  for (var i = 0; i < arguments.length; i++) {
    args.push(Utils.arrayish(arguments[i]));
    total += args[i].length;
  }
  var r = new Uint8Array(total);
  var offset = 0;
  for (i = 0; i < arguments.length; i++) {
    for (var j = 0; j < args[i].length; j++) {
      r[offset++] = args[i][j];
    }
  }
  Jose.assert(offset == total, "arrayBufferConcat: unexpected offset");
  return r;
};

Utils.Base64Url = {};

/**
 * Base64Url encodes a string (no trailing '=')
 *
 * @param str  string
 * @return string
 */
Utils.Base64Url.encode = function(str) {
  Jose.assert(Utils.isString(str), "Base64Url.encode: invalid input");
  return btoa(str)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/, "");
};

/**
 * Base64Url encodes an array
 *
 * @param arr array or ArrayBuffer
 * @return string
 */
Utils.Base64Url.encodeArray = function(arr) {
  return Utils.Base64Url.encode(Utils.stringFromArray(arr));
};

/**
 * Base64Url decodes a string
 *
 * @param str  string
 * @return string
 */
Utils.Base64Url.decode = function(str) {
  Jose.assert(Utils.isString(str), "Base64Url.decode: invalid input");
  // atob is nice and ignores missing '='
  return atob(str.replace(/-/g, "+").replace(/_/g, "/"));
};

Utils.Base64Url.decodeArray = function(str) {
  Jose.assert(Utils.isString(str), "Base64Url.decodeArray: invalid input");
  return Utils.arrayFromString(Utils.Base64Url.decode(str));
};

Utils.sha256 = function(str) {
  // Browser docs indicate the first parameter to crypto.subtle.digest to be a
  // DOMString. This was initially implemented as an object and continues to be
  // supported, so we favor the older form for backwards compatibility.
  return Jose.crypto.subtle.digest({name: "SHA-256"}, Utils.arrayFromString(str)).then(function(hash) {
    return Utils.Base64Url.encodeArray(hash);
  });
};

Utils.isCryptoKey = function(rsa_key) {
  // Some browsers don't expose the CryptoKey as an object, so we need to check
  // the constructor's name.
  if (rsa_key.constructor.name == 'CryptoKey') {
    return true;
  }

  // In the presence of minifiers, relying on class names can be problematic,
  // so let's also allow objects that have an 'algorithm' property.
  if (rsa_key.hasOwnProperty('algorithm')) {
    return true;
  }

  return false;
};

/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Handles encryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent).
 * @param key_promise    Promise<CryptoKey>, either RSA or shared key
 */
JoseJWE.Encrypter = function(cryptographer, key_promise) {
  this.cryptographer = cryptographer;
  this.key_promise = key_promise;
  this.userHeaders = {};
};

/**
 * Adds a key/value pair which will be included in the header.
 *
 * The data lives in plaintext (an attacker can read the header) but is tamper
 * proof (an attacker cannot modify the header).
 *
 * Note: some headers have semantic implications. E.g. if you set the "zip"
 * header, you are responsible for properly compressing plain_text before
 * calling encrypt().
 *
 * @param k  String
 * @param v  String
 */
JoseJWE.Encrypter.prototype.addHeader = function(k, v) {
  this.userHeaders[k] = v;
};

/**
 * Performs encryption.
 *
 * @param plain_text  utf-8 string
 * @return Promise<String>
 */
JoseJWE.Encrypter.prototype.encrypt = function(plain_text) {
  /**
   * Encrypts plain_text with CEK.
   *
   * @param cek_promise  Promise<CryptoKey>
   * @param plain_text   string
   * @return Promise<json>
   */
  var encryptPlainText = function(cek_promise, plain_text) {
    // Create header
    var headers = {};
    for (var i in this.userHeaders) {
      headers[i] = this.userHeaders[i];
    }
    headers.alg = this.cryptographer.getKeyEncryptionAlgorithm();
    headers.enc = this.cryptographer.getContentEncryptionAlgorithm();
    var jwe_protected_header = Utils.Base64Url.encode(JSON.stringify(headers));

    // Create the IV
    var iv = this.cryptographer.createIV();

    // Create the AAD
    var aad = Utils.arrayFromString(jwe_protected_header);
    plain_text = Utils.arrayFromUtf8String(plain_text);

    return this.cryptographer.encrypt(iv, aad, cek_promise, plain_text).then(function(r) {
      r.header = jwe_protected_header;
      r.iv = iv;
      return r;
    });
  };

  var cek_promise, encrypted_cek;

  if (this.cryptographer.getKeyEncryptionAlgorithm() == "dir") {
    // with direct encryption, this.key_promise provides the cek
    // and encrypted_cek is empty
    cek_promise = Promise.resolve(this.key_promise);
    encrypted_cek = [];
  } else {
    // Create a CEK key
    cek_promise = this.cryptographer.createCek();

    // Key & Cek allows us to create the encrypted_cek
    encrypted_cek = Promise.all([this.key_promise, cek_promise]).then(function (all) {
      var key = all[0];
      var cek = all[1];
      return this.cryptographer.wrapCek(cek, key);
    }.bind(this));
  }

  // Cek allows us to encrypy the plain text
  var enc_promise = encryptPlainText.bind(this, cek_promise, plain_text)();

  // Once we have all the promises, we can base64 encode all the pieces.
  return Promise.all([encrypted_cek, enc_promise]).then(function(all) {
    var encrypted_cek = all[0];
    var data = all[1];
    return data.header + "." +
      Utils.Base64Url.encodeArray(encrypted_cek) + "." +
      Utils.Base64Url.encodeArray(data.iv) + "." +
      Utils.Base64Url.encodeArray(data.cipher) + "." +
      Utils.Base64Url.encodeArray(data.tag);
  });
};

/*-
 * Copyright 2014 Square Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param key_promise    Promise<CryptoKey>, either RSA or shared key
 */
JoseJWE.Decrypter = function(cryptographer, key_promise) {
  this.cryptographer = cryptographer;
  this.key_promise = key_promise;
  this.headers = {};
};

JoseJWE.Decrypter.prototype.getHeaders = function() {
  return this.headers;
};

/**
 * Performs decryption.
 *
 * @param cipher_text  String
 * @return Promise<String>
 */
JoseJWE.Decrypter.prototype.decrypt = function(cipher_text) {
  // Split cipher_text in 5 parts
  var parts = cipher_text.split(".");
  if (parts.length != 5) {
    return Promise.reject(Error("decrypt: invalid input"));
  }

  // part 1: header
  this.headers = JSON.parse(Utils.Base64Url.decode(parts[0]));
  if (!this.headers.alg) {
    return Promise.reject(Error("decrypt: missing alg"));
  }
  if (!this.headers.enc) {
    return Promise.reject(Error("decrypt: missing enc"));
  }
  this.cryptographer.setKeyEncryptionAlgorithm(this.headers.alg);
  this.cryptographer.setContentEncryptionAlgorithm(this.headers.enc);

  if (this.headers.crit) {
    // We don't support the crit header
    return Promise.reject(Error("decrypt: crit is not supported"));
  }

  var cek_promise;

  if (this.headers.alg == "dir") {
    // with direct mode, we already have the cek
    cek_promise = Promise.resolve(this.key_promise);
  } else {
    // part 2: decrypt the CEK
    // In some modes (e.g. RSA-PKCS1v1.5), you must take precautions to prevent
    // chosen-ciphertext attacks as described in RFC 3218, "Preventing
    // the Million Message Attack on Cryptographic Message Syntax". We currently
    // only support RSA-OAEP, so we don't generate a key if unwrapping fails.
    var encrypted_cek = Utils.Base64Url.decodeArray(parts[1]);
    cek_promise = this.key_promise.then(function (key) {
      return this.cryptographer.unwrapCek(encrypted_cek, key);
    }.bind(this));
  }

  // part 3: decrypt the cipher text
  var plain_text_promise = this.cryptographer.decrypt(
    cek_promise,
    Utils.arrayFromString(parts[0]),
    Utils.Base64Url.decodeArray(parts[2]),
    Utils.Base64Url.decodeArray(parts[3]),
    Utils.Base64Url.decodeArray(parts[4]));

  return plain_text_promise.then(Utils.utf8StringFromArray);
};

/*-
 * Copyright 2015 Peculiar Ventures
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Handles decryption.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
JoseJWS.Signer = function(cryptographer) {
  this.cryptographer = cryptographer;

  this.key_promises = {};
  this.waiting_kid = 0;
  this.headers = {};
  this.signer_aads = {};
  this.signer_headers = {};
};

/**
 * Adds a signer to JoseJWS instance. It'll be the on of the signers of the resulting JWS.
 *
 * @param rsa_key        private RSA key in json format, Parameters can be base64
 *                       encoded, strings or number (for 'e'). Or CryptoKey
 * @param key_id         a string identifying the rsa_key. OPTIONAL
 * @param aad            Object protected header
 * @param header         Object unprotected header
 */
JoseJWS.Signer.prototype.addSigner = function(rsa_key, key_id, aad, header) {
  var that = this;
  var key_promise;
  if (Utils.isCryptoKey(rsa_key)) {
    key_promise = new Promise(function(resolve) {
      resolve(rsa_key);
    });
  } else {
    var alg;
    if (aad && aad.alg) {
      alg = aad.alg;
    } else {
      alg = that.cryptographer.getContentSignAlgorithm();
    }
    key_promise = Jose.Utils.importRsaPrivateKey(rsa_key, alg, "sign");
  }

  var kid_promise;
  if (key_id) {
    kid_promise = new Promise(function(resolve) {
      resolve(key_id);
    });
  } else if (Utils.isCryptoKey(rsa_key)) {
    throw new Error("key_id is a mandatory argument when the key is a CryptoKey");
  } else {
    kid_promise = Jose.WebCryptographer.keyId(rsa_key);
  }

  that.waiting_kid++;

  return kid_promise.then(function(kid) {
    that.key_promises[kid] = key_promise;
    that.waiting_kid--;
    if (aad) {
      that.signer_aads[kid] = aad;
    }
    if (header) {
      that.signer_headers[kid] = header;
    }
    return kid;
  });
};

/**
 * Adds a signature to a JWS object
 * @param jws JWS Object to be signed or its representation
 * @param aad     Object protected header
 * @param header  Object unprotected header
 * @return Promise<String>
 */
JoseJWS.Signer.prototype.addSignature = function(jws, aad, header) {
  if (Utils.isString(jws)) {
    jws = JSON.parse(jws);
  }

  if (jws.payload && Utils.isString(jws.payload) &&
    jws.protected && Utils.isString(jws.protected) &&
    jws.header && jws.header instanceof Object &&
    jws.signature && Utils.isString(jws.signature)) {
    return this.sign(JWS.fromObject(jws), aad, header);
  } else {
    throw new Error("JWS is not a valid JWS object");
  }
};

/**
 * Computes signature.
 *
 * @param payload JWS Object or utf-8 string to be signed
 * @param aad     Object protected header
 * @param header  Object unprotected header
 * @return Promise<JWS>
 */
JoseJWS.Signer.prototype.sign = function(payload, aad, header) {

  var that = this;
  var kids = [];

  if (Object.keys(that.key_promises).length === 0) {
    throw new Error("No signers defined. At least one is required to sign the JWS.");
  }

  if (that.waiting_kid) {
    throw new Error("still generating key IDs");
  }

  function sign (message, protectedHeader, unprotectedHeader, rsa_key_promise, kid) {
    var toBeSigned;

    if (!protectedHeader) {
      protectedHeader = {};
    }

    if (!protectedHeader.alg) {
      protectedHeader.alg = that.cryptographer.getContentSignAlgorithm();
      protectedHeader.typ = "JWT";
    }

    if (!protectedHeader.kid) {
      protectedHeader.kid = kid;
    }

    if (Utils.isString(message)) {
      toBeSigned = Utils.arrayFromUtf8String(message);
    } else {
      try {
        toBeSigned = Utils.arrayish(message);
      } catch (e) {
        if (message instanceof JWS) {
          toBeSigned = Utils.arrayFromString(Utils.Base64Url.decode(message.payload));
        } else if (message instanceof Object) {
          toBeSigned = Utils.arrayFromUtf8String(JSON.stringify(message));
        } else {
          throw new Error("cannot sign this message");
        }
      }
    }

    return that.cryptographer.sign(protectedHeader, toBeSigned, rsa_key_promise).then(function(signature) {
      var jws = new JWS(protectedHeader, unprotectedHeader, toBeSigned, signature);
      if (message instanceof JWS) {
        delete jws.payload;
        if (!message.signatures) {
          message.signatures = [jws];
        } else {
          message.signatures.push(jws);
        }
        return message;
      }
      return jws;
    });
  }

  function doSign (pl, ph, uh, kps, kids) {
    if (kids.length) {
      var k_id = kids.shift();
      var rv = sign(pl, that.signer_aads[k_id] || ph, that.signer_headers[k_id] || uh, kps[k_id], k_id);
      if (kids.length) {
        rv = rv.then(function(jws) {
          return doSign(jws, null, null, kps, kids);
        });
      }
      return rv;
    }
  }

  for(var kid in that.key_promises) {
    if (that.key_promises.hasOwnProperty(kid)) {
      kids.push(kid);
    }
  }
  return doSign(payload, aad, header, that.key_promises, kids);
};


/**
 * Initialize a JWS object.
 *
 * @param protectedHeader protected header (JS object)
 * @param payload Uint8Array payload to be signed
 * @param signature ArrayBuffer signature of the payload
 * @param header unprotected header (JS object)
 *
 * @constructor
 */
var JWS = function(protectedHeader, header, payload, signature) {
  this.header = header;
  this.payload = Utils.Base64Url.encodeArray(payload);
  if (signature) {
    this.signature = Utils.Base64Url.encodeArray(signature);
  }
  this.protected = Utils.Base64Url.encode(JSON.stringify(protectedHeader));
};

JWS.fromObject = function(obj) {
  var rv = new JWS(obj.protected, obj.header, obj.payload, null);
  rv.signature = obj.signature;
  rv.signatures = obj.signatures;
  return rv;
};

/**
 * Serialize a JWS object using the JSON serialization format
 *
 * @returns {Object} a copy of this
 */
JWS.prototype.JsonSerialize = function() {
  return JSON.stringify(this);
};

/**
 * Serialize a JWS object using the Compact Serialization Format
 *
 * @returns {string} BASE64URL(UTF8(PROTECTED HEADER)).BASE64URL(PAYLOAD).BASE64URL(SIGNATURE)
 */
JWS.prototype.CompactSerialize = function() {
  return this.protected + '.' + this.payload + '.' + this.signature;
};

/*-
 * Copyright 2015 Peculiar Ventures
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

/**
 * Handles signature verification.
 *
 * @param cryptographer  an instance of WebCryptographer (or equivalent). Keep
 *                       in mind that decryption mutates the cryptographer.
 * @param message        a JWS message
 * @param keyfinder (optional) a function returning a Promise<CryptoKey> given
 *                             a key id
 *
 * @author Patrizio Bruno <patrizio@desertconsulting.net>
 */
JoseJWS.Verifier = function (cryptographer, message, keyfinder) {

  var that = this,
    alg,
    jwt,
    aad,
    header,
    payload,
    signatures,
    protectedHeader,
    jwtRx = /^([0-9a-z_\-]+)\.([0-9a-z_\-]+)\.([0-9a-z_\-]+)$/i;

  that.cryptographer = cryptographer;

  alg = cryptographer.getContentSignAlgorithm();

  that.cryptographer = new Jose.WebCryptographer();

  if (Utils.isString(message)) {
    if ((jwt = jwtRx.exec(message))) {
      if (jwt.length != 4) {
        throw new Error("wrong JWS compact serialization format");
      }

      message = {
        protected: jwt[1],
        payload: jwt[2],
        signature: jwt[3]
      };
    } else {
      message = JSON.parse(message);
    }
  } else if (typeof message != "object") {
    throw new Error("data format not supported");
  }

  aad = message.protected;
  header = message.header;
  payload = message.payload;
  signatures = message.signatures instanceof Array ? message.signatures.slice(0) : [];

  signatures.forEach(function (sign) {
    sign.aad = sign.protected;
    sign.protected = JSON.parse(Utils.Base64Url.decode(sign.protected));
  });

  that.aad = aad;
  protectedHeader = Utils.Base64Url.decode(aad);
  try {
    protectedHeader = JSON.parse(protectedHeader);
  } catch (e) {
  }

  if (!protectedHeader && !header) {
    throw new Error("at least one header is required");
  }

  if (!protectedHeader.alg) {
    throw new Error("'alg' is a mandatory header");
  }

  if (protectedHeader.alg != alg) {
    throw new Error("the alg header '" + protectedHeader.alg + "' doesn't match the requested algorithm '" + alg + "'");
  }

  if (protectedHeader && protectedHeader.typ && protectedHeader.typ != "JWT") {
    throw new Error("typ '" + protectedHeader.typ + "' not supported");
  }

  if (message.signature) {
    signatures.unshift({
      aad: aad,
      protected: protectedHeader,
      header: header,
      signature: message.signature
    });
  }

  that.signatures = [];
  for(var i = 0; i < signatures.length; i++) {
    that.signatures[i] = JSON.parse(JSON.stringify(signatures[i]));
    that.signatures[i].signature = Utils.arrayFromString(Utils.Base64Url.decode(signatures[i].signature));
  }

  that.payload = payload;

  that.key_promises = {};
  that.waiting_kid = 0;

  if (keyfinder) {
    that.keyfinder = keyfinder;
  }
};

/**
 * Add supported recipients to verify multiple signatures
 *
 * @param rsa_key        public RSA key in json format. Parameters can be base64
 *                       encoded, strings or number (for 'e').
 * @param key_id         a string identifying the rsa_key. OPTIONAL
 * @param alg            String signature algorithm. OPTIONAL
 * @returns Promise<string> a Promise of a key id
 */
JoseJWS.Verifier.prototype.addRecipient = function (rsa_key, key_id, alg) {

  var that = this,
    kid_promise,
    key_promise = Utils.isCryptoKey(rsa_key) ? new Promise(function (resolve) {
      resolve(rsa_key);
    }) : Jose.Utils.importRsaPublicKey(rsa_key, alg || that.cryptographer.getContentSignAlgorithm(), "verify");

  if (key_id) {
    kid_promise = new Promise(function (resolve) {
      resolve(key_id);
    });
  } else if (Utils.isCryptoKey(rsa_key)) {
    throw new Error("key_id is a mandatory argument when the key is a CryptoKey");
  } else {
    console.log("it's not safe to not pass a key_id");
    kid_promise = Jose.WebCryptographer.keyId(rsa_key);
  }

  that.waiting_kid++;

  return kid_promise.then(function (kid) {
    that.key_promises[kid] = key_promise;
    that.waiting_kid--;
    return kid;
  });
};

/**
 * Verifies a JWS signature
 *
 * @returns Promise<Array> a Promise of an array of objects { kid: string, verified: bool, payload?: string }
 *
 * payload is only populated and usable if verified is true
 */
JoseJWS.Verifier.prototype.verify = function () {

  var that = this,
    signatures = that.signatures,
    key_promises = that.key_promises,
    keyfinder = that.keyfinder,
    promises = [],
    check = !!keyfinder || Object.keys(that.key_promises).length > 0;

  if (!check) {
    throw new Error("No recipients defined. At least one is required to verify the JWS.");
  }

  if (that.waiting_kid) {
    throw new Error("still generating key IDs");
  }

  signatures.forEach(function (sig) {
    var kid = sig.protected.kid;
    if (keyfinder) {
      key_promises[kid] = keyfinder(kid);
    }
    promises.push(that.cryptographer.verify(sig.aad, that.payload, sig.signature, key_promises[kid], kid)
      .then(function (vr) {
        if (vr.verified) {
          vr.payload = Utils.Base64Url.decode(that.payload);
        }
        return vr;
      }));
  });
  return Promise.all(promises);
};

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(2).Buffer))

/***/ }),
/* 2 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";
/* WEBPACK VAR INJECTION */(function(global) {/*!
 * The buffer module from node.js, for the browser.
 *
 * @author   Feross Aboukhadijeh <feross@feross.org> <http://feross.org>
 * @license  MIT
 */
/* eslint-disable no-proto */



var base64 = __webpack_require__(4)
var ieee754 = __webpack_require__(5)
var isArray = __webpack_require__(6)

exports.Buffer = Buffer
exports.SlowBuffer = SlowBuffer
exports.INSPECT_MAX_BYTES = 50

/**
 * If `Buffer.TYPED_ARRAY_SUPPORT`:
 *   === true    Use Uint8Array implementation (fastest)
 *   === false   Use Object implementation (most compatible, even IE6)
 *
 * Browsers that support typed arrays are IE 10+, Firefox 4+, Chrome 7+, Safari 5.1+,
 * Opera 11.6+, iOS 4.2+.
 *
 * Due to various browser bugs, sometimes the Object implementation will be used even
 * when the browser supports typed arrays.
 *
 * Note:
 *
 *   - Firefox 4-29 lacks support for adding new properties to `Uint8Array` instances,
 *     See: https://bugzilla.mozilla.org/show_bug.cgi?id=695438.
 *
 *   - Chrome 9-10 is missing the `TypedArray.prototype.subarray` function.
 *
 *   - IE10 has a broken `TypedArray.prototype.subarray` function which returns arrays of
 *     incorrect length in some situations.

 * We detect these buggy browsers and set `Buffer.TYPED_ARRAY_SUPPORT` to `false` so they
 * get the Object implementation, which is slower but behaves correctly.
 */
Buffer.TYPED_ARRAY_SUPPORT = global.TYPED_ARRAY_SUPPORT !== undefined
  ? global.TYPED_ARRAY_SUPPORT
  : typedArraySupport()

/*
 * Export kMaxLength after typed array support is determined.
 */
exports.kMaxLength = kMaxLength()

function typedArraySupport () {
  try {
    var arr = new Uint8Array(1)
    arr.__proto__ = {__proto__: Uint8Array.prototype, foo: function () { return 42 }}
    return arr.foo() === 42 && // typed array instances can be augmented
        typeof arr.subarray === 'function' && // chrome 9-10 lack `subarray`
        arr.subarray(1, 1).byteLength === 0 // ie10 has broken `subarray`
  } catch (e) {
    return false
  }
}

function kMaxLength () {
  return Buffer.TYPED_ARRAY_SUPPORT
    ? 0x7fffffff
    : 0x3fffffff
}

function createBuffer (that, length) {
  if (kMaxLength() < length) {
    throw new RangeError('Invalid typed array length')
  }
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = new Uint8Array(length)
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    if (that === null) {
      that = new Buffer(length)
    }
    that.length = length
  }

  return that
}

/**
 * The Buffer constructor returns instances of `Uint8Array` that have their
 * prototype changed to `Buffer.prototype`. Furthermore, `Buffer` is a subclass of
 * `Uint8Array`, so the returned instances will have all the node `Buffer` methods
 * and the `Uint8Array` methods. Square bracket notation works as expected -- it
 * returns a single octet.
 *
 * The `Uint8Array` prototype remains unmodified.
 */

function Buffer (arg, encodingOrOffset, length) {
  if (!Buffer.TYPED_ARRAY_SUPPORT && !(this instanceof Buffer)) {
    return new Buffer(arg, encodingOrOffset, length)
  }

  // Common case.
  if (typeof arg === 'number') {
    if (typeof encodingOrOffset === 'string') {
      throw new Error(
        'If encoding is specified then the first argument must be a string'
      )
    }
    return allocUnsafe(this, arg)
  }
  return from(this, arg, encodingOrOffset, length)
}

Buffer.poolSize = 8192 // not used by this implementation

// TODO: Legacy, not needed anymore. Remove in next major version.
Buffer._augment = function (arr) {
  arr.__proto__ = Buffer.prototype
  return arr
}

function from (that, value, encodingOrOffset, length) {
  if (typeof value === 'number') {
    throw new TypeError('"value" argument must not be a number')
  }

  if (typeof ArrayBuffer !== 'undefined' && value instanceof ArrayBuffer) {
    return fromArrayBuffer(that, value, encodingOrOffset, length)
  }

  if (typeof value === 'string') {
    return fromString(that, value, encodingOrOffset)
  }

  return fromObject(that, value)
}

/**
 * Functionally equivalent to Buffer(arg, encoding) but throws a TypeError
 * if value is a number.
 * Buffer.from(str[, encoding])
 * Buffer.from(array)
 * Buffer.from(buffer)
 * Buffer.from(arrayBuffer[, byteOffset[, length]])
 **/
Buffer.from = function (value, encodingOrOffset, length) {
  return from(null, value, encodingOrOffset, length)
}

if (Buffer.TYPED_ARRAY_SUPPORT) {
  Buffer.prototype.__proto__ = Uint8Array.prototype
  Buffer.__proto__ = Uint8Array
  if (typeof Symbol !== 'undefined' && Symbol.species &&
      Buffer[Symbol.species] === Buffer) {
    // Fix subarray() in ES2016. See: https://github.com/feross/buffer/pull/97
    Object.defineProperty(Buffer, Symbol.species, {
      value: null,
      configurable: true
    })
  }
}

function assertSize (size) {
  if (typeof size !== 'number') {
    throw new TypeError('"size" argument must be a number')
  } else if (size < 0) {
    throw new RangeError('"size" argument must not be negative')
  }
}

function alloc (that, size, fill, encoding) {
  assertSize(size)
  if (size <= 0) {
    return createBuffer(that, size)
  }
  if (fill !== undefined) {
    // Only pay attention to encoding if it's a string. This
    // prevents accidentally sending in a number that would
    // be interpretted as a start offset.
    return typeof encoding === 'string'
      ? createBuffer(that, size).fill(fill, encoding)
      : createBuffer(that, size).fill(fill)
  }
  return createBuffer(that, size)
}

/**
 * Creates a new filled Buffer instance.
 * alloc(size[, fill[, encoding]])
 **/
Buffer.alloc = function (size, fill, encoding) {
  return alloc(null, size, fill, encoding)
}

function allocUnsafe (that, size) {
  assertSize(size)
  that = createBuffer(that, size < 0 ? 0 : checked(size) | 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) {
    for (var i = 0; i < size; ++i) {
      that[i] = 0
    }
  }
  return that
}

/**
 * Equivalent to Buffer(num), by default creates a non-zero-filled Buffer instance.
 * */
Buffer.allocUnsafe = function (size) {
  return allocUnsafe(null, size)
}
/**
 * Equivalent to SlowBuffer(num), by default creates a non-zero-filled Buffer instance.
 */
Buffer.allocUnsafeSlow = function (size) {
  return allocUnsafe(null, size)
}

function fromString (that, string, encoding) {
  if (typeof encoding !== 'string' || encoding === '') {
    encoding = 'utf8'
  }

  if (!Buffer.isEncoding(encoding)) {
    throw new TypeError('"encoding" must be a valid string encoding')
  }

  var length = byteLength(string, encoding) | 0
  that = createBuffer(that, length)

  var actual = that.write(string, encoding)

  if (actual !== length) {
    // Writing a hex string, for example, that contains invalid characters will
    // cause everything after the first invalid character to be ignored. (e.g.
    // 'abxxcd' will be treated as 'ab')
    that = that.slice(0, actual)
  }

  return that
}

function fromArrayLike (that, array) {
  var length = array.length < 0 ? 0 : checked(array.length) | 0
  that = createBuffer(that, length)
  for (var i = 0; i < length; i += 1) {
    that[i] = array[i] & 255
  }
  return that
}

function fromArrayBuffer (that, array, byteOffset, length) {
  array.byteLength // this throws if `array` is not a valid ArrayBuffer

  if (byteOffset < 0 || array.byteLength < byteOffset) {
    throw new RangeError('\'offset\' is out of bounds')
  }

  if (array.byteLength < byteOffset + (length || 0)) {
    throw new RangeError('\'length\' is out of bounds')
  }

  if (byteOffset === undefined && length === undefined) {
    array = new Uint8Array(array)
  } else if (length === undefined) {
    array = new Uint8Array(array, byteOffset)
  } else {
    array = new Uint8Array(array, byteOffset, length)
  }

  if (Buffer.TYPED_ARRAY_SUPPORT) {
    // Return an augmented `Uint8Array` instance, for best performance
    that = array
    that.__proto__ = Buffer.prototype
  } else {
    // Fallback: Return an object instance of the Buffer class
    that = fromArrayLike(that, array)
  }
  return that
}

function fromObject (that, obj) {
  if (Buffer.isBuffer(obj)) {
    var len = checked(obj.length) | 0
    that = createBuffer(that, len)

    if (that.length === 0) {
      return that
    }

    obj.copy(that, 0, 0, len)
    return that
  }

  if (obj) {
    if ((typeof ArrayBuffer !== 'undefined' &&
        obj.buffer instanceof ArrayBuffer) || 'length' in obj) {
      if (typeof obj.length !== 'number' || isnan(obj.length)) {
        return createBuffer(that, 0)
      }
      return fromArrayLike(that, obj)
    }

    if (obj.type === 'Buffer' && isArray(obj.data)) {
      return fromArrayLike(that, obj.data)
    }
  }

  throw new TypeError('First argument must be a string, Buffer, ArrayBuffer, Array, or array-like object.')
}

function checked (length) {
  // Note: cannot use `length < kMaxLength()` here because that fails when
  // length is NaN (which is otherwise coerced to zero.)
  if (length >= kMaxLength()) {
    throw new RangeError('Attempt to allocate Buffer larger than maximum ' +
                         'size: 0x' + kMaxLength().toString(16) + ' bytes')
  }
  return length | 0
}

function SlowBuffer (length) {
  if (+length != length) { // eslint-disable-line eqeqeq
    length = 0
  }
  return Buffer.alloc(+length)
}

Buffer.isBuffer = function isBuffer (b) {
  return !!(b != null && b._isBuffer)
}

Buffer.compare = function compare (a, b) {
  if (!Buffer.isBuffer(a) || !Buffer.isBuffer(b)) {
    throw new TypeError('Arguments must be Buffers')
  }

  if (a === b) return 0

  var x = a.length
  var y = b.length

  for (var i = 0, len = Math.min(x, y); i < len; ++i) {
    if (a[i] !== b[i]) {
      x = a[i]
      y = b[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

Buffer.isEncoding = function isEncoding (encoding) {
  switch (String(encoding).toLowerCase()) {
    case 'hex':
    case 'utf8':
    case 'utf-8':
    case 'ascii':
    case 'latin1':
    case 'binary':
    case 'base64':
    case 'ucs2':
    case 'ucs-2':
    case 'utf16le':
    case 'utf-16le':
      return true
    default:
      return false
  }
}

Buffer.concat = function concat (list, length) {
  if (!isArray(list)) {
    throw new TypeError('"list" argument must be an Array of Buffers')
  }

  if (list.length === 0) {
    return Buffer.alloc(0)
  }

  var i
  if (length === undefined) {
    length = 0
    for (i = 0; i < list.length; ++i) {
      length += list[i].length
    }
  }

  var buffer = Buffer.allocUnsafe(length)
  var pos = 0
  for (i = 0; i < list.length; ++i) {
    var buf = list[i]
    if (!Buffer.isBuffer(buf)) {
      throw new TypeError('"list" argument must be an Array of Buffers')
    }
    buf.copy(buffer, pos)
    pos += buf.length
  }
  return buffer
}

function byteLength (string, encoding) {
  if (Buffer.isBuffer(string)) {
    return string.length
  }
  if (typeof ArrayBuffer !== 'undefined' && typeof ArrayBuffer.isView === 'function' &&
      (ArrayBuffer.isView(string) || string instanceof ArrayBuffer)) {
    return string.byteLength
  }
  if (typeof string !== 'string') {
    string = '' + string
  }

  var len = string.length
  if (len === 0) return 0

  // Use a for loop to avoid recursion
  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'ascii':
      case 'latin1':
      case 'binary':
        return len
      case 'utf8':
      case 'utf-8':
      case undefined:
        return utf8ToBytes(string).length
      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return len * 2
      case 'hex':
        return len >>> 1
      case 'base64':
        return base64ToBytes(string).length
      default:
        if (loweredCase) return utf8ToBytes(string).length // assume utf8
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}
Buffer.byteLength = byteLength

function slowToString (encoding, start, end) {
  var loweredCase = false

  // No need to verify that "this.length <= MAX_UINT32" since it's a read-only
  // property of a typed array.

  // This behaves neither like String nor Uint8Array in that we set start/end
  // to their upper/lower bounds if the value passed is out of range.
  // undefined is handled specially as per ECMA-262 6th Edition,
  // Section 13.3.3.7 Runtime Semantics: KeyedBindingInitialization.
  if (start === undefined || start < 0) {
    start = 0
  }
  // Return early if start > this.length. Done here to prevent potential uint32
  // coercion fail below.
  if (start > this.length) {
    return ''
  }

  if (end === undefined || end > this.length) {
    end = this.length
  }

  if (end <= 0) {
    return ''
  }

  // Force coersion to uint32. This will also coerce falsey/NaN values to 0.
  end >>>= 0
  start >>>= 0

  if (end <= start) {
    return ''
  }

  if (!encoding) encoding = 'utf8'

  while (true) {
    switch (encoding) {
      case 'hex':
        return hexSlice(this, start, end)

      case 'utf8':
      case 'utf-8':
        return utf8Slice(this, start, end)

      case 'ascii':
        return asciiSlice(this, start, end)

      case 'latin1':
      case 'binary':
        return latin1Slice(this, start, end)

      case 'base64':
        return base64Slice(this, start, end)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return utf16leSlice(this, start, end)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = (encoding + '').toLowerCase()
        loweredCase = true
    }
  }
}

// The property is used by `Buffer.isBuffer` and `is-buffer` (in Safari 5-7) to detect
// Buffer instances.
Buffer.prototype._isBuffer = true

function swap (b, n, m) {
  var i = b[n]
  b[n] = b[m]
  b[m] = i
}

Buffer.prototype.swap16 = function swap16 () {
  var len = this.length
  if (len % 2 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 16-bits')
  }
  for (var i = 0; i < len; i += 2) {
    swap(this, i, i + 1)
  }
  return this
}

Buffer.prototype.swap32 = function swap32 () {
  var len = this.length
  if (len % 4 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 32-bits')
  }
  for (var i = 0; i < len; i += 4) {
    swap(this, i, i + 3)
    swap(this, i + 1, i + 2)
  }
  return this
}

Buffer.prototype.swap64 = function swap64 () {
  var len = this.length
  if (len % 8 !== 0) {
    throw new RangeError('Buffer size must be a multiple of 64-bits')
  }
  for (var i = 0; i < len; i += 8) {
    swap(this, i, i + 7)
    swap(this, i + 1, i + 6)
    swap(this, i + 2, i + 5)
    swap(this, i + 3, i + 4)
  }
  return this
}

Buffer.prototype.toString = function toString () {
  var length = this.length | 0
  if (length === 0) return ''
  if (arguments.length === 0) return utf8Slice(this, 0, length)
  return slowToString.apply(this, arguments)
}

Buffer.prototype.equals = function equals (b) {
  if (!Buffer.isBuffer(b)) throw new TypeError('Argument must be a Buffer')
  if (this === b) return true
  return Buffer.compare(this, b) === 0
}

Buffer.prototype.inspect = function inspect () {
  var str = ''
  var max = exports.INSPECT_MAX_BYTES
  if (this.length > 0) {
    str = this.toString('hex', 0, max).match(/.{2}/g).join(' ')
    if (this.length > max) str += ' ... '
  }
  return '<Buffer ' + str + '>'
}

Buffer.prototype.compare = function compare (target, start, end, thisStart, thisEnd) {
  if (!Buffer.isBuffer(target)) {
    throw new TypeError('Argument must be a Buffer')
  }

  if (start === undefined) {
    start = 0
  }
  if (end === undefined) {
    end = target ? target.length : 0
  }
  if (thisStart === undefined) {
    thisStart = 0
  }
  if (thisEnd === undefined) {
    thisEnd = this.length
  }

  if (start < 0 || end > target.length || thisStart < 0 || thisEnd > this.length) {
    throw new RangeError('out of range index')
  }

  if (thisStart >= thisEnd && start >= end) {
    return 0
  }
  if (thisStart >= thisEnd) {
    return -1
  }
  if (start >= end) {
    return 1
  }

  start >>>= 0
  end >>>= 0
  thisStart >>>= 0
  thisEnd >>>= 0

  if (this === target) return 0

  var x = thisEnd - thisStart
  var y = end - start
  var len = Math.min(x, y)

  var thisCopy = this.slice(thisStart, thisEnd)
  var targetCopy = target.slice(start, end)

  for (var i = 0; i < len; ++i) {
    if (thisCopy[i] !== targetCopy[i]) {
      x = thisCopy[i]
      y = targetCopy[i]
      break
    }
  }

  if (x < y) return -1
  if (y < x) return 1
  return 0
}

// Finds either the first index of `val` in `buffer` at offset >= `byteOffset`,
// OR the last index of `val` in `buffer` at offset <= `byteOffset`.
//
// Arguments:
// - buffer - a Buffer to search
// - val - a string, Buffer, or number
// - byteOffset - an index into `buffer`; will be clamped to an int32
// - encoding - an optional encoding, relevant is val is a string
// - dir - true for indexOf, false for lastIndexOf
function bidirectionalIndexOf (buffer, val, byteOffset, encoding, dir) {
  // Empty buffer means no match
  if (buffer.length === 0) return -1

  // Normalize byteOffset
  if (typeof byteOffset === 'string') {
    encoding = byteOffset
    byteOffset = 0
  } else if (byteOffset > 0x7fffffff) {
    byteOffset = 0x7fffffff
  } else if (byteOffset < -0x80000000) {
    byteOffset = -0x80000000
  }
  byteOffset = +byteOffset  // Coerce to Number.
  if (isNaN(byteOffset)) {
    // byteOffset: it it's undefined, null, NaN, "foo", etc, search whole buffer
    byteOffset = dir ? 0 : (buffer.length - 1)
  }

  // Normalize byteOffset: negative offsets start from the end of the buffer
  if (byteOffset < 0) byteOffset = buffer.length + byteOffset
  if (byteOffset >= buffer.length) {
    if (dir) return -1
    else byteOffset = buffer.length - 1
  } else if (byteOffset < 0) {
    if (dir) byteOffset = 0
    else return -1
  }

  // Normalize val
  if (typeof val === 'string') {
    val = Buffer.from(val, encoding)
  }

  // Finally, search either indexOf (if dir is true) or lastIndexOf
  if (Buffer.isBuffer(val)) {
    // Special case: looking for empty string/buffer always fails
    if (val.length === 0) {
      return -1
    }
    return arrayIndexOf(buffer, val, byteOffset, encoding, dir)
  } else if (typeof val === 'number') {
    val = val & 0xFF // Search for a byte value [0-255]
    if (Buffer.TYPED_ARRAY_SUPPORT &&
        typeof Uint8Array.prototype.indexOf === 'function') {
      if (dir) {
        return Uint8Array.prototype.indexOf.call(buffer, val, byteOffset)
      } else {
        return Uint8Array.prototype.lastIndexOf.call(buffer, val, byteOffset)
      }
    }
    return arrayIndexOf(buffer, [ val ], byteOffset, encoding, dir)
  }

  throw new TypeError('val must be string, number or Buffer')
}

function arrayIndexOf (arr, val, byteOffset, encoding, dir) {
  var indexSize = 1
  var arrLength = arr.length
  var valLength = val.length

  if (encoding !== undefined) {
    encoding = String(encoding).toLowerCase()
    if (encoding === 'ucs2' || encoding === 'ucs-2' ||
        encoding === 'utf16le' || encoding === 'utf-16le') {
      if (arr.length < 2 || val.length < 2) {
        return -1
      }
      indexSize = 2
      arrLength /= 2
      valLength /= 2
      byteOffset /= 2
    }
  }

  function read (buf, i) {
    if (indexSize === 1) {
      return buf[i]
    } else {
      return buf.readUInt16BE(i * indexSize)
    }
  }

  var i
  if (dir) {
    var foundIndex = -1
    for (i = byteOffset; i < arrLength; i++) {
      if (read(arr, i) === read(val, foundIndex === -1 ? 0 : i - foundIndex)) {
        if (foundIndex === -1) foundIndex = i
        if (i - foundIndex + 1 === valLength) return foundIndex * indexSize
      } else {
        if (foundIndex !== -1) i -= i - foundIndex
        foundIndex = -1
      }
    }
  } else {
    if (byteOffset + valLength > arrLength) byteOffset = arrLength - valLength
    for (i = byteOffset; i >= 0; i--) {
      var found = true
      for (var j = 0; j < valLength; j++) {
        if (read(arr, i + j) !== read(val, j)) {
          found = false
          break
        }
      }
      if (found) return i
    }
  }

  return -1
}

Buffer.prototype.includes = function includes (val, byteOffset, encoding) {
  return this.indexOf(val, byteOffset, encoding) !== -1
}

Buffer.prototype.indexOf = function indexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, true)
}

Buffer.prototype.lastIndexOf = function lastIndexOf (val, byteOffset, encoding) {
  return bidirectionalIndexOf(this, val, byteOffset, encoding, false)
}

function hexWrite (buf, string, offset, length) {
  offset = Number(offset) || 0
  var remaining = buf.length - offset
  if (!length) {
    length = remaining
  } else {
    length = Number(length)
    if (length > remaining) {
      length = remaining
    }
  }

  // must be an even number of digits
  var strLen = string.length
  if (strLen % 2 !== 0) throw new TypeError('Invalid hex string')

  if (length > strLen / 2) {
    length = strLen / 2
  }
  for (var i = 0; i < length; ++i) {
    var parsed = parseInt(string.substr(i * 2, 2), 16)
    if (isNaN(parsed)) return i
    buf[offset + i] = parsed
  }
  return i
}

function utf8Write (buf, string, offset, length) {
  return blitBuffer(utf8ToBytes(string, buf.length - offset), buf, offset, length)
}

function asciiWrite (buf, string, offset, length) {
  return blitBuffer(asciiToBytes(string), buf, offset, length)
}

function latin1Write (buf, string, offset, length) {
  return asciiWrite(buf, string, offset, length)
}

function base64Write (buf, string, offset, length) {
  return blitBuffer(base64ToBytes(string), buf, offset, length)
}

function ucs2Write (buf, string, offset, length) {
  return blitBuffer(utf16leToBytes(string, buf.length - offset), buf, offset, length)
}

Buffer.prototype.write = function write (string, offset, length, encoding) {
  // Buffer#write(string)
  if (offset === undefined) {
    encoding = 'utf8'
    length = this.length
    offset = 0
  // Buffer#write(string, encoding)
  } else if (length === undefined && typeof offset === 'string') {
    encoding = offset
    length = this.length
    offset = 0
  // Buffer#write(string, offset[, length][, encoding])
  } else if (isFinite(offset)) {
    offset = offset | 0
    if (isFinite(length)) {
      length = length | 0
      if (encoding === undefined) encoding = 'utf8'
    } else {
      encoding = length
      length = undefined
    }
  // legacy write(string, encoding, offset, length) - remove in v0.13
  } else {
    throw new Error(
      'Buffer.write(string, encoding, offset[, length]) is no longer supported'
    )
  }

  var remaining = this.length - offset
  if (length === undefined || length > remaining) length = remaining

  if ((string.length > 0 && (length < 0 || offset < 0)) || offset > this.length) {
    throw new RangeError('Attempt to write outside buffer bounds')
  }

  if (!encoding) encoding = 'utf8'

  var loweredCase = false
  for (;;) {
    switch (encoding) {
      case 'hex':
        return hexWrite(this, string, offset, length)

      case 'utf8':
      case 'utf-8':
        return utf8Write(this, string, offset, length)

      case 'ascii':
        return asciiWrite(this, string, offset, length)

      case 'latin1':
      case 'binary':
        return latin1Write(this, string, offset, length)

      case 'base64':
        // Warning: maxLength not taken into account in base64Write
        return base64Write(this, string, offset, length)

      case 'ucs2':
      case 'ucs-2':
      case 'utf16le':
      case 'utf-16le':
        return ucs2Write(this, string, offset, length)

      default:
        if (loweredCase) throw new TypeError('Unknown encoding: ' + encoding)
        encoding = ('' + encoding).toLowerCase()
        loweredCase = true
    }
  }
}

Buffer.prototype.toJSON = function toJSON () {
  return {
    type: 'Buffer',
    data: Array.prototype.slice.call(this._arr || this, 0)
  }
}

function base64Slice (buf, start, end) {
  if (start === 0 && end === buf.length) {
    return base64.fromByteArray(buf)
  } else {
    return base64.fromByteArray(buf.slice(start, end))
  }
}

function utf8Slice (buf, start, end) {
  end = Math.min(buf.length, end)
  var res = []

  var i = start
  while (i < end) {
    var firstByte = buf[i]
    var codePoint = null
    var bytesPerSequence = (firstByte > 0xEF) ? 4
      : (firstByte > 0xDF) ? 3
      : (firstByte > 0xBF) ? 2
      : 1

    if (i + bytesPerSequence <= end) {
      var secondByte, thirdByte, fourthByte, tempCodePoint

      switch (bytesPerSequence) {
        case 1:
          if (firstByte < 0x80) {
            codePoint = firstByte
          }
          break
        case 2:
          secondByte = buf[i + 1]
          if ((secondByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0x1F) << 0x6 | (secondByte & 0x3F)
            if (tempCodePoint > 0x7F) {
              codePoint = tempCodePoint
            }
          }
          break
        case 3:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0xC | (secondByte & 0x3F) << 0x6 | (thirdByte & 0x3F)
            if (tempCodePoint > 0x7FF && (tempCodePoint < 0xD800 || tempCodePoint > 0xDFFF)) {
              codePoint = tempCodePoint
            }
          }
          break
        case 4:
          secondByte = buf[i + 1]
          thirdByte = buf[i + 2]
          fourthByte = buf[i + 3]
          if ((secondByte & 0xC0) === 0x80 && (thirdByte & 0xC0) === 0x80 && (fourthByte & 0xC0) === 0x80) {
            tempCodePoint = (firstByte & 0xF) << 0x12 | (secondByte & 0x3F) << 0xC | (thirdByte & 0x3F) << 0x6 | (fourthByte & 0x3F)
            if (tempCodePoint > 0xFFFF && tempCodePoint < 0x110000) {
              codePoint = tempCodePoint
            }
          }
      }
    }

    if (codePoint === null) {
      // we did not generate a valid codePoint so insert a
      // replacement char (U+FFFD) and advance only 1 byte
      codePoint = 0xFFFD
      bytesPerSequence = 1
    } else if (codePoint > 0xFFFF) {
      // encode to utf16 (surrogate pair dance)
      codePoint -= 0x10000
      res.push(codePoint >>> 10 & 0x3FF | 0xD800)
      codePoint = 0xDC00 | codePoint & 0x3FF
    }

    res.push(codePoint)
    i += bytesPerSequence
  }

  return decodeCodePointsArray(res)
}

// Based on http://stackoverflow.com/a/22747272/680742, the browser with
// the lowest limit is Chrome, with 0x10000 args.
// We go 1 magnitude less, for safety
var MAX_ARGUMENTS_LENGTH = 0x1000

function decodeCodePointsArray (codePoints) {
  var len = codePoints.length
  if (len <= MAX_ARGUMENTS_LENGTH) {
    return String.fromCharCode.apply(String, codePoints) // avoid extra slice()
  }

  // Decode in chunks to avoid "call stack size exceeded".
  var res = ''
  var i = 0
  while (i < len) {
    res += String.fromCharCode.apply(
      String,
      codePoints.slice(i, i += MAX_ARGUMENTS_LENGTH)
    )
  }
  return res
}

function asciiSlice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i] & 0x7F)
  }
  return ret
}

function latin1Slice (buf, start, end) {
  var ret = ''
  end = Math.min(buf.length, end)

  for (var i = start; i < end; ++i) {
    ret += String.fromCharCode(buf[i])
  }
  return ret
}

function hexSlice (buf, start, end) {
  var len = buf.length

  if (!start || start < 0) start = 0
  if (!end || end < 0 || end > len) end = len

  var out = ''
  for (var i = start; i < end; ++i) {
    out += toHex(buf[i])
  }
  return out
}

function utf16leSlice (buf, start, end) {
  var bytes = buf.slice(start, end)
  var res = ''
  for (var i = 0; i < bytes.length; i += 2) {
    res += String.fromCharCode(bytes[i] + bytes[i + 1] * 256)
  }
  return res
}

Buffer.prototype.slice = function slice (start, end) {
  var len = this.length
  start = ~~start
  end = end === undefined ? len : ~~end

  if (start < 0) {
    start += len
    if (start < 0) start = 0
  } else if (start > len) {
    start = len
  }

  if (end < 0) {
    end += len
    if (end < 0) end = 0
  } else if (end > len) {
    end = len
  }

  if (end < start) end = start

  var newBuf
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    newBuf = this.subarray(start, end)
    newBuf.__proto__ = Buffer.prototype
  } else {
    var sliceLen = end - start
    newBuf = new Buffer(sliceLen, undefined)
    for (var i = 0; i < sliceLen; ++i) {
      newBuf[i] = this[i + start]
    }
  }

  return newBuf
}

/*
 * Need to make sure that buffer isn't trying to write out of bounds.
 */
function checkOffset (offset, ext, length) {
  if ((offset % 1) !== 0 || offset < 0) throw new RangeError('offset is not uint')
  if (offset + ext > length) throw new RangeError('Trying to access beyond buffer length')
}

Buffer.prototype.readUIntLE = function readUIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }

  return val
}

Buffer.prototype.readUIntBE = function readUIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    checkOffset(offset, byteLength, this.length)
  }

  var val = this[offset + --byteLength]
  var mul = 1
  while (byteLength > 0 && (mul *= 0x100)) {
    val += this[offset + --byteLength] * mul
  }

  return val
}

Buffer.prototype.readUInt8 = function readUInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  return this[offset]
}

Buffer.prototype.readUInt16LE = function readUInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return this[offset] | (this[offset + 1] << 8)
}

Buffer.prototype.readUInt16BE = function readUInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  return (this[offset] << 8) | this[offset + 1]
}

Buffer.prototype.readUInt32LE = function readUInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return ((this[offset]) |
      (this[offset + 1] << 8) |
      (this[offset + 2] << 16)) +
      (this[offset + 3] * 0x1000000)
}

Buffer.prototype.readUInt32BE = function readUInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] * 0x1000000) +
    ((this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    this[offset + 3])
}

Buffer.prototype.readIntLE = function readIntLE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var val = this[offset]
  var mul = 1
  var i = 0
  while (++i < byteLength && (mul *= 0x100)) {
    val += this[offset + i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readIntBE = function readIntBE (offset, byteLength, noAssert) {
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) checkOffset(offset, byteLength, this.length)

  var i = byteLength
  var mul = 1
  var val = this[offset + --i]
  while (i > 0 && (mul *= 0x100)) {
    val += this[offset + --i] * mul
  }
  mul *= 0x80

  if (val >= mul) val -= Math.pow(2, 8 * byteLength)

  return val
}

Buffer.prototype.readInt8 = function readInt8 (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 1, this.length)
  if (!(this[offset] & 0x80)) return (this[offset])
  return ((0xff - this[offset] + 1) * -1)
}

Buffer.prototype.readInt16LE = function readInt16LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset] | (this[offset + 1] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt16BE = function readInt16BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 2, this.length)
  var val = this[offset + 1] | (this[offset] << 8)
  return (val & 0x8000) ? val | 0xFFFF0000 : val
}

Buffer.prototype.readInt32LE = function readInt32LE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset]) |
    (this[offset + 1] << 8) |
    (this[offset + 2] << 16) |
    (this[offset + 3] << 24)
}

Buffer.prototype.readInt32BE = function readInt32BE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)

  return (this[offset] << 24) |
    (this[offset + 1] << 16) |
    (this[offset + 2] << 8) |
    (this[offset + 3])
}

Buffer.prototype.readFloatLE = function readFloatLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, true, 23, 4)
}

Buffer.prototype.readFloatBE = function readFloatBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 4, this.length)
  return ieee754.read(this, offset, false, 23, 4)
}

Buffer.prototype.readDoubleLE = function readDoubleLE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, true, 52, 8)
}

Buffer.prototype.readDoubleBE = function readDoubleBE (offset, noAssert) {
  if (!noAssert) checkOffset(offset, 8, this.length)
  return ieee754.read(this, offset, false, 52, 8)
}

function checkInt (buf, value, offset, ext, max, min) {
  if (!Buffer.isBuffer(buf)) throw new TypeError('"buffer" argument must be a Buffer instance')
  if (value > max || value < min) throw new RangeError('"value" argument is out of bounds')
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
}

Buffer.prototype.writeUIntLE = function writeUIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var mul = 1
  var i = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUIntBE = function writeUIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  byteLength = byteLength | 0
  if (!noAssert) {
    var maxBytes = Math.pow(2, 8 * byteLength) - 1
    checkInt(this, value, offset, byteLength, maxBytes, 0)
  }

  var i = byteLength - 1
  var mul = 1
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    this[offset + i] = (value / mul) & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeUInt8 = function writeUInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0xff, 0)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  this[offset] = (value & 0xff)
  return offset + 1
}

function objectWriteUInt16 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 2); i < j; ++i) {
    buf[offset + i] = (value & (0xff << (8 * (littleEndian ? i : 1 - i)))) >>>
      (littleEndian ? i : 1 - i) * 8
  }
}

Buffer.prototype.writeUInt16LE = function writeUInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeUInt16BE = function writeUInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0xffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

function objectWriteUInt32 (buf, value, offset, littleEndian) {
  if (value < 0) value = 0xffffffff + value + 1
  for (var i = 0, j = Math.min(buf.length - offset, 4); i < j; ++i) {
    buf[offset + i] = (value >>> (littleEndian ? i : 3 - i) * 8) & 0xff
  }
}

Buffer.prototype.writeUInt32LE = function writeUInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset + 3] = (value >>> 24)
    this[offset + 2] = (value >>> 16)
    this[offset + 1] = (value >>> 8)
    this[offset] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeUInt32BE = function writeUInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0xffffffff, 0)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

Buffer.prototype.writeIntLE = function writeIntLE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = 0
  var mul = 1
  var sub = 0
  this[offset] = value & 0xFF
  while (++i < byteLength && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i - 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeIntBE = function writeIntBE (value, offset, byteLength, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) {
    var limit = Math.pow(2, 8 * byteLength - 1)

    checkInt(this, value, offset, byteLength, limit - 1, -limit)
  }

  var i = byteLength - 1
  var mul = 1
  var sub = 0
  this[offset + i] = value & 0xFF
  while (--i >= 0 && (mul *= 0x100)) {
    if (value < 0 && sub === 0 && this[offset + i + 1] !== 0) {
      sub = 1
    }
    this[offset + i] = ((value / mul) >> 0) - sub & 0xFF
  }

  return offset + byteLength
}

Buffer.prototype.writeInt8 = function writeInt8 (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 1, 0x7f, -0x80)
  if (!Buffer.TYPED_ARRAY_SUPPORT) value = Math.floor(value)
  if (value < 0) value = 0xff + value + 1
  this[offset] = (value & 0xff)
  return offset + 1
}

Buffer.prototype.writeInt16LE = function writeInt16LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
  } else {
    objectWriteUInt16(this, value, offset, true)
  }
  return offset + 2
}

Buffer.prototype.writeInt16BE = function writeInt16BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 2, 0x7fff, -0x8000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 8)
    this[offset + 1] = (value & 0xff)
  } else {
    objectWriteUInt16(this, value, offset, false)
  }
  return offset + 2
}

Buffer.prototype.writeInt32LE = function writeInt32LE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value & 0xff)
    this[offset + 1] = (value >>> 8)
    this[offset + 2] = (value >>> 16)
    this[offset + 3] = (value >>> 24)
  } else {
    objectWriteUInt32(this, value, offset, true)
  }
  return offset + 4
}

Buffer.prototype.writeInt32BE = function writeInt32BE (value, offset, noAssert) {
  value = +value
  offset = offset | 0
  if (!noAssert) checkInt(this, value, offset, 4, 0x7fffffff, -0x80000000)
  if (value < 0) value = 0xffffffff + value + 1
  if (Buffer.TYPED_ARRAY_SUPPORT) {
    this[offset] = (value >>> 24)
    this[offset + 1] = (value >>> 16)
    this[offset + 2] = (value >>> 8)
    this[offset + 3] = (value & 0xff)
  } else {
    objectWriteUInt32(this, value, offset, false)
  }
  return offset + 4
}

function checkIEEE754 (buf, value, offset, ext, max, min) {
  if (offset + ext > buf.length) throw new RangeError('Index out of range')
  if (offset < 0) throw new RangeError('Index out of range')
}

function writeFloat (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 4, 3.4028234663852886e+38, -3.4028234663852886e+38)
  }
  ieee754.write(buf, value, offset, littleEndian, 23, 4)
  return offset + 4
}

Buffer.prototype.writeFloatLE = function writeFloatLE (value, offset, noAssert) {
  return writeFloat(this, value, offset, true, noAssert)
}

Buffer.prototype.writeFloatBE = function writeFloatBE (value, offset, noAssert) {
  return writeFloat(this, value, offset, false, noAssert)
}

function writeDouble (buf, value, offset, littleEndian, noAssert) {
  if (!noAssert) {
    checkIEEE754(buf, value, offset, 8, 1.7976931348623157E+308, -1.7976931348623157E+308)
  }
  ieee754.write(buf, value, offset, littleEndian, 52, 8)
  return offset + 8
}

Buffer.prototype.writeDoubleLE = function writeDoubleLE (value, offset, noAssert) {
  return writeDouble(this, value, offset, true, noAssert)
}

Buffer.prototype.writeDoubleBE = function writeDoubleBE (value, offset, noAssert) {
  return writeDouble(this, value, offset, false, noAssert)
}

// copy(targetBuffer, targetStart=0, sourceStart=0, sourceEnd=buffer.length)
Buffer.prototype.copy = function copy (target, targetStart, start, end) {
  if (!start) start = 0
  if (!end && end !== 0) end = this.length
  if (targetStart >= target.length) targetStart = target.length
  if (!targetStart) targetStart = 0
  if (end > 0 && end < start) end = start

  // Copy 0 bytes; we're done
  if (end === start) return 0
  if (target.length === 0 || this.length === 0) return 0

  // Fatal error conditions
  if (targetStart < 0) {
    throw new RangeError('targetStart out of bounds')
  }
  if (start < 0 || start >= this.length) throw new RangeError('sourceStart out of bounds')
  if (end < 0) throw new RangeError('sourceEnd out of bounds')

  // Are we oob?
  if (end > this.length) end = this.length
  if (target.length - targetStart < end - start) {
    end = target.length - targetStart + start
  }

  var len = end - start
  var i

  if (this === target && start < targetStart && targetStart < end) {
    // descending copy from end
    for (i = len - 1; i >= 0; --i) {
      target[i + targetStart] = this[i + start]
    }
  } else if (len < 1000 || !Buffer.TYPED_ARRAY_SUPPORT) {
    // ascending copy from start
    for (i = 0; i < len; ++i) {
      target[i + targetStart] = this[i + start]
    }
  } else {
    Uint8Array.prototype.set.call(
      target,
      this.subarray(start, start + len),
      targetStart
    )
  }

  return len
}

// Usage:
//    buffer.fill(number[, offset[, end]])
//    buffer.fill(buffer[, offset[, end]])
//    buffer.fill(string[, offset[, end]][, encoding])
Buffer.prototype.fill = function fill (val, start, end, encoding) {
  // Handle string cases:
  if (typeof val === 'string') {
    if (typeof start === 'string') {
      encoding = start
      start = 0
      end = this.length
    } else if (typeof end === 'string') {
      encoding = end
      end = this.length
    }
    if (val.length === 1) {
      var code = val.charCodeAt(0)
      if (code < 256) {
        val = code
      }
    }
    if (encoding !== undefined && typeof encoding !== 'string') {
      throw new TypeError('encoding must be a string')
    }
    if (typeof encoding === 'string' && !Buffer.isEncoding(encoding)) {
      throw new TypeError('Unknown encoding: ' + encoding)
    }
  } else if (typeof val === 'number') {
    val = val & 255
  }

  // Invalid ranges are not set to a default, so can range check early.
  if (start < 0 || this.length < start || this.length < end) {
    throw new RangeError('Out of range index')
  }

  if (end <= start) {
    return this
  }

  start = start >>> 0
  end = end === undefined ? this.length : end >>> 0

  if (!val) val = 0

  var i
  if (typeof val === 'number') {
    for (i = start; i < end; ++i) {
      this[i] = val
    }
  } else {
    var bytes = Buffer.isBuffer(val)
      ? val
      : utf8ToBytes(new Buffer(val, encoding).toString())
    var len = bytes.length
    for (i = 0; i < end - start; ++i) {
      this[i + start] = bytes[i % len]
    }
  }

  return this
}

// HELPER FUNCTIONS
// ================

var INVALID_BASE64_RE = /[^+\/0-9A-Za-z-_]/g

function base64clean (str) {
  // Node strips out invalid characters like \n and \t from the string, base64-js does not
  str = stringtrim(str).replace(INVALID_BASE64_RE, '')
  // Node converts strings with length < 2 to ''
  if (str.length < 2) return ''
  // Node allows for non-padded base64 strings (missing trailing ===), base64-js does not
  while (str.length % 4 !== 0) {
    str = str + '='
  }
  return str
}

function stringtrim (str) {
  if (str.trim) return str.trim()
  return str.replace(/^\s+|\s+$/g, '')
}

function toHex (n) {
  if (n < 16) return '0' + n.toString(16)
  return n.toString(16)
}

function utf8ToBytes (string, units) {
  units = units || Infinity
  var codePoint
  var length = string.length
  var leadSurrogate = null
  var bytes = []

  for (var i = 0; i < length; ++i) {
    codePoint = string.charCodeAt(i)

    // is surrogate component
    if (codePoint > 0xD7FF && codePoint < 0xE000) {
      // last char was a lead
      if (!leadSurrogate) {
        // no lead yet
        if (codePoint > 0xDBFF) {
          // unexpected trail
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        } else if (i + 1 === length) {
          // unpaired lead
          if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
          continue
        }

        // valid lead
        leadSurrogate = codePoint

        continue
      }

      // 2 leads in a row
      if (codePoint < 0xDC00) {
        if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
        leadSurrogate = codePoint
        continue
      }

      // valid surrogate pair
      codePoint = (leadSurrogate - 0xD800 << 10 | codePoint - 0xDC00) + 0x10000
    } else if (leadSurrogate) {
      // valid bmp char, but last char was a lead
      if ((units -= 3) > -1) bytes.push(0xEF, 0xBF, 0xBD)
    }

    leadSurrogate = null

    // encode utf8
    if (codePoint < 0x80) {
      if ((units -= 1) < 0) break
      bytes.push(codePoint)
    } else if (codePoint < 0x800) {
      if ((units -= 2) < 0) break
      bytes.push(
        codePoint >> 0x6 | 0xC0,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x10000) {
      if ((units -= 3) < 0) break
      bytes.push(
        codePoint >> 0xC | 0xE0,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else if (codePoint < 0x110000) {
      if ((units -= 4) < 0) break
      bytes.push(
        codePoint >> 0x12 | 0xF0,
        codePoint >> 0xC & 0x3F | 0x80,
        codePoint >> 0x6 & 0x3F | 0x80,
        codePoint & 0x3F | 0x80
      )
    } else {
      throw new Error('Invalid code point')
    }
  }

  return bytes
}

function asciiToBytes (str) {
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    // Node's code seems to be doing this and not & 0x7F..
    byteArray.push(str.charCodeAt(i) & 0xFF)
  }
  return byteArray
}

function utf16leToBytes (str, units) {
  var c, hi, lo
  var byteArray = []
  for (var i = 0; i < str.length; ++i) {
    if ((units -= 2) < 0) break

    c = str.charCodeAt(i)
    hi = c >> 8
    lo = c % 256
    byteArray.push(lo)
    byteArray.push(hi)
  }

  return byteArray
}

function base64ToBytes (str) {
  return base64.toByteArray(base64clean(str))
}

function blitBuffer (src, dst, offset, length) {
  for (var i = 0; i < length; ++i) {
    if ((i + offset >= dst.length) || (i >= src.length)) break
    dst[i + offset] = src[i]
  }
  return i
}

function isnan (val) {
  return val !== val // eslint-disable-line no-self-compare
}

/* WEBPACK VAR INJECTION */}.call(exports, __webpack_require__(3)))

/***/ }),
/* 3 */
/***/ (function(module, exports) {

var g;

// This works in non-strict mode
g = (function() {
	return this;
})();

try {
	// This works if eval is allowed (see CSP)
	g = g || Function("return this")() || (1,eval)("this");
} catch(e) {
	// This works if the window reference is available
	if(typeof window === "object")
		g = window;
}

// g can still be undefined, but nothing to do about it...
// We return undefined, instead of nothing here, so it's
// easier to handle this case. if(!global) { ...}

module.exports = g;


/***/ }),
/* 4 */
/***/ (function(module, exports, __webpack_require__) {

"use strict";


exports.byteLength = byteLength
exports.toByteArray = toByteArray
exports.fromByteArray = fromByteArray

var lookup = []
var revLookup = []
var Arr = typeof Uint8Array !== 'undefined' ? Uint8Array : Array

var code = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
for (var i = 0, len = code.length; i < len; ++i) {
  lookup[i] = code[i]
  revLookup[code.charCodeAt(i)] = i
}

revLookup['-'.charCodeAt(0)] = 62
revLookup['_'.charCodeAt(0)] = 63

function placeHoldersCount (b64) {
  var len = b64.length
  if (len % 4 > 0) {
    throw new Error('Invalid string. Length must be a multiple of 4')
  }

  // the number of equal signs (place holders)
  // if there are two placeholders, than the two characters before it
  // represent one byte
  // if there is only one, then the three characters before it represent 2 bytes
  // this is just a cheap hack to not do indexOf twice
  return b64[len - 2] === '=' ? 2 : b64[len - 1] === '=' ? 1 : 0
}

function byteLength (b64) {
  // base64 is 4/3 + up to two characters of the original data
  return (b64.length * 3 / 4) - placeHoldersCount(b64)
}

function toByteArray (b64) {
  var i, l, tmp, placeHolders, arr
  var len = b64.length
  placeHolders = placeHoldersCount(b64)

  arr = new Arr((len * 3 / 4) - placeHolders)

  // if there are placeholders, only get up to the last complete 4 chars
  l = placeHolders > 0 ? len - 4 : len

  var L = 0

  for (i = 0; i < l; i += 4) {
    tmp = (revLookup[b64.charCodeAt(i)] << 18) | (revLookup[b64.charCodeAt(i + 1)] << 12) | (revLookup[b64.charCodeAt(i + 2)] << 6) | revLookup[b64.charCodeAt(i + 3)]
    arr[L++] = (tmp >> 16) & 0xFF
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  if (placeHolders === 2) {
    tmp = (revLookup[b64.charCodeAt(i)] << 2) | (revLookup[b64.charCodeAt(i + 1)] >> 4)
    arr[L++] = tmp & 0xFF
  } else if (placeHolders === 1) {
    tmp = (revLookup[b64.charCodeAt(i)] << 10) | (revLookup[b64.charCodeAt(i + 1)] << 4) | (revLookup[b64.charCodeAt(i + 2)] >> 2)
    arr[L++] = (tmp >> 8) & 0xFF
    arr[L++] = tmp & 0xFF
  }

  return arr
}

function tripletToBase64 (num) {
  return lookup[num >> 18 & 0x3F] + lookup[num >> 12 & 0x3F] + lookup[num >> 6 & 0x3F] + lookup[num & 0x3F]
}

function encodeChunk (uint8, start, end) {
  var tmp
  var output = []
  for (var i = start; i < end; i += 3) {
    tmp = (uint8[i] << 16) + (uint8[i + 1] << 8) + (uint8[i + 2])
    output.push(tripletToBase64(tmp))
  }
  return output.join('')
}

function fromByteArray (uint8) {
  var tmp
  var len = uint8.length
  var extraBytes = len % 3 // if we have 1 byte left, pad 2 bytes
  var output = ''
  var parts = []
  var maxChunkLength = 16383 // must be multiple of 3

  // go through the array every three bytes, we'll deal with trailing stuff later
  for (var i = 0, len2 = len - extraBytes; i < len2; i += maxChunkLength) {
    parts.push(encodeChunk(uint8, i, (i + maxChunkLength) > len2 ? len2 : (i + maxChunkLength)))
  }

  // pad the end with zeros, but make sure to not forget the extra bytes
  if (extraBytes === 1) {
    tmp = uint8[len - 1]
    output += lookup[tmp >> 2]
    output += lookup[(tmp << 4) & 0x3F]
    output += '=='
  } else if (extraBytes === 2) {
    tmp = (uint8[len - 2] << 8) + (uint8[len - 1])
    output += lookup[tmp >> 10]
    output += lookup[(tmp >> 4) & 0x3F]
    output += lookup[(tmp << 2) & 0x3F]
    output += '='
  }

  parts.push(output)

  return parts.join('')
}


/***/ }),
/* 5 */
/***/ (function(module, exports) {

exports.read = function (buffer, offset, isLE, mLen, nBytes) {
  var e, m
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var nBits = -7
  var i = isLE ? (nBytes - 1) : 0
  var d = isLE ? -1 : 1
  var s = buffer[offset + i]

  i += d

  e = s & ((1 << (-nBits)) - 1)
  s >>= (-nBits)
  nBits += eLen
  for (; nBits > 0; e = e * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  m = e & ((1 << (-nBits)) - 1)
  e >>= (-nBits)
  nBits += mLen
  for (; nBits > 0; m = m * 256 + buffer[offset + i], i += d, nBits -= 8) {}

  if (e === 0) {
    e = 1 - eBias
  } else if (e === eMax) {
    return m ? NaN : ((s ? -1 : 1) * Infinity)
  } else {
    m = m + Math.pow(2, mLen)
    e = e - eBias
  }
  return (s ? -1 : 1) * m * Math.pow(2, e - mLen)
}

exports.write = function (buffer, value, offset, isLE, mLen, nBytes) {
  var e, m, c
  var eLen = nBytes * 8 - mLen - 1
  var eMax = (1 << eLen) - 1
  var eBias = eMax >> 1
  var rt = (mLen === 23 ? Math.pow(2, -24) - Math.pow(2, -77) : 0)
  var i = isLE ? 0 : (nBytes - 1)
  var d = isLE ? 1 : -1
  var s = value < 0 || (value === 0 && 1 / value < 0) ? 1 : 0

  value = Math.abs(value)

  if (isNaN(value) || value === Infinity) {
    m = isNaN(value) ? 1 : 0
    e = eMax
  } else {
    e = Math.floor(Math.log(value) / Math.LN2)
    if (value * (c = Math.pow(2, -e)) < 1) {
      e--
      c *= 2
    }
    if (e + eBias >= 1) {
      value += rt / c
    } else {
      value += rt * Math.pow(2, 1 - eBias)
    }
    if (value * c >= 2) {
      e++
      c /= 2
    }

    if (e + eBias >= eMax) {
      m = 0
      e = eMax
    } else if (e + eBias >= 1) {
      m = (value * c - 1) * Math.pow(2, mLen)
      e = e + eBias
    } else {
      m = value * Math.pow(2, eBias - 1) * Math.pow(2, mLen)
      e = 0
    }
  }

  for (; mLen >= 8; buffer[offset + i] = m & 0xff, i += d, m /= 256, mLen -= 8) {}

  e = (e << mLen) | m
  eLen += mLen
  for (; eLen > 0; buffer[offset + i] = e & 0xff, i += d, e /= 256, eLen -= 8) {}

  buffer[offset + i - d] |= s * 128
}


/***/ }),
/* 6 */
/***/ (function(module, exports) {

var toString = {}.toString;

module.exports = Array.isArray || function (arr) {
  return toString.call(arr) == '[object Array]';
};


/***/ }),
/* 7 */
/***/ (function(module, exports) {

module.exports = {"e":"AQAB","kty":"RSA","n":"3nI-DQ7NoUZCvT348Vi4JfGC1h6R3Qf_yXR0dKM5DmwsuQMxguce6sZ28GWQHJjgbdcs8nTuNQihyVtr9vLsoKUVSmPs_a3QEGXEhTpuTtm7cCb_7HyAlwGtysn2AsdElG8HsDFWlZmiDaHTrTmdLnuk-Z3GRg4nnA4xs4vvUuh0fCVIKoSMFyt3Tkc6IBWJ9X3XrDEbSPrghXV7Cu8LMK3Y4avy6rjEGjWXL-WqIPhiYJcBiFnCcqUCMPvdW7Fs9B36asc_2EQAM5d7BAiBwMjoosSyU6b4JGpI530c3xhqLbX00q1ePCG732cIwp0-bGWV_q0FpQX2M9cNv2Ax4Q"}

/***/ })
/******/ ])));
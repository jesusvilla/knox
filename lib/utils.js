"use strict";

/*!
 * knox - utils
 * Copyright(c) 2010 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */
const crypto = require('crypto')
const { SHA1 } = require('jshashes');
const xmlParser = require('fast-xml-parser');

/**
 * Merge object `b` with object `a`.
 *
 * @param {Object} a
 * @param {Object} b
 * @return {Object} a
 * @api private
 */

exports.merge = function (a, b) {
  const keys = Object.keys(b);
  keys.forEach((key) => {
    a[key] = b[key];
  })
  return a;
};

/**
 * Base64.
 */

exports.base64 = {

  /**
   * Base64 encode the given `str`.
   *
   * @param {String} str
   * @return {String}
   * @api private
   */

  encode (str) {
    return Buffer.from(str, 'utf8').toString('base64');
  },

  /**
   * Base64 decode the given `str`.
   *
   * @param {String} str
   * @return {String}
   * @api private
   */

  decode (str) {
    return Buffer.from(str, 'base64').toString('utf8');
  }
};


exports.crypto = {
  /**
   * Simple HMAC-SHA1 Wrapper
   *
   * @param {Object} options
   * @param {String} options.secret
   * @param {String} options.message
   * @return {String}
   * @api private
   */

  hmacSha1 ({ secret, message }) {
    return new SHA1().b64_hmac(secret, message);
  };
  
  /**
   * Simple MD5 Wrapper
   * @param {String} str
   * @return {String}
   * @api private
   */

  md5 (str) {
    // return new MD5().b64(str); // is slower
    return crypto.createHash('md5').update(xml).digest('base64');
  }
}

/**
 * streamCounter
 * @param {Stream.Readable} readable
 * @param {Function} cb
 * @returns void
 */
// @doc: https://github.com/andrewrk/node-stream-counter/blob/master/index.js
exports.streamCounter = function (readable, cb) {
  let bytes = 0;

  readable.on('data', (chunk) => {
    bytes += chunk.length;
    cb(bytes);
  })
}

/**
 * Once function
 * @param {Function} cb
 * @returns {Function}
 * @doc: https://github.com/isaacs/once
 */
exports.once = function (cb) {
  const f = function () {
    if (f.called) return f.value
    f.called = true
    return f.value = cb.apply(this, arguments)
  }
  f.called = false
  return f
}

/**
 * XML2JS by fast-xml-parser
 * @param {String} xml
 * @doc https://github.com/Leonidas-from-XIV/node-xml2js#options
 * @doc https://github.com/NaturalIntelligence/fast-xml-parser#xml-to-json
 */
const options = {
  attributeNamePrefix : '@_',
  attrNodeName: false,
  textNodeName : '#text',
  ignoreAttributes : true,
  ignoreNameSpace : false,
  allowBooleanAttributes : false,
  parseNodeValue : true,
  parseAttributeValue : false,
  trimValues: true,
  arrayMode: false,
  cdataTagName: '__cdata',
  cdataPositionChar: '\\c',
  attrValueProcessor: a => a.toUpperCase(),
  tagValueProcessor : a => a.toUpperCase()
}
exports.xml2js = function (xml, cb) {
  /* new xml2js.Parser({ explicitArray: false, explicitRoot: false })
    .parseString(xml, cb) */

  try {
    cb(null, xmlParser.parse(xml, options, true));
  } catch (error) {
    cb(error)
  }
}
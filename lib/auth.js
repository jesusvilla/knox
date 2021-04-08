"use strict";

/*!
 * knox - auth
 * Copyright(c) 2010 LearnBoost <dev@learnboost.com>
 * MIT Licensed
 */

/**
 * Module dependencies.
 */
const { parse } = require('url');
const { crypto } = require('./utils')

/**
 * Query string params permitted in the canonicalized resource.
 * @see http://docs.amazonwebservices.com/AmazonS3/latest/dev/RESTAuthentication.html#ConstructingTheCanonicalizedResourceElement
 */

const whitelist = [
  'acl',
  'delete',
  'lifecycle',
  'location',
  'logging',
  'notification',
  'partNumber',
  'policy',
  'requestPayment',
  'torrent',
  'uploadId',
  'uploads',
  'versionId',
  'versioning',
  'versions',
  'website'
];

/**
 * Return an "Authorization" header value with the given `options`
 * in the form of "AWS <key>:<signature>"
 *
 * @param {Object} options
 * @return {String}
 * @api private
 */

exports.authorization = function (options) {
  return 'AWS ' + options.key + ':' + exports.sign(options);
};

/**
 * Create a base64 sha1 HMAC for `options`.
 *
 * @param {Object} options
 * @return {String}
 * @api private
 */

exports.sign = function (options) {
  options.message = exports.stringToSign(options);
  return crypto.hmacSha1(options);
};

/**
 * Create a base64 sha1 HMAC for `options`.
 *
 * Specifically to be used with S3 presigned URLs
 *
 * @param {Object} options
 * @return {String}
 * @api private
 */

exports.signQuery = function (options) {
  options.message = exports.queryStringToSign(options);
  return crypto.hmacSha1(options);
};

/**
 * Return a string for sign() with the given `options`.
 *
 * Spec:
 *
 *    <verb>\n
 *    <md5>\n
 *    <content-type>\n
 *    <date>\n
 *    [headers\n]
 *    <resource>
 *
 * @param {Object} options
 * 
 * @param {String} options.amazonHeaders
 * @param {String} options.verb
 * @param {String} options.md5
 * @param {String} options.contentType
 * @param {String} options.date
 * @param {String} options.resource
 * 
 * @return {String}
 * @api private
 */

exports.stringToSign = function ({ amazonHeaders, verb, md5, contentType, date, resource }) {
  const headers = amazonHeaders ? amazonHeaders + '\n' : '';
  
  return [
      verb
    , md5
    , contentType
    , date instanceof Date ? date.toUTCString() : date
    , headers + resource
  ].join('\n');
};

/**
 * Return a string for sign() with the given `options`, but is meant exclusively
 * for S3 presigned URLs
 *
 * Spec:
 *
 *    <verb>\n\n
 *    <contentType or nothing>\n
 *    <date>\n
 *    <x-amz-security-token header>\n --- optional
 *    <resource>
 *
 * @param {Object} options
 * @return {String}
 * @api private
 */

exports.queryStringToSign = function ({ verb = 'GET', contentType = '', date, extraHeaders, token, resource }) {
  return verb + '\n\n' +
    contentType + '\n' +
    date + '\n' +
    (extraHeaders !== undefined ? exports.canonicalizeHeaders(extraHeaders) + '\n' : '') +
    (token !== undefined ? 'x-amz-security-token:' + token + '\n' : '') +
    resource;
};

/**
 * Perform the following:
 *
 *  - ignore non-amazon headers
 *  - lowercase fields
 *  - sort lexicographically
 *  - trim whitespace between ":"
 *  - join with newline
 *
 * @param {Object} headers
 * @return {String}
 * @api private
 */

exports.canonicalizeHeaders = function (headers) {
  let res = '';
  // Headers are sorted lexigraphically based on the header name only.
  const fields = Object.keys(headers).sort();

  fields.forEach((field) => {
    const value = headers[field];
    field = field.toLowerCase();

    if (field === 'x-amz-date' || field.indexOf('x-amz') !== 0) {
      return;
    }

    res += (res !== '' ? '\n' : '') + field + ':' + value;
  })

  return res;
};

/**
 * Perform the following:
 *
 *  - ignore non sub-resources
 *  - sort lexicographically
 *
 * @param {String} a URI-encoded resource (path + query string)
 * @return {String}
 * @api private
 */

exports.canonicalizeResource = function (resource) {
  const url = parse(resource, true)
    , path = url.pathname
    , buf = [];

  // apply the query string whitelist
  Object.keys(url.query).forEach((key) => {
    if (whitelist.indexOf(key) !== -1) {
      buf.push(key + (url.query[key] ? '=' + url.query[key] : ''));
    }
  });

  return path + (buf.length !== 0
    ? '?' + buf.sort().join('&')
    : '');
};

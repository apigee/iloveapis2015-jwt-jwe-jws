/*
 * Copyright 2014 Apigee Corporation.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */
 /* jshint node: true */

'use strict';

var apigee = require('./index');
var url = require('url');

var oauth;
try {
  oauth = require('apigee-internal-oauth-2');
} catch (e) {
  // We will get here if the Node.js code is ahead version-wise of the runtime
  throw new Error('OAuth support is not available in this version of Edge.');
}

/*
 * Expected options:
 *   clientId, clientSecret
 *   grantType
 *   scope (optional)
 *   username, password (password grant type)
 *   code (authorization code)
 *   redirectUri, state (implicit grant, authorization code)
 *   tokenType (implicit grant, authorization code)
 */
module.exports.generateAccessToken = function(opts, cb) {
  if (typeof opts !== 'object') {
    throw new Error('opts must be an Object');
  }
  if (typeof cb !== 'function') {
    throw new Error('Callback must be a function');
  }

  oauth.generateAccessToken(process.env._APIGEE_APP_ID, opts, function(err, result) {
    cb(err, result);
  });
};

/*
 * Expected options:
 *   clientId
 *   redirectUri
 */
module.exports.generateAuthorizationCode = function(opts, cb) {
  if (typeof opts !== 'object') {
    throw new Error('opts must be an Object');
  }
  if (typeof cb !== 'function') {
    throw new Error('Callback must be a function');
  }

  oauth.generateAuthorizationCode(process.env._APIGEE_APP_ID, opts, function(err, result) {
    cb(err, result);
  });
};

/*
 * Expected options:
 *   clientId, clientSecret
 *   token
 */
module.exports.revokeToken = function(opts, cb) {
  if (typeof opts !== 'object') {
    throw new Error('opts must be an Object');
  }
  if (typeof cb !== 'function') {
    throw new Error('Callback must be a function');
  }

  oauth.revokeToken(process.env._APIGEE_APP_ID, opts, function(err) {
    cb(err);
  });
};

/*
 * Expected options:
 *   token
 *   scopes (array, optional)
 */
module.exports.verifyAccessToken = function(req, opts, cb) {
  if (req && (typeof req !== 'object')) {
    throw new Error('req must be an Http request object');
  }
  if (typeof opts !== 'object') {
    throw new Error('opts must be an Object');
  }
  if (typeof cb !== 'function') {
    throw new Error('Callback must be a function');
  }

  oauth.verifyAccessToken(process.env._APIGEE_APP_ID, req, opts, function(err, result) {
    cb(err, result);
  });
};

/*
 * Expected options:
 *   apiKey
 */
module.exports.verifyApiKey = function(req, opts, cb) {
  if (req && (typeof req !== 'object')) {
    throw new Error('req must be an Http request object');
  }
  if (typeof opts !== 'object') {
    throw new Error('opts must be an Object');
  }
  if (typeof cb !== 'function') {
    throw new Error('Callback must be a function');
  }

  oauth.verifyApiKey(process.env._APIGEE_APP_ID, req, opts, function(err, result) {
    cb(err, result);
  });
};

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

'use strict';

var apigeeVault;

try {
  apigeeVault = require('apigee-internal-secure-store');
} catch (e) {
  // We will get here if not on Apigee or on an older version
  throw new Error('This version of Edge does not support the vault');
}

module.exports.getOrganizationVault = function(name) {
  return new Vault(name, false);
};

module.exports.getEnvironmentVault = function(name) {
  return new Vault(name, true);
};

function Vault(name, environmentScope) {
  this.name = name;
  this.environmentScope = environmentScope;
}

Vault.prototype.getKeys = function(cb) {
  apigeeVault.getKeys(process.env._APIGEE_APP_ID, this.name,
                      this.environmentScope, function(err, keys) {
    cb(err, keys);
  });
};

Vault.prototype.get = function(key, cb) {
  apigeeVault.getKey(process.env._APIGEE_APP_ID, key, this.name,
                     this.environmentScope, function(err, value) {
    cb(err, value);
  });
};

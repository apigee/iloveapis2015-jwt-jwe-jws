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

var fs = require('fs');
var path = require('path');
var util = require('util');

// Mode support -- determine whether we are running native to Apigee

var APIGEE_MODE = 'apigee';
var STANDALONE_MODE = 'standalone';

module.exports.APIGEE_MODE = APIGEE_MODE;
module.exports.STANDALONE_MODE = STANDALONE_MODE;

var mode;
var variables;
try {
  variables = require('apigee-internal-variables');
  mode = APIGEE_MODE;

} catch (external) {
  mode = STANDALONE_MODE;
}

module.exports.getMode = function() {
  return mode;
};

// Version support -- read the version number from our package.json file

var moduleVersion = '0.0.0';

try {
  var pkg = fs.readFileSync(path.join(__dirname, '../package.json'));
  var packageJson = JSON.parse(pkg);
  if (packageJson) {
    moduleVersion = packageJson.version;
  }
} catch (e) {
  // Error reading package.json -- just leave the default
  console.error('Error reading package.json: %s', e);
}

module.exports.getVersion = function() {
  return moduleVersion;
};

// Variable support -- get and set flow variables

var getVariable;
var setVariable;
var deleteVariable;

if (mode === APIGEE_MODE) {
  // If we are running inside Apigee, then we use the native module
  getVariable = function(request, v) {
    return variables.get(request, v);
  };

  setVariable = function(request, v, value) {
    variables.set(request, v, value);
  };

  deleteVariable = function(request, v) {
    variables.remove(request, v);
  };

} else {
  // If we are running outside Apigee, then we use this built-in support
  getVariable = function(request, v) {
    return getContext(request).variables[v];
  };

  setVariable = function(request, v, value) {
    var vars = getContext(request).variables;
    var desc = Object.getOwnPropertyDescriptor(vars, v);
    if (desc && !desc.writable) {
      throw new Error('Read only variable');
    }
    vars[v] = value;
  };

  deleteVariable = function(request, v) {
    var vars = getContext(request).variables;
    var desc = Object.getOwnPropertyDescriptor(vars, v);
    if (desc && !desc.writable) {
      throw new Error('Read only variable');
    }
    delete vars[v];
  };

}

module.exports.getVariable = function(request, key) {
  if (typeof request !== 'object') {
    throw new Error('request must be a valid HTTP request');
  }
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  return getVariable(request, key);
};

module.exports.setVariable = function(request, key, value) {
  if (typeof request !== 'object') {
    throw new Error('request must be a valid HTTP request');
  }
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }

  var realValue;
  if ((value === undefined) || (value === null) ) {
    realValue = null;
  } else if ((typeof value !== 'string') && (typeof value !== 'number') &&
             (typeof value !== 'boolean')) {
    throw new Error('value must be string, number, or boolean');
  } else {
    realValue = value;
  }

  setVariable(request, key, realValue);
};

module.exports.setIntVariable = function(request, key, value) {
  if (typeof request !== 'object') {
    throw new Error('request must be a valid HTTP request');
  }
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }

  var realValue;
  if (typeof value === 'number') {
    realValue = Math.round(value);
  } else if (typeof value === 'string') {
    realValue = parseInt(value);
  } else {
    throw new Error('value must be a string, number, or boolean');
  }
  setVariable(request, key, realValue);
};

module.exports.deleteVariable = function(request, key) {
  if (typeof request !== 'object') {
    throw new Error('request must be a valid HTTP request');
  }
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  deleteVariable(request, key);
};

function getContext(request) {
  var att = request._apigeeAttachment;
  if (!att) {
    att = { variables: {} };
    request._apigeeAttachment = att;
    setPreDefinedVariables(att.variables);
  }
  return att;
}

function setPreDefinedVariables(v) {
  var now = new Date();

  Object.defineProperty(v, 'client.received.start.timestamp',
    { value: now.getTime(), writable: false });
  Object.defineProperty(v, 'client.received.end.timestamp',
    { value: now.getTime(), writable: false });
  Object.defineProperty(v, 'client.received.start.time',
    { value: now.toString(), writable: false });
  Object.defineProperty(v, 'client.received.end.time',
    { value: now.toString(), writable: false });
}

// Cache support

var caches = {};

module.exports.getCache = function(name, config) {
  if (caches[name]) {
    return caches[name];
  }
  caches[name] = require('./cache').createCache(name, mode, config);
  return caches[name];
};

// vault

module.exports.getVault = function(name, s) {
  var scope = (s ? s : 'organization');
  if (scope === 'organization') {
    return require('./vault').getOrganizationVault(name);
  }
  if (scope === 'environment') {
    return require('./vault').getEnvironmentVault(name);
  }
  throw new Error(util.format('Invalid scope %s', scope));
};

// Quota

module.exports.getQuota = function(o) {
  var opts = o ? o : {};
  if (opts.syncInterval && (typeof opts.syncInterval !== 'number')) {
    throw new Error('syncInterval must be a number');
  }

  return require('./quota').createQuota(opts);
};

// OAuth

module.exports.getOAuth = function() {
  return require('./oauth');
};

// Analytics

module.exports.getAnalytics = function() {
  return require('./analytics');
};

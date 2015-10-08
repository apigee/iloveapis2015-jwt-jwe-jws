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
 
function createCache(name, mode, config) {
  return new Cache(name, mode, config);
}

module.exports.createCache = createCache;

function Cache(name, mode, config) {
  this.name = name;
  
  if (mode === 'apigee') {
    var apigeeCache = require('apigee-internal-cache');
    var realConfig = (config ? config : {});
    
    // Apply defaults
    realConfig.name = name;
    if (!realConfig.scope) {
      realConfig.scope = 'exclusive';
    }
    
    this.impl = 
      apigeeCache.createCache(process.env._APIGEE_APP_ID, realConfig);
  } else {
    this.objects = {};
  }
}

Cache.prototype.get = function(key, cb) {
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  if (typeof cb !== 'function') {
    throw new Error('callback must be a function');
  }
  
  if (this.impl) {
    this.impl.get(key, function(err, item) {
        cb(err, item);
    });
    
  } else {
    var item = this.objects[key];
    cb(undefined, item);
  }
};

Cache.prototype.put = function(key, data, ttl, cb) {
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  
  if (typeof ttl === 'function') {
    // key, data, cb
    cb = ttl;
    ttl = undefined;
  }
  
  if (ttl && (typeof ttl !== 'number')) {
    throw new Error('ttl must be a number');
  }
  if (cb && (typeof cb !== 'function')) {
    throw new Error('callback must be a function');
  }
  
  var buf;
  if (data instanceof Buffer) {
    buf = data;
  } else if (typeof data === 'string') {
    buf = data;
  } else if (typeof data === 'object') {
    buf = JSON.stringify(data);
  } else {
    throw new Error('data must be a String, Buffer, or object');
  }
  
  if (this.impl) {
    this.impl.put(key, buf, ttl, function(err) {
        if (cb) {
          cb(err);
        }
    });
    
  } else {
    this.objects[key] = buf;
    if (cb) {
      cb();
    }
  }
};

Cache.prototype.remove = function(key, cb) {
  if (typeof key !== 'string') {
    throw new Error('key must be a string');
  }
  if (cb && (typeof cb !== 'function')) {
    throw new Error('callback must be a function');
  }
  
  if (this.impl) {
    this.impl.remove(key, function(err) {
        if (cb) {
          cb(err);
        }
    });
  
  } else {
    delete this.objects[key];
    if (cb) {
      cb();
    }
  }
};



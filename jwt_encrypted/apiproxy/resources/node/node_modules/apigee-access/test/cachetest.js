/*
 * Copyright 2013 Apigee Corporation.
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

var apigee = require('..');
var assert = require('assert');

describe('Apigee Access Cache', function() {
    it('Default Cache', function(done) {
        var cache = apigee.getCache();
        cache.put('key', 'Hello', function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            assert.equal(val, 'Hello');
            done();
          });
        });  
    });
    
    it('Cache String', function(done) {
        var cache = apigee.getCache();
        cache.put('key', 'Hello3', function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            assert.equal(val, 'Hello3');
            done();
          });
        });  
    });
    
    it('Cache Buffer', function(done) {
        var cache = apigee.getCache();
        var buf = new Buffer('Hello3', 'ascii');
        cache.put('key', buf, function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            assert.deepEqual(val, buf);
            done();
          });
        });  
    });
    
    it('Object Encoding', function(done) {
        var cache = apigee.getCache();
        var obj = { foo: 123, bar: 'Baz', tweety: true };
        cache.put('key', obj, function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            var result = JSON.parse(val);
            assert.deepEqual(result, obj);
            done();
          });
        });  
    });
    
    it('TTL 1', function(done) {
        var cache = apigee.getCache();
        cache.put('key', 'Hello2', 1000, function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            assert.equal(val, 'Hello2');
            done();
          });
        });  
    });
    
    it('TTL 2', function(done) {
        var cache = apigee.getCache();
        cache.put('key', 'Hello4', 1000, function(err) {
          assert(!err);
          cache.get('key', function(err, val) {
            assert(!err);
            assert.equal(val, 'Hello4');
            done();
          });
        });  
    });
});


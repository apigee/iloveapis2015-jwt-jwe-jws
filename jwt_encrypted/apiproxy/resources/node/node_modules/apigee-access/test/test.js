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
 /* jshint node: true */

 'use strict';

 var apigee = require('..');
 var assert = require('assert');
 var fs = require('fs');
 var http = require('http');
 var util = require('util');

 var PORT = process.env.PORT || 33334;

 var svr;

 describe('Apigee Extensions', function() {
     before(function(done) {
         svr = http.createServer(handleRequest);
         svr.listen(PORT, function() {
             done();
         });
     });

     after(function() {
         svr.close();
     });

     it('Mode', function() {
         assert.equal(apigee.getMode(), 'standalone');
     });

     it('Set Get', function(done) {
         sendRequest('/setget', function(resp) {
             assert.equal(resp.statusCode, 200);
             done();
         });
     });

     it('Set Get Two', function(done) {
         sendRequest('/setgetsetget', function(resp) {
             assert.equal(resp.statusCode, 200);
             done();
         });
     });

     it('Set Get Int', function(done) {
         sendRequest('/setgetint', function(resp) {
             assert.equal(resp.statusCode, 200);
             done();
         });
     });

     it('Delete', function(done) {
         sendRequest('/delete', function(resp) {
             assert.equal(resp.statusCode, 200);
             done();
         });
     });

     it('Predefined', function(done) {
         sendRequest('/predefined', function(resp) {
             assert.equal(resp.statusCode, 200);
             done();
         });
     });
 });

 function handleRequest(req, resp) {

   if (req.url === '/setget') {
     assert(!apigee.getVariable(req, 'testone'));
     apigee.setVariable(req, 'testone', 'Foo');
     assert.equal(apigee.getVariable(req, 'testone'), 'Foo');

   } else if (req.url === '/setgetint') {
     assert(!apigee.getVariable(req, 'testint'));
     apigee.setIntVariable(req, 'testint', 1);
     assert.equal(apigee.getVariable(req, 'testint'), 1);
     apigee.setIntVariable(req, 'testint2', 1.1);
     assert.equal(apigee.getVariable(req, 'testint2'), 1);
     apigee.setIntVariable(req, 'testint3', '123');
     assert.equal(apigee.getVariable(req, 'testint3'), 123);

   } else if (req.url === '/setgetsetget') {
     assert(!apigee.getVariable(req, 'test2'));
     apigee.setVariable(req, 'test2', 'Foo');
     assert.equal(apigee.getVariable(req, 'test2'), 'Foo');

     apigee.setVariable(req, 'test2', 'Baz');
     assert.equal(apigee.getVariable(req, 'test2'), 'Baz');

   } else if (req.url === '/delete') {
     assert(!apigee.getVariable(req, 'testthree'));
     apigee.setVariable(req, 'testthree', 'Foo');
     assert.equal(apigee.getVariable(req, 'testthree'), 'Foo');
     apigee.deleteVariable(req, 'testthree');
     assert(!apigee.getVariable(req, 'testthree'));

     assert.throws(function() {
       apigee.deleteVariable(req, 'client.received.start.timestamp', 'Invalid');
     });

   } else if (req.url === '/predefined') {
     assert(apigee.getVariable(req, 'client.received.start.timestamp'));
     assert(apigee.getVariable(req, 'client.received.end.timestamp'));
     assert(apigee.getVariable(req, 'client.received.start.time'));
     assert(apigee.getVariable(req, 'client.received.end.time'));
     assert.equal(typeof apigee.getVariable(req, 'client.received.start.timestamp'), 'number');
     assert.equal(typeof apigee.getVariable(req, 'client.received.end.timestamp'), 'number');
     assert.equal(typeof apigee.getVariable(req, 'client.received.start.time'), 'string');
     assert.equal(typeof apigee.getVariable(req, 'client.received.end.time'), 'string');

     assert.throws(function() {
         apigee.setVariable(req, 'client.received.start.timestamp', 'Invalid');
     });

   } else {
     resp.writeHead(404);
     return;
   }

   resp.end();
 }

 function sendRequest(path, done) {
   http.get(util.format('http://localhost:%d%s', PORT, path), function(resp) {
       done(resp);
   });
 }

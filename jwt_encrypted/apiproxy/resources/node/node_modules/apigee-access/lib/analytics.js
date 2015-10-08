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

 var ax;
 try {
   ax = require('apigee-internal-analytics');
 } catch (e) {
   // We will get here if the Node.js code is ahead version-wise of the runtime
   throw new Error('Analytics support is not available in this version of Edge.');
 }

 module.exports.push = function(data, cb) {
   if (typeof data !== 'object') {
     throw new Error('Analytics data must be passed as an object');
   }
   if (!data.records || (typeof data.records !== 'object')) {
     throw new Error('Analytics object must contain an object or array called "records"');
   }
   if (typeof cb !== 'function') {
     throw new Error('callback parameter must be a function');
   }

   ax.push(process.env._APIGEE_APP_ID, data, function(err, result) {
     cb(err, result);
   });
 };

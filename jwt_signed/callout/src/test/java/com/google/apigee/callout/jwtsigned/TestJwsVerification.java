// Copyright 2018-2020 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.jwtsigned;

import com.apigee.flow.execution.ExecutionResult;
import java.util.HashMap;
import java.util.Map;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestJwsVerification extends JoseTestBase {

  @Test()
  public void basic() {
    Map properties = new HashMap();
    properties.put(
        "jws",
        "eyJhbGciOiJIUzI1NiJ9.Rm91ciBzY29yZSBhbmQgc2V2ZW4geWVhcnMgYWdvIG91ciBmYXRoZXJzIGJyb3VnaHQgZm9ydGggb24gdGhpcyBjb250aW5lbnQsIGEgbmV3IG5hdGlvbiwgY29uY2VpdmVkIGluIExpYmVydHksIGFuZCBkZWRpY2F0ZWQgdG8gdGhlIHByb3Bvc2l0aW9uIHRoYXQgYWxsIG1lbiBhcmUgY3JlYXRlZCBlcXVhbC4KCk5vdyB3ZSBhcmUgZW5nYWdlZCBpbiBhIGdyZWF0IGNpdmlsIHdhciwgdGVzdGluZyB3aGV0aGVyIHRoYXQgbmF0aW9uLCBvciBhbnkgbmF0aW9uIHNvIGNvbmNlaXZlZCBhbmQgc28gZGVkaWNhdGVkLCBjYW4gbG9uZyBlbmR1cmUuIFdlIGFyZSBtZXQgb24gYSBncmVhdCBiYXR0bGUtZmllbGQgb2YgdGhhdCB3YXIuIFdlIGhhdmUgY29tZSB0byBkZWRpY2F0ZSBhIHBvcnRpb24gb2YgdGhhdCBmaWVsZCwgYXMgYSBmaW5hbCByZXN0aW5nIHBsYWNlIGZvciB0aG9zZSB3aG8gaGVyZSBnYXZlIHRoZWlyIGxpdmVzIHRoYXQgdGhhdCBuYXRpb24gbWlnaHQgbGl2ZS4gSXQgaXMgYWx0b2dldGhlciBmaXR0aW5nIGFuZCBwcm9wZXIgdGhhdCB3ZSBzaG91bGQgZG8gdGhpcy4.0epAvpgPQjHrsAlvMgD_rwsxOGzjGIK7uOxvLI7RaNI");
    properties.put("algorithm", "HS256");
    properties.put("debug", "true"); // causes exception to be logged to stdout
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");

    JwsVerifierCallout callout = new JwsVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jws_isValid");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(isValid, "true");
  }

  @Test()
  public void detached() {
    Map properties = new HashMap();
    properties.put("jws", "eyJhbGciOiJIUzI1NiJ9..0epAvpgPQjHrsAlvMgD_rwsxOGzjGIK7uOxvLI7RaNI");
    properties.put("algorithm", "HS256");
    properties.put("detached-content", gettysburgAddress);
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    JwsVerifierCallout callout = new JwsVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jws_isValid");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(isValid, "true");
  }

  @Test()
  public void detachedFail() {
    Map properties = new HashMap();
    properties.put("jws", "eyJhbGciOiJIUzI1NiJ9..0epAvpgPQjHrsAlvMgD_rwsxOGzjGIK7uOxvLI7RaNI");
    properties.put("algorithm", "HS256");
    properties.put("detached-content", "Not the real payload");
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    JwsVerifierCallout callout = new JwsVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jws_isValid");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.ABORT);
    Assert.assertEquals(isValid, "false");
  }
}

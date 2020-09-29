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
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestJwsCreation extends JoseTestBase {
  private static final Pattern threePartJwsPattern;

  static {
    threePartJwsPattern = Pattern.compile("^([^.]+)\\.([^.]*)\\.([^.]+)$");
  }

  @Test()
  public void basicCreate() {
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("payload", gettysburgAddress);

    JwsCreatorCallout callout = new JwsCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String jws = msgCtxt.getVariable("jws_jws");
    System.out.println("jws: " + jws);
    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNotNull(jws);
    Matcher matcher = threePartJwsPattern.matcher(jws);
    Assert.assertTrue(matcher.matches());
    Assert.assertNotNull(matcher.group(2));
    Assert.assertTrue(matcher.group(2).length() > 0);
  }

  @Test()
  public void createDetached() {
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("payload", gettysburgAddress);
    properties.put("detach-content", "true");

    JwsCreatorCallout callout = new JwsCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String jws = msgCtxt.getVariable("jws_jws");
    System.out.println("jws: " + jws);
    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertNotNull(jws);
    Matcher matcher = threePartJwsPattern.matcher(jws);
    Assert.assertTrue(matcher.matches());
    Assert.assertNotNull(matcher.group(2));
    Assert.assertTrue(matcher.group(2).length() == 0);
  }
}

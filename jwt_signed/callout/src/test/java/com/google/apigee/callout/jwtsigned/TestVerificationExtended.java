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

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.File;
import java.io.IOException;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.Map;
import mockit.Mock;
import mockit.MockUp;
import org.apache.commons.io.FileUtils;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;
import org.testng.annotations.Test;

public class TestVerificationExtended {
  private static String testDataDirPath = "src/test/resources/parse-extended";
  private static File testDataDir = new File(testDataDirPath);

  MessageContext msgCtxt;
  ExecutionContext exeCtxt;

  @BeforeMethod()
  public void testSetup1() {

    msgCtxt =
        new MockUp<MessageContext>() {
          private Map variables;

          public void $init() {
            variables = new HashMap();
          }

          @Mock()
          public <T> T getVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            return (T) variables.get(name);
          }

          @Mock()
          public boolean setVariable(final String name, final Object value) {
            if (variables == null) {
              variables = new HashMap();
            }
            variables.put(name, value);
            return true;
          }

          @Mock()
          public boolean removeVariable(final String name) {
            if (variables == null) {
              variables = new HashMap();
            }
            if (variables.containsKey(name)) {
              variables.remove(name);
            }
            return true;
          }
        }.getMockInstance();

    exeCtxt = new MockUp<ExecutionContext>() {}.getMockInstance();
  }

  @Test
  public void testDataProviders() throws IOException {
    Object[][] tests = getDataForBatch1();
    System.out.println("extended tests: " + tests.length);
    Assert.assertTrue(tests.length > 0);
  }

  @Test
  public void testCreateThenVerify() throws IOException {
    String audUuid = java.util.UUID.randomUUID().toString();
    Map<String, String> createProps = new HashMap<String, String>();
    createProps.put("algorithm", "HS256");
    createProps.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    createProps.put("issuer", "http://dinochiesa.net");
    createProps.put("subject", "http://dinochiesa.net");
    createProps.put("audience", audUuid);
    createProps.put("debug", "true");
    createProps.put("expiresIn", "1800");
    createProps.put("claim_motto", "Iloveapis");
    JwtCreatorCallout callout1 = new JwtCreatorCallout(createProps);
    ExecutionResult result = callout1.execute(msgCtxt, exeCtxt);

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    String jwt = msgCtxt.getVariable("jwt_jwt");
    Assert.assertNotNull(jwt);

    // now verify the signature
    Map<String, String> verifyProps = new HashMap<String, String>();
    verifyProps.put("algorithm", "HS256");
    verifyProps.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    verifyProps.put("jwt", jwt);
    verifyProps.put("claim_sub", "http://dinochiesa.net");
    verifyProps.put("debug", "true");
    verifyProps.put("claim_aud", audUuid);
    verifyProps.put("claim_motto", "Iloveapis");
    JwtVerifierCallout callout2 = new JwtVerifierCallout(verifyProps);
    result = callout2.execute(msgCtxt, exeCtxt);

    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");
    String verified = msgCtxt.getVariable("jwt_verified");

    Assert.assertEquals(isValid, "true");
    Assert.assertEquals(isExpired, "false");
    Assert.assertEquals(hasExpiry, "true");
    Assert.assertEquals(verified, "true");

    String claims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(claims);
  }

  @Test(dataProvider = "batch1")
  public void test2_Configs(TestCase tc) {
    JwtVerifierCallout callout = new JwtVerifierCallout(tc.getInputProperties());
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    ExecutionResult expectedResult = getExpectedExecutionResult(tc);
    System.out.printf("\n** Test case : %s\n", tc.getTestName());
    if (expectedResult != result) {
      System.out.printf("   Unexpected result: %s\n", result);
    }
    Assert.assertEquals(result, expectedResult);

    // retrieve output
    Map<String, String> expected = tc.getExpected();
    for (String key : expected.keySet()) {
      if (!key.equals("result")) {
        String expectedValue = expected.get(key);
        String actualValue = msgCtxt.getVariable("jwt_" + key);
        System.out.printf("Examining: %s (%s)\n", key, actualValue);
        Assert.assertEquals(actualValue, expectedValue, key);
      }
    }
    System.out.printf("\n");
  }

  @DataProvider(name = "batch1")
  public static Object[][] getDataForBatch1() throws IOException {
    Object[][] data = null;

    // @DataProvider requires the output to be a Object[][]. The inner
    // Object[] is the set of params that get passed to the test method.
    // If you want to pass just one param to the constructor, then
    // each inner Object[] must have length 1.

    ObjectMapper om = new ObjectMapper();
    om.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);

    // read in all the *.json files in the test-data directory
    // System.out.println("dir name: " + testDataDir.getAbsolutePath());
    File[] files = testDataDir.listFiles();
    if (files != null && files.length > 0) {
      int c = 0;
      ArrayList<TestCase> list = new ArrayList<TestCase>();
      for (File file : files) {
        String name = file.getName();
        if (name.endsWith(".json")) {
          TestCase tc = om.readValue(file, TestCase.class);
          tc.setTestName(name.substring(0, name.length() - 5));
          readInFileData(tc);
          list.add(tc);
        }
      }

      // I could not figure an easier way to generate a 2-d array...
      int n = list.size();
      data = new Object[n][];
      for (int i = 0; i < n; i++) {
        data[i] = new Object[] {list.get(i)};
      }
    }
    return data;
  }

  private static void readInFileData(TestCase tc) throws IOException {
    String[] propNames = {"certificate", "public-key", "jwt"};
    for (String propName : propNames) {
      String value = tc.getInputProperties().get(propName);
      if ((value != null) && value.startsWith("file://")) {
        String filename = value.substring(7);
        File file = new File(testDataDir, filename);
        String fileContents = FileUtils.readFileToString(file);
        tc.getInputProperties().put(propName, fileContents);
      }
    }
  }

  private static ExecutionResult getExpectedExecutionResult(TestCase tc) {
    String value = tc.getExpected().get("result");
    return (value.toLowerCase().equals("success"))
        ? ExecutionResult.SUCCESS
        : ExecutionResult.ABORT;
  }
}

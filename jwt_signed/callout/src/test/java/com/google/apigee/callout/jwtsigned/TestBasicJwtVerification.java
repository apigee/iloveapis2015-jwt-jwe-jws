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
import java.io.File;
import java.io.IOException;
import java.util.HashMap;
import java.util.Map;
import org.apache.commons.io.FileUtils;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestBasicJwtVerification extends JoseTestBase {
  private static String testDataDirPath = "src/test/resources/parse-basic";
  private static File testDataDir = new File(testDataDirPath);
  private static final Map<String, String> jwtMap;
  private static final Map<String, String> certMap;

  static {
    jwtMap = java.util.Collections.unmodifiableMap(readFilesIntoMap(".jwt"));
    certMap = java.util.Collections.unmodifiableMap(readFilesIntoMap(".cert"));
  }

  private static Map<String, String> readFilesIntoMap(String extension) {
    Map<String, String> m = new HashMap<String, String>();
    try {
      File[] files = testDataDir.listFiles();
      int extLength = extension.length();
      if (files != null && files.length > 0) {
        for (File file : files) {
          String name = file.getName();
          if (name.endsWith(extension)) {
            String fileContents = FileUtils.readFileToString(file);
            String shortName = name.substring(0, name.length() - extLength);
            m.put(shortName, fileContents.trim());
          }
        }
      }

    } catch (IOException exc1) {
      // gulp
      exc1.printStackTrace();
    }
    return m;
  }

  @Test()
  public void test1_BadJwt() {
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      String expectedReason = "the JWT did not parse.";
      Map properties = new HashMap();
      properties.put("jwt", "This is an invalid JWT, will not parse...");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }
      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false");
      Assert.assertEquals(reason, expectedReason);
    }
  }

  @Test()
  public void missingJwt() {
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      String expectedReason = "jwt is not specified or is empty.";
      // now parse and verify
      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      properties.put("debug", "true"); // causes exception to be logged to stdout
      properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }
      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false", "isValid");
      Assert.assertEquals(reason, expectedReason, "reason");
    }
  }

  @Test()
  public void test2_Rs256JwtMissingPemfileProperty() {
    String expectedReason =
        "must specify pemfile or public-key or certificate when algorithm is RS*";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      // properties.put("debug", "true"); // causes exception to be logged to stdout
      properties.put("jwt", jwtMap.get("ms1"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(reason, expectedReason);
      Assert.assertEquals(isValid, "false", "isValid");
    }
  }

  @Test()
  public void test2_Rs256JwtMissingPemfileProperty_NoVerify() {
    String[][] cases =
        new String[][] {
          new String[] {
            null, "must specify pemfile or public-key or certificate when algorithm is RS*"
          },
          new String[] {
            "true", "must specify pemfile or public-key or certificate when algorithm is RS*"
          },
          new String[] {"false", "the token is expired"}
        };

    for (String[] s : cases) {
      String wantVerifyString = s[0];
      String expectedReason = s[1];

      ExecutionResult expectedResult =
          ("false".equals(wantVerifyString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      // properties.put("debug", "true"); // causes exception to be logged to stdout
      properties.put("jwt", jwtMap.get("ms1"));
      if (wantVerifyString != null) {
        properties.put("wantVerify", wantVerifyString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      String thisCase =
          String.format("Case(%s)", wantVerifyString != null ? wantVerifyString : "null");
      Assert.assertEquals(result, expectedResult, thisCase);
      Assert.assertEquals(reason, expectedReason, thisCase);
      Assert.assertEquals(isValid, "false", thisCase);
    }
  }

  @Test()
  public void test2_Rs256JwtNonExistentPemfile() {
    String nonExistentPemFile = "This-pemfile-does-not-exist.pem";
    String expectedReason = "resource \"/" + nonExistentPemFile + "\" not found";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      // properties.put("debug", "true"); // causes exception to be logged to stdout
      properties.put("pemfile", nonExistentPemFile);
      properties.put("jwt", jwtMap.get("ms1"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(reason, expectedReason);
      Assert.assertEquals(isValid, "false");
    }
  }

  @Test()
  public void rs256JwtPemExistsButIsEmpty() {
    String emptyPemFile = "for-testing-only.pem";
    String expectedReason = "an invalid public key was provided";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      // properties.put("debug", "true"); // causes exception to be logged to stdout
      properties.put("pemfile", emptyPemFile);
      properties.put("jwt", jwtMap.get("ms1"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(reason, expectedReason);
      Assert.assertEquals(isValid, "false");
    }
  }

  @Test()
  public void test3_ExpiredJwt() {
    String expectedReason = "the token is expired";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      properties.put("jwt", jwtMap.get("ms1"));
      properties.put("certificate", certMap.get("ms1"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String expiry = msgCtxt.getVariable("jwt_expirationTimeFormatted");
      String reason = msgCtxt.getVariable("jwt_reason");
      String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");
      String isExpired = msgCtxt.getVariable("jwt_isExpired");
      // System.out.println("test3 expiry: " + expiry);

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false");
      Assert.assertEquals(hasExpiry, "true");
      Assert.assertEquals(isExpired, "true");
      Assert.assertEquals(reason, expectedReason);
    }
  }

  @Test()
  public void test4_MismatchedAlgorithm1() {
    String expectedReason = "Algorithm mismatch. provided=RS256, required=HS256";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      properties.put("jwt", jwtMap.get("ms1"));
      properties.put("secret-key", "123456");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String reason = msgCtxt.getVariable("jwt_reason");
      String isValid = msgCtxt.getVariable("jwt_isValid");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(reason, expectedReason);
      Assert.assertEquals(isValid, "false");
    }
  }

  @Test()
  public void test4_MismatchedAlgorithm2() {
    String expectedReason = "Algorithm mismatch. provided=HS256, required=RS256";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      properties.put("jwt", jwtMap.get("sample1"));
      properties.put("certificate", certMap.get("ms1"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false");
      Assert.assertEquals(reason, expectedReason);
    }
  }

  @Test()
  public void test5_SimpleClaims1() {
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("jwt", jwtMap.get("sample1"));

    // The nimbus library requires the secret-key to be at least 256
    // bits in length.  This translates to 32 x 8-bit characters.
    //                            ----------1---------2---------3--
    //                            012345678901234567890123456789012
    properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
    properties.put("claim_sub", "1234567890");
    properties.put("claim_name", "John Doe");

    JwtVerifierCallout callout = new JwtVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String reason = msgCtxt.getVariable("jwt_reason");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS, "ExecutionResult");
    Assert.assertEquals(isValid, "true", "isValid");
    Assert.assertEquals(reason, null, "reason");
    Assert.assertEquals(isExpired, "false", "isExpired");
    Assert.assertEquals(hasExpiry, "false", "hasExpiry");
  }

  @Test()
  public void test5_SimpleClaims2() {
    String expectedReason = "mismatch in claim name, expected:Jane Williams provided:John Doe";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      // properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("sample1"));
      properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
      properties.put("claim_sub", "1234567890");
      properties.put("claim_name", "Jane Williams");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String reason = msgCtxt.getVariable("jwt_reason");
      String isValid = msgCtxt.getVariable("jwt_isValid");

      // check result and output
      String thisCase =
          String.format("Case(%s)", continueOnErrorString != null ? continueOnErrorString : "null");
      Assert.assertEquals(result, expectedResult, thisCase);
      Assert.assertEquals(isValid, "false", thisCase);
      Assert.assertEquals(reason, expectedReason, thisCase);
    }
  }

  @Test()
  public void test5_SimpleClaims3() {
    String expectedReason = "mismatch in claim sub, expected:ABCDEFG provided:1234567890";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      // properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("sample1"));
      properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
      properties.put("claim_sub", "ABCDEFG");
      properties.put("claim_name", "John Doe");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult, "ExecutionResult");
      Assert.assertEquals(isValid, "false", "isValid");
      Assert.assertEquals(reason, expectedReason, "reason");
    }
  }

  @Test()
  public void test5_SimpleClaims4() {
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("jwt", jwtMap.get("sample2"));
    //                            ----------1---------2---------3-
    //                            01234567890123456789012345678901
    properties.put("secret-key", "Qwerty123-Qwerty123-Qwerty123-Qwerty123");
    properties.put("claim_given_name", "Dino");
    properties.put("claim_family_name", "Chiesa");

    JwtVerifierCallout callout = new JwtVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String reason = msgCtxt.getVariable("jwt_reason");
    String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(isValid, "true");
    Assert.assertEquals(reason, null);
    Assert.assertEquals(hasExpiry, "false");
  }

  @Test()
  public void test5_ClaimVariable1() {
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    // properties.put("debug", "true");
    properties.put("jwt", jwtMap.get("sample1"));
    properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
    properties.put("claim_sub", "1234567890");
    properties.put("claim_name", "John Doe");

    JwtVerifierCallout callout = new JwtVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String reason = msgCtxt.getVariable("jwt_reason");
    String isValid = msgCtxt.getVariable("jwt_isValid");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS, "ExecutionResult");
    Assert.assertEquals(isValid, "true", "isValid");

    String claimName = msgCtxt.getVariable("jwt_claim_name");
    Assert.assertEquals(claimName, "John Doe", "claimName");
  }

  @Test()
  public void test6_UnsignedJwt() {
    String expectedReason = "the JWT did not parse.";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      Map properties = new HashMap();
      properties.put("algorithm", "none");
      properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("unsigned1"));
      properties.put("claim_username", "john.doe");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false");
      Assert.assertEquals(reason, expectedReason);
    }
  }

  @Test()
  public void test7_BadHmacKey() {
    String expectedReason = "the signature could not be verified";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;

      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("sample1"));

      // The nimbus library requires the secret-key to be at least 256
      // bits in length.  This translates to 32 x 8-bit characters.
      //                            ----------1---------2---------3--
      //                            012345678901234567890123456789012
      properties.put("secret-key", "IncorrectSecretKey-01929292929292");
      properties.put("claim_sub", "1234567890");
      properties.put("claim_name", "John Doe");
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String verified = msgCtxt.getVariable("jwt_verified");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(isValid, "false");
      Assert.assertEquals(verified, "false");
      Assert.assertEquals(reason, expectedReason);
    }
  }

  @Test()
  public void test7_BadHmacKey_NoVerify() {
    String[][] cases =
        new String[][] {
          new String[] {null, "the signature could not be verified"},
          new String[] {"true", "the signature could not be verified"},
          new String[] {"false", "the signature was not verified"}
        };

    for (String[] s : cases) {
      ExecutionResult expectedResult =
          ("false".equals(s[0])) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT; // SUCCESS ;
      Map properties = new HashMap();
      properties.put("algorithm", "HS256");
      properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("sample1"));

      // The nimbus library requires the secret-key to be at least 256
      // bits in length.  This translates to 32 x 8-bit characters.
      //                            ----------1---------2---------3--
      //                            012345678901234567890123456789012
      properties.put("secret-key", "IncorrectSecretKey-01929292929292");
      properties.put("claim_sub", "1234567890");
      properties.put("claim_name", "John Doe");
      if (s[0] != null) {
        properties.put("wantVerify", s[0]);
      }

      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String verified = msgCtxt.getVariable("jwt_verified");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      String thisCase = String.format("Case(%s)", s[0] != null ? s[0] : "null");
      Assert.assertEquals(reason, s[1], thisCase);
      Assert.assertEquals(result, expectedResult, thisCase);
      Assert.assertEquals(isValid, "false", thisCase);
      Assert.assertEquals(verified, "false", thisCase);
    }
  }

  @Test()
  public void test8_ExpiredJwtDisabledTimeCheck() {
    // String expectedReason = "the token is expired";
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("jwt", jwtMap.get("ms1"));
    properties.put("timeAllowance", "-1");
    properties.put("certificate", certMap.get("ms1"));

    JwtVerifierCallout callout = new JwtVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String expiry = msgCtxt.getVariable("jwt_expirationTimeFormatted");
    String reason = msgCtxt.getVariable("jwt_reason");
    String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    String isActuallyExpired = msgCtxt.getVariable("jwt_isActuallyExpired");
    String timeCheckDisabled = msgCtxt.getVariable("jwt_timeCheckDisabled");
    // System.out.println("test8 expiry: " + expiry);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(isValid, "true");
    Assert.assertEquals(hasExpiry, "true");
    Assert.assertEquals(isActuallyExpired, "true");
    Assert.assertEquals(isExpired, "false");
    Assert.assertEquals(timeCheckDisabled, "true");
    // Assert.assertEquals(reason, expectedReason);
  }

  @Test()
  public void test9_Sample3() {
    String expectedReason = "the token is expired";
    String[] cases = new String[] {null, "true", "false"};
    for (String continueOnErrorString : cases) {
      ExecutionResult expectedResult =
          ("true".equals(continueOnErrorString)) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      Map properties = new HashMap();
      properties.put("algorithm", "RS256");
      properties.put("debug", "true");
      properties.put("jwt", jwtMap.get("sample3"));
      properties.put("certificate", certMap.get("sample3"));
      if (continueOnErrorString != null) {
        properties.put("continueOnError", continueOnErrorString);
      }
      JwtVerifierCallout callout = new JwtVerifierCallout(properties);
      ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

      // retrieve output
      String isValid = msgCtxt.getVariable("jwt_isValid");
      String reason = msgCtxt.getVariable("jwt_reason");

      // check result and output
      Assert.assertEquals(result, expectedResult);
      Assert.assertEquals(reason, expectedReason);
      Assert.assertEquals(isValid, "false");
    }
  }

  @Test()
  public void verifyViaJwks() {
    ExecutionResult expectedResult = ExecutionResult.SUCCESS;
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("jwt", "eyJraWQiOiIwNTZlZGM0OCIsInR5cCI6IkpXVCIsImFsZyI6IlJTMjU2In0.eyJzdWIiOiJSdXNsYW4iLCJhdWQiOiJSdXNsYW4iLCJpc3MiOiJqd2tzLXNlcnZpY2UuYXBwc3BvdC5jb20iLCJpYXQiOjE2MDE1MDk4MjQsImp0aSI6IjEwNTQ3NjMwLWZhNGEtNGQ3Ni04NDA1LWM3NTcxZGVkYTZjYiJ9.UzPZzSv0A0VTmu3vjJAGbEtD4Sn7ITGVkcUUm9Bm3Z3SddTrNhsnbNWd38RwWqhIZF2mVDN944-ZsATH96-23aV9mlgq8HUYJtes9j43VPwt0ZPGvYIkoJ_3_UL4LTIzSuIDlvKM_07QNdZ1ogkJFoLfMJudMr6bAZ620fzTrJJoIRd1ujzuSS2KHuNMsPAyvbmW10HukEhLHJXnlY3O6_4k-ECBaJS_6uFAJUeOjGlR7kCFIJIx9epo_vH7ZVjCstix4JQTbkPdcXzXQ_LOeH5LzMuYtIIwvi78cd2oKh46JNqqw8mvF3FHd1Tvkb7J3SPUZl86CupsiOxDbYxARA");
    properties.put("jwks-uri", "https://jwks-service.appspot.com/.well-known/jwks.json");

    JwtVerifierCallout callout = new JwtVerifierCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String reason = msgCtxt.getVariable("jwt_reason");

    // check result and output
    Assert.assertEquals(result, expectedResult);
    Assert.assertEquals(isValid, "true");
  }



}

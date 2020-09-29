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
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import org.apache.commons.lang3.time.DateParser;
import org.apache.commons.lang3.time.FastDateFormat;
import org.testng.Assert;
import org.testng.annotations.Test;

public class TestJwtCreation extends JoseTestBase {
  private static final ObjectMapper om = new ObjectMapper();

  @Test()
  public void basicCreateAndParse() {
    String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
    String audience = "everyone";
    String subject = "urn:F5CF2B90-DDF3-47EB-82EB-F67A5B561FD2";
    String jti = "e7a0db4d-6bbe-476c-85be-385274dd0c0d";
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("id", jti);
    properties.put("audience", audience);

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // now parse and verify
    properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("claim_sub", subject);
    properties.put("claim_jti", jti);
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    String jwt_jti = msgCtxt.getVariable("jwt_jti");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(jwt_jti, jti, "jti");
    Assert.assertEquals(isExpired, "false", "isExpired");
    Assert.assertEquals(isValid, "true", "isValid");
  }

  @Test()
  public void createAndParseWithGeneratedId() {
    String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
    String audience = "everyone";
    String subject = "urn:F5CF2B90-DDF3-47EB-82EB-F67A5B561FD2";
    Map properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("id", "");
    properties.put("audience", audience);

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // retrieve output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // now parse and verify
    properties = new HashMap();
    properties.put("algorithm", "HS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
    properties.put("claim_sub", subject);
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isValid = msgCtxt.getVariable("jwt_isValid");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    String jwt_jti = msgCtxt.getVariable("jwt_jti");

    Assert.assertEquals(result, ExecutionResult.SUCCESS);
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");
    Assert.assertEquals(isValid, "true", "isValid");
    Assert.assertNotNull(jwt_jti, "jti");
    Assert.assertNotEquals(jwt_jti, "", "jti");
  }

  @Test()
  public void createAndParseMultiAudience() {
    String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
    String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
    msgCtxt.setVariable("audienceVar", new String[] {"everyone", "anyone"});
    String[] audienceProperties = new String[] {"audience", "claim_aud"};
    String[] audiences = new String[] {"everyone,anyone", "{audienceVar}"};
    String[] continueOnErrorStrings = new String[] {null, "true", "false"};
    for (String audienceProperty : audienceProperties) {
      for (String audience : audiences) {
        for (String continueOnErrorString : continueOnErrorStrings) {
          String trialLabel =
              String.format(
                  "createAndParseMultiAudience (%s,%s,%s)",
                  audienceProperty, audience, continueOnErrorString);
          ExecutionResult expectedResult =
              ("true".equals(continueOnErrorString))
                  ? ExecutionResult.SUCCESS
                  : ExecutionResult.ABORT;

          Map properties = new HashMap();
          properties.put("algorithm", "HS256");
          properties.put("debug", "true");
          properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
          properties.put("subject", subject);
          properties.put("issuer", issuer);
          properties.put(audienceProperty, audience);
          if (continueOnErrorString != null) {
            properties.put("continueOnError", continueOnErrorString);
          }

          JwtCreatorCallout callout = new JwtCreatorCallout(properties);
          ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

          // retrieve output
          String jwt = msgCtxt.getVariable("jwt_jwt");
          System.out.println("jwt: " + jwt);
          // check result and output
          Assert.assertEquals(result, ExecutionResult.SUCCESS);

          // now parse and verify, audience = anyone
          properties = new HashMap();
          properties.put("algorithm", "HS256");
          properties.put("jwt", jwt);
          properties.put("debug", "true");
          properties.put("claim_aud", "anyone");
          properties.put("claim_sub", subject);
          properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
          if (continueOnErrorString != null) {
            properties.put("continueOnError", continueOnErrorString);
          }
          System.out.printf("\n** createAndParseMultiAudience trial: %s\n", trialLabel);

          JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
          result = callout2.execute(msgCtxt, exeCtxt);

          String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
          String isValid = msgCtxt.getVariable("jwt_isValid");
          String isExpired = msgCtxt.getVariable("jwt_isExpired");

          Assert.assertEquals(result, ExecutionResult.SUCCESS, trialLabel);

          Assert.assertEquals(jwt_issuer, issuer, trialLabel + " Issuer");
          Assert.assertEquals(isValid, "true", trialLabel + " isValid");
          Assert.assertEquals(isExpired, "false", trialLabel + " isExpired");

          // now verify audience "everyone"
          properties.put("claim_aud", "everyone");
          properties.put("claim_sub", subject);
          callout2 = new JwtVerifierCallout(properties);
          result = callout2.execute(msgCtxt, exeCtxt);
          isValid = msgCtxt.getVariable("jwt_isValid");
          isExpired = msgCtxt.getVariable("jwt_isExpired");

          Assert.assertEquals(result, ExecutionResult.SUCCESS);
          Assert.assertEquals(isValid, "true", "isValid");
          Assert.assertEquals(isExpired, "false", "isExpired");

          // now try verify audience "someone", should return "not valid"
          properties.put("claim_aud", "someone");
          properties.put("claim_sub", subject);
          callout2 = new JwtVerifierCallout(properties);
          result = callout2.execute(msgCtxt, exeCtxt);
          isValid = msgCtxt.getVariable("jwt_isValid");
          isExpired = msgCtxt.getVariable("jwt_isExpired");
          String reason = msgCtxt.getVariable("jwt_reason");

          Assert.assertEquals(result, expectedResult);
          Assert.assertEquals(isValid, "false", "isValid");
          Assert.assertEquals(isExpired, "false", "isExpired");
          Assert.assertEquals(reason, "audience violation", "audience");
        }
      }
    }
  }

  @Test
  public void createBoxJwt() throws Exception {
    String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
    String issuer = "api-key-goes-here-78B13CD0-CEFD-4F6A-BB76";
    String audience = "https://api.box.com/oauth2/token";
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-2"));
    properties.put("private-key-password", "Secret123");
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("audience", audience);
    properties.put("expiresIn", "30"); // seconds
    properties.put("claim_box_sub_type", "enterprise");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);

    // now parse and verify the token. Check that all the claim_* claims are present.
    properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("claim_aud", audience);
    properties.put("claim_sub", subject);
    properties.put("claim_box_sub_type", "enterprise");
    properties.put("public-key", publicKeyMap.get("rsa-public-2"));
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String reason = msgCtxt.getVariable("jwt_reason");
    Assert.assertEquals(reason, null, "reason");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    Assert.assertEquals(isValid, "true", "isValid");

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");
  }

  @Test
  public void createJwtWithKid() throws Exception {
    String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
    String issuer = "api-key-goes-here-78B13CD0-CEFD-4F6A-BB76";
    String audience = "urn://example.com";
    String kid = java.util.UUID.randomUUID().toString().replace("-", "");
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-2"));
    properties.put("private-key-password", "Secret123");
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("kid", kid);
    properties.put("audience", audience);
    properties.put("expiresIn", "30"); // seconds
    properties.put("claim_box_sub_type", "enterprise");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);

    // now parse and verify the token. Check that all the claim_* claims are present.
    properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("claim_aud", audience);
    properties.put("claim_sub", subject);
    properties.put("claim_box_sub_type", "enterprise");
    properties.put("public-key", publicKeyMap.get("rsa-public-2"));
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String reason = msgCtxt.getVariable("jwt_reason");
    Assert.assertEquals(reason, null, "reason");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    Assert.assertEquals(isValid, "true", "isValid");

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");

    String jwt_kid = msgCtxt.getVariable("jwt_kid");
    Assert.assertEquals(jwt_kid, kid, "jwt_kid");
  }

  @Test
  public void edgeMicroJwt() throws Exception {
    String subject = "urn:edge-micro-apigee-com";
    String issuer = "http://apigee.com/edgemicro/";
    String audience = "everybody";
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("audience", audience);
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);

    // now parse and verify the token. Check that all the claim_* claims are present.
    properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("claim_aud", audience);
    properties.put("claim_sub", subject);
    properties.put("public-key", publicKeyMap.get("rsa-public-3"));
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String reason = msgCtxt.getVariable("jwt_reason");
    Assert.assertEquals(reason, null, "reason");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    Assert.assertEquals(isValid, "true", "isValid");

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");
  }

  @Test
  public void withArrayClaim() throws Exception {
    String subject = "urn:edge-micro-apigee-com";
    String issuer = "http://apigee.com/edgemicro/";
    String audience = "everybody";
    String[] apiProducts = {"product1", "product2"};

    msgCtxt.setVariable("api_products", apiProducts);
    msgCtxt.setVariable("my_issuer", issuer);
    msgCtxt.setVariable("my_subject", subject);

    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("subject", "{my_subject}");
    properties.put("issuer", "{my_issuer}");
    properties.put("audience", audience);
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());
    properties.put("claim_api_products", "{api_products}"); // note: array

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    System.out.println("claims: " + msgCtxt.getVariable("jwt_claims"));

    // now parse and verify the token. Check that all the claim_* claims are present.
    properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("claim_aud", audience);
    properties.put("claim_sub", subject);
    properties.put("claim_api_products", "product1"); // can verify only one item in an array claim
    properties.put("public-key", publicKeyMap.get("rsa-public-3"));
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String reason = msgCtxt.getVariable("jwt_reason");
    Assert.assertEquals(reason, null, "reason");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    Assert.assertEquals(isValid, "true", "isValid");

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");

    String apiProductsOut = msgCtxt.getVariable("jwt_claim_api_products_provided");
    Assert.assertEquals(apiProductsOut, "product1|product2", "api_products");
  }

  @Test
  public void defaultNotBefore_None() throws Exception {
    Date now = new Date();
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "defaultNotBefore_None");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    JsonNode nbf = claimsNode.get("nbf");
    Assert.assertNull(nbf, "nbf");
    // String iatAsText = claimsNode.get("iat").asText();
    // Assert.assertEquals(iatAsText, nbfAsText, "nbf and iat");
    // int nbfSeconds = Integer.parseInt(nbfAsText);
    // int secondsNow = (int) (now.getTime()/1000);
    // int delta = Math.abs(secondsNow - nbfSeconds);
    // Assert.assertTrue(delta<=1, "nbf");
  }

  @Test
  public void notBefore_Default_Empty() throws Exception {
    Date now = new Date();
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("not-before", "");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "notBefore_Default_Empty");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    JsonNode nbf = claimsNode.get("nbf");
    Assert.assertNotNull(nbf, "nbf");
    String nbfAsText = nbf.asText();
    String iatAsText = claimsNode.get("iat").asText();
    Assert.assertEquals(iatAsText, nbfAsText, "nbf and iat");
    int nbfSeconds = Integer.parseInt(nbfAsText);
    int secondsNow = (int) (now.getTime() / 1000);
    int delta = Math.abs(secondsNow - nbfSeconds);
    Assert.assertTrue(delta <= 1, "nbf");
  }

  @Test
  public void notBefore_Explicit() throws Exception {
    String notBeforeString = "2017-08-14T11:00:21.269-0700";
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("not-before", notBeforeString);
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "notBefore_Explicit");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    String nbfAsText = claimsNode.get("nbf").asText();
    Assert.assertNotNull(nbfAsText, "nbf");

    DateParser dp =
        FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss.SSSZ", TimeZone.getTimeZone("UTC"));
    Date notBefore = dp.parse(notBeforeString);
    int secondsNbfExpected = (int) (notBefore.getTime() / 1000);
    int secondsNbfActual = Integer.parseInt(nbfAsText);
    Assert.assertEquals(secondsNbfActual, secondsNbfExpected, "nbf");
  }

  @Test
  public void notBefore_Explicit_2() throws Exception {
    String notBeforeString = "1508536333";
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("not-before", notBeforeString);
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "notBefore_Explicit_2");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    JsonNode nbfNode = claimsNode.get("nbf");
    Assert.assertNotNull(nbfNode, "nbfNode");
    String nbfAsText = nbfNode.asText();
    Assert.assertNotNull(nbfAsText, "nbf");
    Assert.assertEquals(nbfAsText, notBeforeString, "notBeforeString");
  }

  @Test
  public void rsa_EncryptedKey_3DES() throws Exception {
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-4"));
    properties.put("private-key-password", "Apigee-IloveAPIs");
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "rsa_EncryptedKey_3DES");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);
  }

  @Test
  public void rsa_EncryptedKey_3DES_2() throws Exception {
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", "{private.privateKey}");
    properties.put("private-key-password", "{private.privateKey.passphrase}");
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "rsa_EncryptedKey_3DES_2");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    msgCtxt.setVariable("private.privateKey.passphrase", "Apigee-IloveAPIs");
    msgCtxt.setVariable("private.privateKey", privateKeyMap.get("rsa-private-4"));

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);
  }

  @Test
  public void rsa_EncryptedKey_AES() throws Exception {
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-1"));
    properties.put("private-key-password", "deecee123");
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "rsa_EncryptedKey_AES");
    properties.put("claim_jti", java.util.UUID.randomUUID().toString());

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);
  }

  @Test
  public void withJsonClaim() throws Exception {
    String jsonClaim = "{\"id\":1234,\"verified\":true,\"allocations\":[4,\"seven\",false]}";
    String jti = java.util.UUID.randomUUID().toString();
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "withJsonClaim");
    properties.put("claim_jti", jti);
    properties.put("claim_json_account", jsonClaim);

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    JsonNode accountNode = claimsNode.get("account");
    JsonNode idNode = accountNode.get("id");
    int idFromClaim = idNode.asInt();
    Assert.assertEquals(idFromClaim, 1234, "account-id");
  }

  @Test
  public void withJsonClaimFromVariable() throws Exception {
    String jsonClaim =
        "{ \"id\": 1234, \"verified\": true, \"allocations\" : [4, \"seven\", false] }";
    String jti = java.util.UUID.randomUUID().toString();
    Map properties = new HashMap();
    properties.put("algorithm", "RS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-3"));
    properties.put("expiresIn", "300"); // seconds
    properties.put("claim_testname", "withJsonClaimFromVariable");
    properties.put("claim_jti", jti);
    properties.put("claim_json_account", "{jsonClaimVariable}");

    msgCtxt.setVariable("jsonClaimVariable", jsonClaim);

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);
    String jwtClaims = msgCtxt.getVariable("jwt_claims");
    Assert.assertNotNull(jwtClaims, "jwt_claims");
    System.out.println("claims: " + jwtClaims);

    JsonNode claimsNode = om.readTree(jwtClaims);
    JsonNode accountNode = claimsNode.get("account");
    JsonNode idNode = accountNode.get("id");
    int idFromClaim = idNode.asInt();
    Assert.assertEquals(idFromClaim, 1234, "account-id");
  }

  @Test
  public void ps256Basic() throws Exception {
    String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
    String issuer = "api-key-goes-here-78B13CD0-CEFD-4F6A-BB76";
    String audience = "urn://example.com";
    String kid = java.util.UUID.randomUUID().toString().replace("-", "");
    Map properties = new HashMap();
    properties.put("algorithm", "PS256");
    properties.put("debug", "true");
    properties.put("private-key", privateKeyMap.get("rsa-private-2"));
    properties.put("private-key-password", "Secret123");
    properties.put("subject", subject);
    properties.put("issuer", issuer);
    properties.put("kid", kid);
    properties.put("audience", audience);
    properties.put("expiresIn", "30"); // seconds

    JwtCreatorCallout callout = new JwtCreatorCallout(properties);
    ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    // retrieve and check output
    String jwt = msgCtxt.getVariable("jwt_jwt");
    System.out.println("jwt: " + jwt);

    // now parse and verify the token. Check that all the claim_* claims are present.
    properties = new HashMap();
    properties.put("algorithm", "PS256");
    properties.put("jwt", jwt);
    properties.put("debug", "true");
    properties.put("claim_aud", audience);
    properties.put("claim_sub", subject);
    properties.put("public-key", publicKeyMap.get("rsa-public-2"));
    JwtVerifierCallout callout2 = new JwtVerifierCallout(properties);
    result = callout2.execute(msgCtxt, exeCtxt);

    String reason = msgCtxt.getVariable("jwt_reason");
    Assert.assertEquals(reason, null, "reason");

    // check result and output
    Assert.assertEquals(result, ExecutionResult.SUCCESS);

    String isValid = msgCtxt.getVariable("jwt_isValid");
    Assert.assertEquals(isValid, "true", "isValid");

    String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
    String isExpired = msgCtxt.getVariable("jwt_isExpired");
    Assert.assertEquals(jwt_issuer, issuer, "Issuer");
    Assert.assertEquals(isExpired, "false", "isExpired");

    String jwt_kid = msgCtxt.getVariable("jwt_kid");
    Assert.assertEquals(jwt_kid, kid, "jwt_kid");
  }

}

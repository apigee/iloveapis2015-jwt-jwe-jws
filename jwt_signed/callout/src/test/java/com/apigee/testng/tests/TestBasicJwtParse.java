package com.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.io.File;
import java.io.IOException;
import org.apache.commons.io.FileUtils;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.BeforeMethod;

import mockit.Mock;
import mockit.MockUp;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.execution.ExecutionResult;

import com.apigee.callout.jwtsigned.JwtParserCallout;

public class TestBasicJwtParse {
    private static String testDataDirPath = "src/test/resources/parse-basic";
    private static File testDataDir = new File(testDataDirPath);

    MessageContext msgCtxt;
    ExecutionContext exeCtxt;

    @BeforeMethod()
    public void testSetup1() {

        msgCtxt = new MockUp<MessageContext>() {
            private Map variables;
            public void $init() {
                variables = new HashMap();
            }

            @Mock()
            public <T> T getVariable(final String name){
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

        exeCtxt = new MockUp<ExecutionContext>(){ }.getMockInstance();
    }

    private static final Map<String, String> jwtMap;
    private static final Map<String, String> certMap;

    static {
        jwtMap = java.util.Collections.unmodifiableMap(readFilesIntoMap(".jwt"));
        certMap = java.util.Collections.unmodifiableMap(readFilesIntoMap(".cert"));
    }

    private static Map<String,String> readFilesIntoMap(String extension) {
        Map<String, String> m = new HashMap<String,String>();
        try {
            File[] files = testDataDir.listFiles();
            int extLength = extension.length();
            if (files != null && files.length > 0) {
                for (File file : files) {
                    String name = file.getName();
                    if (name.endsWith(extension)) {
                        String fileContents = FileUtils.readFileToString(file);
                        String shortName = name.substring(0,name.length()-extLength);
                        m.put(shortName, fileContents.trim() );
                    }
                }
            }

        }
        catch (IOException exc1) {
            // gulp
            exc1.printStackTrace();
        }
        return m;
    }

    @Test()
    public void test1_BadJwt() {
        String expectedReason = "the JWT did not parse.";
        Map properties = new HashMap();
        properties.put("jwt", "This is an invalid JWT, will not parse...");

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "false");
        Assert.assertEquals(reason, expectedReason);
        //Assert.assertNotNull(error);
    }


    @Test()
    public void MissingJwt() {
        String expectedReason = "jwt is not specified or is empty.";
        // now parse and verify
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        //properties.put("debug", "true"); // causes exception to be logged to stdout
        properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(isValid, "false", "isValid");
        Assert.assertEquals(reason, expectedReason, "reason");
    }


    @Test()
    public void test2_Rs256JwtMissingPemfile() {
        String expectedReason = "must specify pemfile or public-key or certificate when algorithm is RS*";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        //properties.put("debug", "true"); // causes exception to be logged to stdout
        properties.put("jwt", jwtMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(reason, expectedReason);
    }

    @Test()
    public void test2_Rs256JwtNonExistentPemfile() {
        String nonExistentPemFile = "This-pemfile-does-not-exist.pem";
        String expectedReason = "resource \"/" + nonExistentPemFile + "\" not found";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        //properties.put("debug", "true"); // causes exception to be logged to stdout
        properties.put("pemfile", nonExistentPemFile);
        properties.put("jwt", jwtMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(reason, expectedReason);
    }

    @Test()
    public void test2_Rs256JwtPemExistsButIsEmpty() {
        String emptyPemFile = "for-testing-only.pem";
        String expectedReason = "an invalid public key was provided";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        //properties.put("debug", "true"); // causes exception to be logged to stdout
        properties.put("pemfile", emptyPemFile);
        properties.put("jwt", jwtMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);
        Assert.assertEquals(reason, expectedReason);
    }

    @Test()
    public void test3_ExpiredJwt() {
        String expectedReason = "the token is expired";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("jwt", jwtMap.get("ms1"));
        properties.put("certificate", certMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String expiry = msgCtxt.getVariable("jwt_expirationTimeFormatted");
        String reason = msgCtxt.getVariable("jwt_reason");
        String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");
        String isExpired = msgCtxt.getVariable("jwt_isExpired");
        //System.out.println("test3 expiry: " + expiry);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "false");
        Assert.assertEquals(hasExpiry, "true");
        Assert.assertEquals(isExpired, "true");
        Assert.assertEquals(reason, expectedReason);
    }

    @Test()
    public void test4_MismatchedAlgorithm1() {
        String expectedReason = "Algorithm mismatch. provided=RS256, required=HS256";
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        properties.put("jwt", jwtMap.get("ms1"));
        properties.put("secret-key", "123456");

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String reason = msgCtxt.getVariable("jwt_reason");
        String isValid = msgCtxt.getVariable("jwt_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(reason, expectedReason);
        Assert.assertEquals(isValid, "false");
    }

    @Test()
    public void test4_MismatchedAlgorithm2() {
        String expectedReason = "Algorithm mismatch. provided=HS256, required=RS256";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("jwt", jwtMap.get("sample1"));
        properties.put("certificate", certMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "false");
        Assert.assertEquals(reason, expectedReason);
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

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");
        String isExpired = msgCtxt.getVariable("jwt_isExpired");
        String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS, "ExecutionResult");
        Assert.assertEquals(isValid,"true", "isValid");
        Assert.assertEquals(reason, null, "reason");
        Assert.assertEquals(isExpired, "false", "isExpired");
        Assert.assertEquals(hasExpiry, "false", "hasExpiry");
    }


    @Test()
    public void test5_SimpleClaims2() {
        String expectedReason = "mismatch in claim name, expected:Jane Williams provided:John Doe";
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        //properties.put("debug", "true");
        properties.put("jwt", jwtMap.get("sample1"));
        properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
        properties.put("claim_sub", "1234567890");
        properties.put("claim_name", "Jane Williams");

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String reason = msgCtxt.getVariable("jwt_reason");
        String isValid = msgCtxt.getVariable("jwt_isValid");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS, "ExecutionResult");
        Assert.assertEquals(isValid, "false", "isValid");
        Assert.assertEquals(reason, expectedReason, "reason");
    }

    @Test()
    public void test5_SimpleClaims3() {
        String expectedReason = "mismatch in claim sub, expected:ABCDEFG provided:1234567890";
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        //properties.put("debug", "true");
        properties.put("jwt", jwtMap.get("sample1"));
        properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
        properties.put("claim_sub", "ABCDEFG");
        properties.put("claim_name", "John Doe");

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS, "ExecutionResult");
        Assert.assertEquals(isValid, "false", "isValid");
        Assert.assertEquals(reason, expectedReason, "reason");
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

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");
        String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid,"true",);
        Assert.assertEquals(reason, null);
        Assert.assertEquals(hasExpiry,"false");
    }


    @Test()
    public void test5_ClaimVariable1() {
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        //properties.put("debug", "true");
        properties.put("jwt", jwtMap.get("sample1"));
        properties.put("secret-key", "secret123456-ABC**secret123456-ABC");
        properties.put("claim_sub", "1234567890");
        properties.put("claim_name", "John Doe");

        JwtParserCallout callout = new JwtParserCallout(properties);
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
        Map properties = new HashMap();
        properties.put("algorithm", "none");
        properties.put("debug", "true");
        properties.put("jwt", jwtMap.get("unsigned1"));
        properties.put("claim_username", "john.doe");

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid,"false");
        Assert.assertEquals(reason, expectedReason);
    }


    @Test()
    public void test7_BadHmacKey() {
        String expectedReason = "the signature could not be verified";
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

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String verified = msgCtxt.getVariable("jwt_verified");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid,"false");
        Assert.assertEquals(verified,"false");
        Assert.assertEquals(reason, expectedReason);
    }

    @Test()
    public void test8_ExpiredJwtDisabledTimeCheck() {
        //String expectedReason = "the token is expired";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("jwt", jwtMap.get("ms1"));
        properties.put("timeAllowance", "-1");
        properties.put("certificate", certMap.get("ms1"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String expiry = msgCtxt.getVariable("jwt_expirationTimeFormatted");
        String reason = msgCtxt.getVariable("jwt_reason");
        String hasExpiry = msgCtxt.getVariable("jwt_hasExpiry");
        String isExpired = msgCtxt.getVariable("jwt_isExpired");
        String isActuallyExpired = msgCtxt.getVariable("jwt_isActuallyExpired");
        String timeCheckDisabled = msgCtxt.getVariable("jwt_timeCheckDisabled");
        //System.out.println("test8 expiry: " + expiry);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "true");
        Assert.assertEquals(hasExpiry, "true");
        Assert.assertEquals(isActuallyExpired, "true");
        Assert.assertEquals(isExpired, "false");
        Assert.assertEquals(timeCheckDisabled, "true");
        //Assert.assertEquals(reason, expectedReason);
    }


    @Test()
    public void test9_Sample3() {
        String expectedReason = "the token is expired";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("jwt", jwtMap.get("sample3"));
        properties.put("certificate", certMap.get("sample3"));

        JwtParserCallout callout = new JwtParserCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String reason = msgCtxt.getVariable("jwt_reason");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(reason, expectedReason);
        Assert.assertEquals(isValid,"false");
    }

}

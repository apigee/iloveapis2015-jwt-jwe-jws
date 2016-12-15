package com.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;

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
        // TODO - put this data in a resources directory in the filesystem
        Map<String, String> m = new HashMap<String,String>();
        m.put("ms1", "eyJ0eXAiOiJKV1QiLCJhbGciOiJSUzI1NiIsIng1dCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSIsImtpZCI6Ik1uQ19WWmNBVGZNNXBPWWlKSE1iYTlnb0VLWSJ9.eyJhdWQiOiI2M2I0YzljMS05YTYyLTQ0OTctYjJmZS05YWY3MTMwNWEyMzciLCJpc3MiOiJodHRwczovL3N0cy53aW5kb3dzLm5ldC9mYTI2MTNkZC0xYzdiLTQ2OWItOGY5Mi04OGNkMjY4NTYyNDAvIiwiaWF0IjoxNDUyNjYxNTM2LCJuYmYiOjE0NTI2NjE1MzYsImV4cCI6MTQ1MjY2NTQzNiwiYW1yIjpbInB3ZCJdLCJlbWFpbCI6ImRwY2hpZXNhQGhvdG1haWwuY29tIiwiZmFtaWx5X25hbWUiOiJjaGllc2EiLCJnaXZlbl9uYW1lIjoiZGlubyIsImlkcCI6ImxpdmUuY29tIiwibmFtZSI6ImRpbm8gY2hpZXNhIiwibm9uY2UiOiJhYmNkZSIsIm9pZCI6ImY5NmYxNGM5LTc5MTAtNGNjNy1iM2I2LTM1YmU2MWMzNjhmMiIsInB3ZF9leHAiOiIwIiwicHdkX3VybCI6Imh0dHBzOi8vcG9ydGFsLm1pY3Jvc29mdG9ubGluZS5jb20vQ2hhbmdlUGFzc3dvcmQuYXNweCIsInN1YiI6IlhBT19xSnNybnd6amQ0MXljcDM4eUotNjRSVU1OMXhvZHlDQnllR3ZJQkkiLCJ0aWQiOiJmYTI2MTNkZC0xYzdiLTQ2OWItOGY5Mi04OGNkMjY4NTYyNDAiLCJ1bmlxdWVfbmFtZSI6ImxpdmUuY29tI2RwY2hpZXNhQGhvdG1haWwuY29tIiwidmVyIjoiMS4wIn0.cAWs-P-e-QbIK4FCFoPQUKBJL88Nw7wbPKuG443WpD76b-E4SQ8fAG5-GjLO7TTgmvvR4mWCrrSJ-MCvTcGtf3J5UIagvbUCfj1rTSPikLaGz96DL66WLVRPeSlegeHdAJOyqj6yCOzQSScdFfJu5I7t3joGUI4t1rCtvdCaT1fwqsZQ0GNDkle2lVSqMFyfMuiT1cGx4kTnzH-pDZ9hRePLOjNY9tKJaisk5J54Qlqz0Tgqzcvq3OD7MKN1IwHmZP8acGCiFdbISXaYEh-cLxjd19hIUX6lQPA7UzilHaJo3H1RVzpuhjWHF5VLB42ng5XUZXmFvjjDxa2GUkWeyw");
        m.put("sample1", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiZW1haWwiOiJqZDJAZXhtYXBsZS5jb20iLCJhZG1pbiI6dHJ1ZX0.DJZX3Nsuj7SN0B0XYgzKt5wWqkBlEefnCd_MRVxEmTA");
        m.put("sample2", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxN0M0QjEwNS00MDhFLTRGNUMtQTBCMS1FOTUxODYwODU1OUYiLCJnaXZlbl9uYW1lIjoiRGlubyIsImZhbWlseV9uYW1lIjoiQ2hpZXNhIiwiaXNzIjoidXJuOjBCOTA5MjAzLTQyREItNDdENy1CNzAyLUVFOTIwNTY0MEFDOCIsInNob2VzaXplIjoiOSJ9.mrsvlFYJ2oMfHAVE-v8dOspKbusOkt4BfwhwJh11JCo");
        m.put("unsigned1", "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpZCI6MTMzNywidXNlcm5hbWUiOiJqb2huLmRvZSJ9");
        m.put("sample3", "eyJhbGciOiJSUzI1NiJ9.eyJleHAiOjE0NTc0NTY2MjMsInVzZXJfbmFtZSI6InRlc3QjI2NvbWNhc3QiLCJhdXRob3JpdGllcyI6WyJST0xFX0FETUlOIiwiUk9MRV9VU0VSIl0sImp0aSI6IjljNDExZTc3LWQzZTItNDQ0Ny04ODJjLWYwODdhMTExZTBmYiIsImNsaWVudF9pZCI6ImFwaWdlZS10ZXN0Iiwic2NvcGUiOlsicmVhZCJdfQ.aQK7DEmRzZLH8_8kExoJaLd109CwOywiOilMgJU_h5l4Ohzl6BQs2auaGpOGSAQTTtixdVUcuKW51IfD8glR558r0cbhs2VC27q2PDibmcUsJUr68WOxko-uIveXITghY1OQEUQDV1cvd57uhaE-brgruHYC9h9TZ7lpD7Su20Itv4PdGj1uG7zobgXyaww2fzpNxzOWnCrQdpajhkkf1I3GA-c0fwVlYQpPqm4Qnwb5PPBAb2TX6IC5XgLBt1jdFvS-2Ayi4lWEUaxW6UjrgI8PhMbfEdieYg96wy9Zmn9VxMb7m9as8lmMnWvlL16ynHy4945VxnKEPncOl27tsw");
        jwtMap = java.util.Collections.unmodifiableMap(m);

        m = new HashMap<String,String>();
        m.put("ms1", "-----BEGIN CERTIFICATE-----\n" +
"MIIC4jCCAcqgAwIBAgIQQNXrmzhLN4VGlUXDYCRT3zANBgkqhkiG9w0BAQsFADAt\n" +
"MSswKQYDVQQDEyJhY2NvdW50cy5hY2Nlc3Njb250cm9sLndpbmRvd3MubmV0MB4X\n" +
"DTE0MTAyODAwMDAwMFoXDTE2MTAyNzAwMDAwMFowLTErMCkGA1UEAxMiYWNjb3Vu\n" +
"dHMuYWNjZXNzY29udHJvbC53aW5kb3dzLm5ldDCCASIwDQYJKoZIhvcNAQEBBQAD\n" +
"ggEPADCCAQoCggEBALyKs/uPhEf7zVizjfcr/ISGFe9+yUOqwpel38zgutvLHmFD\n" +
"39E2hpPdQhcXn4c4dt1fU5KvkbcDdVbP8+e4TvNpJMy/nEB2V92zCQ/hhBjilwhF\n" +
"1ETe1TMmVjALs0KFvbxW9ZN3EdUVvxFvz/gvG29nQhl4QWKj3x8opr89lmq14Z7T\n" +
"0mzOV8kub+cgsOU/1bsKqrIqN1fMKKFhjKaetctdjYTfGzVQ0AJAzzbtg0/Q1wdY\n" +
"NAnhSDafygEv6kNiquk0r0RyasUUevEXs2LY3vSgKsKseI8ZZlQEMtE9/k/iAG7J\n" +
"NcEbVg53YTurNTrPnXJOU88mf3TToX14HpYsS1ECAwEAATANBgkqhkiG9w0BAQsF\n" +
"AAOCAQEAfolx45w0i8CdAUjjeAaYdhG9+NDHxop0UvNOqlGqYJexqPLuvX8iyUaY\n" +
"xNGzZxFgGI3GpKfmQP2JQWQ1E5JtY/n8iNLOKRMwqkuxSCKJxZJq4Sl/m/Yv7TS1\n" +
"P5LNgAj8QLCypxsWrTAmq2HSpkeSk4JBtsYxX6uhbGM/K1sEktKybVTHu22/7TmR\n" +
"qWTmOUy9wQvMjJb2IXdMGLG3hVntN/WWcs5w8vbt1i8Kk6o19W2MjZ95JaECKjBD\n" +
"YRlhG1KmSBtrsKsCBQoBzwH/rXfksTO9JoUYLXiW0IppB7DhNH4PJ5hZI91R8rR0\n" +
"H3/bKkLSuDaKLWSqMhozdhXsIIKvJQ==\n" +
            "-----END CERTIFICATE-----\n");
        m.put("sample3", "-----BEGIN CERTIFICATE-----\n" +
"MIIDdTCCAl2gAwIBAgIEMUkvSTANBgkqhkiG9w0BAQsFADBrMQswCQYDVQQGEwJVUzELMAkGA1UE\n" +
"CBMCUEExGTAXBgNVBAcTEFBseW1vdXRoIE1lZXRpbmcxETAPBgNVBAoTCEFjY29sYWRlMQwwCgYD\n" +
"VQQLEwNFVEcxEzARBgNVBAMTClJvbiBBbGxldmEwHhcNMTYwMjA4MDY1MzQzWhcNMTYwNTA4MDY1\n" +
"MzQzWjBrMQswCQYDVQQGEwJVUzELMAkGA1UECBMCUEExGTAXBgNVBAcTEFBseW1vdXRoIE1lZXRp\n" +
"bmcxETAPBgNVBAoTCEFjY29sYWRlMQwwCgYDVQQLEwNFVEcxEzARBgNVBAMTClJvbiBBbGxldmEw\n" +
"ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQCWX1bhTErNhi3dndEdNW5EI10wb+fh6+BO\n" +
"IsS7EVBPIlBqFwHG6/ShwFiyqNDnY4+TZwTuDuN8iyHeaH1LEEW5UNs2pVmlL8JcSpR7h6svofPu\n" +
"ykHE0iGqgM2FovcqkrRge+lPe1Y/xBgdv/M4ck6wOZbGx45qLrEt4OzXwnq7mjonnywdclgmaa9z\n" +
"i5vlqOmQx6YcK+xGC0Pn+y5A56F4zeOYzFyOZlzfoJcKihHkU2NKZrZh7M6ZBTE2QVul26Q7TAi2\n" +
"5i8KetnYeZKOfSUuHYKX/aeiP7g+PQcnLQfU5oufCSDORZDmxlFdwsMPs4GsEQ0FTq23VCnMXA/5\n" +
"xuMHAgMBAAGjITAfMB0GA1UdDgQWBBQCRpmCetKOlvbXHjk2XU+fAZbN1DANBgkqhkiG9w0BAQsF\n" +
"AAOCAQEAayrUgvc7g4VwQ5ZPS/WqjFUWVBApGLoq1B3y2gmj+pbmq7Kchnca5dqGuSiP6ZVB85/L\n" +
"yV023rK46+qOB0JxhAycbY9uxWJZEDbgQ0ov5kMCYKogvGSl9uH8cV5HZzoXhhSwdhylVMyjrWKY\n" +
"Knh8Iqe4LEgguSm2LLB4kVeyJnlTeHy1VcuN9drzS5KlP3nmxEqJLb5IxUoW9KoT4bWSShlboNJh\n" +
"fGSUCZ4yp8IlANuSKJ05UNOHorW6FdTaZ+TCb4j3PCfb3cRwTxjk6qMu1sp8AN6AQ2AchPRhyg3U\n" +
"qv86xeUxpiXENHvPlWGtqBjrFn5NwFXwP81YPc5AI65CqQ==\n" +
"-----END CERTIFICATE-----");
        certMap = java.util.Collections.unmodifiableMap(m);
    }


    @Test()
    public void test1_BadJwt() {
        String expectedReason = "the JWT did not parse.";
        Map properties = new HashMap();
        properties.put("jwt", "The quick brown fox...");

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
        String expectedReason = "resource \"/resources/" + nonExistentPemFile + "\" not found";
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
        String expectedReason = "there was no public key specified.";
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
        Assert.assertEquals(isValid,"true");
        Assert.assertEquals(reason, null);
        Assert.assertEquals(hasExpiry,"false");
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

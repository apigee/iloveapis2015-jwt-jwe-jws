package com.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;
import java.io.IOException;
import java.io.File;
import org.apache.commons.io.FileUtils;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;

import mockit.Mock;
import mockit.MockUp;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.DeserializationFeature;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.execution.ExecutionResult;

import com.apigee.callout.jwtsigned.JwtParserCallout;
import com.apigee.callout.jwtsigned.JwtCreatorCallout;

public class TestParseExtended {
    private static String testDataDir = "src/test/resources/parse";
    private static File testdir = new File(testDataDir);

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


    @Test
    public void testDataProviders() throws IOException {
        Object[][] tests = getDataForBatch1();
        System.out.println("extended tests: " + tests.length);
        Assert.assertTrue(tests.length > 0);
    }


    @Test
    public void testCreateThenVerify() throws IOException {
        String audUuid = java.util.UUID.randomUUID().toString();
        Map<String,String> createProps = new HashMap<String,String>();
        createProps.put("algorithm","HS256");
        createProps.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
        createProps.put("issuer","http://dinochiesa.net");
        createProps.put("subject","http://dinochiesa.net");
        createProps.put("audience", audUuid);
        createProps.put("debug", "true");
        createProps.put("expiresIn","1800");
        createProps.put("claim_motto","Iloveapis");
        JwtCreatorCallout callout1 = new JwtCreatorCallout(createProps);
        ExecutionResult result = callout1.execute(msgCtxt, exeCtxt);

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        String jwt = msgCtxt.getVariable("jwt_jwt");
        Assert.assertNotNull(jwt);

        // now verify the signature
        Map<String,String> verifyProps = new HashMap<String,String>();
        verifyProps.put("algorithm","HS256");
        verifyProps.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
        verifyProps.put("jwt", jwt);
        verifyProps.put("claim_sub","http://dinochiesa.net");
        verifyProps.put("debug", "true");
        verifyProps.put("claim_aud", audUuid);
        verifyProps.put("claim_motto","Iloveapis");
        JwtParserCallout callout2 = new JwtParserCallout(verifyProps);
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
        JwtParserCallout callout = new JwtParserCallout(tc.getInputProperties());
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // check result and output
        ExecutionResult expectedResult = getExpectedExecutionResult(tc);
        Assert.assertEquals(result, expectedResult);
        System.out.printf("\n** Test case : %s\n", tc.getTestName());

        // retrieve output
        Map<String,String> expected = tc.getExpected();
        for (String key : expected.keySet()) {
            if (!key.equals("result")) {
                String expectedValue = expected.get(key);
                String actualValue = msgCtxt.getVariable("jwt_" + key);
                System.out.printf("Examining: %s (%s)\n", key, actualValue);
                Assert.assertEquals(actualValue, expectedValue, key);
            }
        }
        System.out.printf("\n\n");
        // String isValid = msgCtxt.getVariable("jwt_isValid");
        // String reason = msgCtxt.getVariable("jwt_reason");
        // Assert.assertEquals(reason, expected.get("reason"));
        // Assert.assertEquals(isValid, expected.get("isValid"));
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
        //System.out.println("dir name: " + testdir.getAbsolutePath());
        File[] files = testdir.listFiles();
        if (files != null && files.length > 0) {
            int c = 0;
            ArrayList<TestCase> list = new ArrayList<TestCase>();
            for (File file : files) {
                String name = file.getName();
                if (name.endsWith(".json")) {
                    TestCase tc = om.readValue(file, TestCase.class);
                    tc.setTestName(name.substring(0,name.length()-5));
                    readInFileData(tc);
                    list.add(tc);
                }
            }

            // I could not figure an easier way to generate a 2-d array...
            int n = list.size();
            data = new Object[n][];
            for (int i = 0; i < n; i++) {
                data[i] = new Object[]{ list.get(i) };
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
                File file = new File(testdir, filename);
                String fileContents = FileUtils.readFileToString(file);
                tc.getInputProperties().put(propName, fileContents);
            }
        }
    }

    private static ExecutionResult getExpectedExecutionResult(TestCase tc) {
        String value = tc.getExpected().get("result");
        return (value.toLowerCase().equals("success")) ?
            ExecutionResult.SUCCESS : ExecutionResult.ABORT;
    }

}

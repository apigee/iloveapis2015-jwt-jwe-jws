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

public class TestParseExtended {
    private static String testDataDir = "src/test/resources/test-cases";
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

    @Test(dataProvider = "batch1")
    public void test2_Configs(TestCase tc) {
        JwtParserCallout callout = new JwtParserCallout(tc.getInputProperties());
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // check result and output
        ExecutionResult expectedResult = getExpectedExecutionResult(tc);
        Assert.assertEquals(result, expectedResult);

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

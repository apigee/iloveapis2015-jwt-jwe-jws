package com.apigee.testng.tests;

import java.util.HashMap;
import java.util.Map;
import java.util.ArrayList;

import org.testng.Assert;
import org.testng.annotations.Test;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.DataProvider;

import mockit.Mock;
import mockit.MockUp;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.message.MessageContext;
import com.apigee.flow.execution.ExecutionResult;

import com.apigee.callout.jwe.JweEncryptorCallout;
import com.apigee.callout.jwe.JweDecryptorCallout;

import java.nio.charset.StandardCharsets;
import org.apache.commons.ssl.PKCS8Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyFactory;

import org.apache.commons.lang.RandomStringUtils;
import org.apache.commons.lang.StringUtils;

public class TestJweCreation {
    MessageContext msgCtxt;
    ExecutionContext exeCtxt;

    //private static final Map<String, String> privateKeyMap;
    //private static final Map<String, String> publicKeyMap;

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


    @Test()
    public void BasicCreateAndParse() {
        String secretKey = "ABCDEFGH12345678_ABCDEFGH12345678";
        String plainText = "The quick brown fox jumps over the lazy dog";
        String alg = "A128CBC-HS256";

        Map properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", secretKey);
        properties.put("plaintext", plainText);

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String jwe = msgCtxt.getVariable("jwe_jwe");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        // now parse and verify
        properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", secretKey);
        properties.put("jwe", jwe);
        JweDecryptorCallout callout2 = new JweDecryptorCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);

        String jwe_plainText = msgCtxt.getVariable("jwe_plaintext");
        String error = msgCtxt.getVariable("jwe_error");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(jwe_plainText, plainText, "Plaintext");
    }

    @Test()
    public void BasicCreateAndParse_Variables() {
        String secretKey = "ABCDEFGH12345678_ABCDEFGH12345678";
        String plainText = "The quick brown fox jumps over the lazy dog";
        String alg = "A128CBC-HS256";

        msgCtxt.setVariable("secretKey", secretKey);
        msgCtxt.setVariable("plainText", plainText);

        Map properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}"); // a variable reference
        properties.put("plaintext", "{plainText}");

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String jwe = msgCtxt.getVariable("jwe_jwe");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        msgCtxt.setVariable("computed_jwe", jwe);

        // now parse and verify
        properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}");
        properties.put("jwe", "{computed_jwe}");
        JweDecryptorCallout callout2 = new JweDecryptorCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);

        String jwe_plainText = msgCtxt.getVariable("jwe_plaintext");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(jwe_plainText, plainText, "Plaintext");
    }

    @Test()
    public void BadEncryptionAlgorithm() {
        String secretKey = "ABCDEFGH12345678_ABCDEFGH12345678";
        String plainText = "The quick brown fox jumps over the lazy dog";
        String bogusAlg = "A128SKiddo-HS256";

        msgCtxt.setVariable("secretKey", secretKey);
        msgCtxt.setVariable("plainText", plainText);

        Map properties = new HashMap();
        properties.put("algorithm", bogusAlg);
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}"); // a variable reference
        properties.put("plaintext", "{plainText}");

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.ABORT);

        String error = msgCtxt.getVariable("jwe_error");
        String expectedError = "Exception java.lang.IllegalStateException: unsupported algorithm: '"+bogusAlg+"'";
        Assert.assertEquals(error, expectedError, "error");
    }

    @Test()
    public void BadDecryptionAlgorithm() {
        String secretKey = "ABCDEFGH12345678_ABCDEFGH12345678";
        String plainText = "The quick brown fox jumps over the lazy dog";
        String alg = "A128CBC-HS256";

        msgCtxt.setVariable("secretKey", secretKey);
        msgCtxt.setVariable("plainText", plainText);

        Map properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}"); // a variable reference
        properties.put("plaintext", "{plainText}");

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String jwe = msgCtxt.getVariable("jwe_jwe");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        msgCtxt.setVariable("computed_jwe", jwe);

        // now parse and verify
        properties = new HashMap();
        properties.put("algorithm", "hello");
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}");
        properties.put("jwe", "{computed_jwe}");
        JweDecryptorCallout callout2 = new JweDecryptorCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);
        Assert.assertEquals(result, ExecutionResult.ABORT);

        String error = msgCtxt.getVariable("jwe_error");
        String expectedError = "Exception java.lang.IllegalStateException: unsupported algorithm: 'hello'";
        Assert.assertEquals(error, expectedError, "error");
    }

    @Test
    public void MismatchedDecryptionAlgorithm() {
        String secretKey = "ABCDEFGH12345678_ABCDEFGH12345678";
        String plainText = "The quick brown fox jumps over the lazy dog";
        String alg = "A128CBC-HS256";

        msgCtxt.setVariable("secretKey", secretKey);
        msgCtxt.setVariable("plainText", plainText);

        Map properties = new HashMap();
        properties.put("algorithm", alg);
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}"); // a variable reference
        properties.put("plaintext", "{plainText}");

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String jwe = msgCtxt.getVariable("jwe_jwe");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        msgCtxt.setVariable("computed_jwe", jwe);

        // now parse and verify
        properties = new HashMap();
        properties.put("algorithm", "A128GCM");
        properties.put("debug", "true");
        properties.put("secret-key", "{secretKey}");
        properties.put("jwe", "{computed_jwe}");
        JweDecryptorCallout callout2 = new JweDecryptorCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);
        Assert.assertEquals(result, ExecutionResult.ABORT);

        String error = msgCtxt.getVariable("jwe_error");
        String expectedError = "Algorithm mismatch: found [A128CBC-HS256], expected [A128GCM]";
        Assert.assertEquals(error, expectedError, "error");
    }


    @DataProvider(name = "batch1")
    public static Object[][] getDataForBatch1() {
        Object[][] supportedAlgorithms = new Object[][] {
            new Object[] {"A128CBC-HS256"},
            new Object[] {"A192CBC-HS384"},
            new Object[] {"A256CBC-HS512"},
            new Object[] {"A128GCM"},
            new Object[] {"A192GCM"},
            new Object[] {"A256GCM"}
        };

        return supportedAlgorithms;
    }


    @Test(dataProvider = "batch1")
    public void testGoodAlgorithms(String algorithm) {
        // this will get called once, for each supported algorithm
        String secretKey = RandomStringUtils.random(32);
        String plainText = "The quick brown fox jumps over the lazy dog.";

        Map properties = new HashMap();
        properties.put("algorithm", algorithm);
        properties.put("debug", "true");
        properties.put("secret-key", secretKey);
        properties.put("plaintext", plainText);

        JweEncryptorCallout callout = new JweEncryptorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // retrieve output
        String jwe = msgCtxt.getVariable("jwe_jwe");

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        // now parse and verify
        properties = new HashMap();
        properties.put("algorithm", algorithm);
        properties.put("debug", "true");
        properties.put("secret-key", secretKey);
        properties.put("jwe", jwe);
        JweDecryptorCallout callout2 = new JweDecryptorCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);

        String jwe_plainText = msgCtxt.getVariable("jwe_plaintext");
        String error = msgCtxt.getVariable("jwe_error");
        String jwe_algorithm = msgCtxt.getVariable("jwe_algorithm");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(jwe_plainText, plainText, "Plaintext");
        Assert.assertEquals(jwe_algorithm, algorithm, "Algorithm");
        Assert.assertTrue(StringUtils.isEmpty(error), "error");
    }

}

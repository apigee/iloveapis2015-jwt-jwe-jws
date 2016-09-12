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
        //System.out.println("jwe: " + jwe);
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
        System.out.println("jwe: " + jwe);
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
        // System.out.println("jwe: " + jwe);
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
        // String expectedError = "Algorithm mismatch: found [A128CBC-HS256], expected [hello]";
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
        //System.out.println("jwe: " + jwe);
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
        //String expectedError = "Exception java.lang.IllegalStateException: unsupported algorithm: 'hello'";
        Assert.assertEquals(error, expectedError, "error");
    }

}

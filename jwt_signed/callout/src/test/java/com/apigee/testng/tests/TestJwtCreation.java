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

import com.apigee.callout.jwtsigned.JwtCreatorCallout;
import com.apigee.callout.jwtsigned.JwtParserCallout;


import java.nio.charset.StandardCharsets;
import org.apache.commons.ssl.PKCS8Key;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.PrivateKey;
import java.security.NoSuchAlgorithmException;
import java.security.GeneralSecurityException;
import java.security.spec.InvalidKeySpecException;
import java.security.KeyFactory;


public class TestJwtCreation {

    MessageContext msgCtxt;
    ExecutionContext exeCtxt;

    private static final Map<String, String> privateKeyMap;
    private static final Map<String, String> publicKeyMap;
    static {
        // TODO - put this data in a resources directory in the filesystem
        Map<String, String> m = new HashMap<String,String>();
        m.put("rsa1",
              "-----BEGIN PUBLIC KEY-----\n" +
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAyyTD+a4vyRx2Ng4LH/+D\n" +
              "di19c42W5dk/OVNor31IcEvN2H9GvTruOQZLJ29yka2SajiV3xJUjjxCTD9y9F14\n" +
              "Tj/E1z3JEa3rMIorh+EadABQn+qjkXjYAD8ASAjdZfaDSciS5D5cKgafxEV/0DwW\n" +
              "xlM1ZVmtEn6IdPNYpfuSuilhd1rP/VANiLMzmnrb6ZkNGdUzW6MYRz8tiA7VPkTH\n" +
              "DyN6+jclCucq5WTiC871PgA/nR81yY7FLiF0mElaveXf/PecSn5A3wOC/wKch55y\n" +
              "ATxhWpB0sA7tnIBDUX/XX4jn63RfmxmVTvol3QYMDGbyz4MB3LWTtojVK2QUaUib\n" +
              "qQIDAQAB\n" +
              "-----END PUBLIC KEY-----\n");
        m.put("rsa2",
              "-----BEGIN PUBLIC KEY-----\n" +
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Cu87vr/HH8LTsafFczZ\n" +
              "YSF8Qee6cLOd2NQmEcTLQWnAKlebBLY58c63ig3QYWocravtkqULKfImjOg7xA5E\n" +
              "npeiwlVyhfKwooFq5u40k2ob0Mq3LI+/ZCKGvraJ53D1PyLhAt/ZwFqwpJ8Ja111\n" +
              "GnVtUf7rr6+wChXx7XlEDmNpIyn3eepVJcjE2Hpb6WCP7/mPgpRsDjYE5Yw2PxUt\n" +
              "N2P26R8tVTsaIrex74yON7ERvB6Hud4YF+XQCypgQFcVhN5DG5WYX22snr1bt3XC\n" +
              "pHbBk+cVJ5nJ8lRjpE0j9KU/30pYNOKWKChoEsnv2iMQkECf5hJU0e13bIUiROXn\n" +
              "6wIDAQAB\n" +
              "-----END PUBLIC KEY-----\n");
        publicKeyMap = java.util.Collections.unmodifiableMap(m);

        m = new HashMap<String,String>();
        // I think maybe AES256 will not work with my verison of Java since
        // I don't have the strong export encryption enabled.
        m.put("rsa1",
              "-----BEGIN RSA PRIVATE KEY-----\n" +
              "Proc-Type: 4,ENCRYPTED\n" +
              "DEK-Info: AES-256-CBC,DD5944845780879E302AF51BCB178DB2\n" +
              "\n" +
              "WOARk4xK3r4UY0uC7clRKnecTpOlZ6tiy7SvY8l01dbmdWzryVStifgth8uy3rYm\n" +
              "YQFn0fwhLn4/+643o7ppCXmdMnW5y81au6yaAFAk97W42xkqnguLAzzgUr7Y/Ygq\n" +
              "zWuLaxsnxq8s8qjuy9E5Z8aCF+DDzB5riiOdR2f6gxTXFaVSRaQGQV68AMjCovWp\n" +
              "5faDxvSqLKnL5uUG5IPkFgqTKTIQzu54bmTy5ejmSfsz3LOy99ggc5OPPv01GPqX\n" +
              "aIdCwZekP+/mD9q4WBoVTFUhu3ifJK6CHdp6fpVLRDA0itz8BiZhh4ys9V2eYGNf\n" +
              "/zKHpTh+BWe5Gjpof8N5F3LPGFr9ttygiumHUR2v3Y1GVDWCOL733V8jGjpTlbxi\n" +
              "BO4v6fA2TKoSLNAXFT5JiAquYdDZ4bwcGqFRuoz/VZ/lMiEnGfqAW2cl1U5N5koe\n" +
              "wS2hb6WvZMLTX+f3yixXH2Hgqq6NEED/of8i4IHhv7+84XGhGaaSBQNRuzUqDwKQ\n" +
              "Qrr9KcWbH6H4rOCOuQ+jEOm4QjEFdxAGu710TVJX0ApvUTZfsR/FEJDxwNopvI4w\n" +
              "NQ7IE9ZLwI7vcwPb/scmUox7+4ON8h1v6qM2lfn/IdefI91D4IvxFQd/+4dogXpY\n" +
              "SmpFxKkBaJMSqoAZISIkZginub0EM/ULQ/QLpGGmh99BpwiReIveSWdV9UG4E5Ml\n" +
              "dFeZf3YpfVDck96sZd46Y7vKz/aIgNvsa9pJUrOIQC9ggxQs4kHOR4h7zpAqtWVW\n" +
              "oeA4bVqvCScG9PzYTGssQLAzWGITPOYa21F18O6x21kwkocWAFrPpFSe+qCXTNKP\n" +
              "Dbq2gIKwi/ffQfqLIok2Z5jjnK/cXndvKps3HHo4kUpG/e2f71zATKPrfOFndI4P\n" +
              "uShXZXL8+eWFD65776iA4Rp+DNO/8bYsGJpbbzRHZRNPyE32qBuDrv+QYnuqou9U\n" +
              "9jbj6N4OFaeis+GXYiCtWtLBMGFES0UVdQlkMcNCsr2fzDpBCBv6Pv0HN5ltjKJ5\n" +
              "/q1Xn+ThnqyPhxt1urJ0gIqOiEijAdMbAZ4J0cUzymbqG5YI4XM6mOpiyd+VSR94\n" +
              "SXcUt9Gb/nG2lAuqL156yRWW6k5pditPF6x5Z7nMbsIsHLmmPWfTyOAAQjQaBJ43\n" +
              "AzI2IQs7aBf1pUcal5oBP3agghCvaIPsv8T7DqYBaLpwD3e8OxvSrtxFtAQhi42b\n" +
              "m6TV3hlQkNjDSka5vQ4vaJiUL+RlOd5erv3YE0prFJVvBLMEBb1IB0AGv/FMfVG8\n" +
              "enYwiiCISze3238ulWUhH9n88FeuUdT9ga774QowcZe2f0eceisOLmeRPuRCAdHQ\n" +
              "C44d0mtkUuh8z/XJH9Scuipbf13WWr8IRMDP3sIGtF8ZKJm6FwUSVhFKpXoc/m9n\n" +
              "C3zTFRkPMu++6xzQm2EwlKjU7Ihu+JplGz6I4GAkjf1ZWQSqRwt8zhy8P+OaRNfn\n" +
              "BUmpuF4gmA/u+3Dk7XtTipsS4ARGnbvi04AixYgsY6mF1fNdDX8mL+jIIugE61Lq\n" +
              "bsCb8ugzVWVUUvb48x6xvUOebjh7AzvtUFqDpjaxEdEtDf8pXxtZu+rQ9G1MAJ8+\n" +
              "-----END RSA PRIVATE KEY-----\n");
        m.put("rsa2",
              "-----BEGIN PRIVATE KEY-----\n" +
              "MIIEvgIBADANBgkqhkiG9w0BAQEFAASCBKgwggSkAgEAAoIBAQDUK7zu+v8cfwtO\n" +
              "xp8VzNlhIXxB57pws53Y1CYRxMtBacAqV5sEtjnxzreKDdBhahytq+2SpQsp8iaM\n" +
              "6DvEDkSel6LCVXKF8rCigWrm7jSTahvQyrcsj79kIoa+tonncPU/IuEC39nAWrCk\n" +
              "nwlrXXUadW1R/uuvr7AKFfHteUQOY2kjKfd56lUlyMTYelvpYI/v+Y+ClGwONgTl\n" +
              "jDY/FS03Y/bpHy1VOxoit7HvjI43sRG8Hoe53hgX5dALKmBAVxWE3kMblZhfbaye\n" +
              "vVu3dcKkdsGT5xUnmcnyVGOkTSP0pT/fSlg04pYoKGgSye/aIxCQQJ/mElTR7Xds\n" +
              "hSJE5efrAgMBAAECggEARsecjMDw8Cm1tP7vvU8MSanpEPdkLArPorELTiwvfk/w\n" +
              "CnAVR9oetHs4oXaASK8kiA9t/tjOQ50DnUgv//SekaWWZ2wn+2V95Yh1CDr5ESB5\n" +
              "zQqDVvtRZu9Zsi+lC6+UMQ7Kr7HLq67VdOWVN9sCoOQBpzP6ni5m9MZjYcxtlrqZ\n" +
              "L1eI5J4QbDJMt6uebPsHsI/JY7KO/48cYlfIGVMX8kARI5Nn1PYrvFRIXJ9bAkwg\n" +
              "8DAIJLHSjiulw7nXd7wKDtC6Sik9Of3R785OJwmhHt0OjEwhzC68fSfSka4+itH2\n" +
              "01C5x96drBxtrk0fgsUrEpvGiiXffO6jBMmeT6nOGQKBgQD8aXvsBtDoyLYhtHX6\n" +
              "3N2XyHpX5oANDkBeW5o7PAqY3+0Ns9dGqvVePzuvGavy6Mg4Rv/McBSKUY10v2J0\n" +
              "LLXH5F0hjVowWtaTAzSVv+eXy08KjYvA9R6U/QhU1DIsH8Pm6MWNhpS09roFYup4\n" +
              "EtV03ZYpD44+fxm+qR0JNmX2HQKBgQDXL9Fta1wnbZAObuTeSMkfno0j37aGV3Y1\n" +
              "GBIPC5M8PKxq9n1EZMQdob+QxsaUzUxFKt8xcyUYErvu4BtlNtJ/ELSLmJyrt+HX\n" +
              "WV++lg4B6CcT7A+7kCM3KSpinD9Dpf2JMLIYA4IMxDqxA3e/0LWfooVDGHUyf5QV\n" +
              "FgUVQnDXpwKBgA3bhLAql6GQE1+6VpfVNF025nCY+QK+e44ynT8PRs2pzYvpCbKZ\n" +
              "hCsOcaplUGlfmk5sp3KD3LzTSV7VewRByCEXSn2jEwaAljMwA90M0hwlT0uXBcss\n" +
              "KeeoFKMDm1WM0OaGdQIWF2fv+7p7+b9p2Uo3OB08+2Q2+iTbh/qPf/2JAoGBAJo5\n" +
              "IUXkniV79rUBcXKGg+7veYRuf6iE4qlm2PqDd0DC02fNxTXRamU6WctvSz+2a6Ve\n" +
              "9pvARKOeOacYY0oFIpQC6wLpm8/OeEQZP++eJ+fh9K/ojdYFldeg30nRZd4cBzvd\n" +
              "9KYVTY3Mzau0Ko0FDkac+hl+W/CXUxBRuc7k0W8dAoGBAJJmzAzthHokAkDSBcTP\n" +
              "Z4oAyblSB3fyobtzzYVfL6yNPGn4UmnS+xGjO2IhP+eJe+wXvDifFnNByNEtAt1+\n" +
              "c8U8IFeovpiKV46il5mF4R9fqQxy+QUbFyjovv753C/qnllkZxu/eXZad2s15N5u\n" +
              "BFKnyL9NPjSDizDqyLocLYt5\n" +
              "-----END PRIVATE KEY-----\n");
                      privateKeyMap = java.util.Collections.unmodifiableMap(m);
    }

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
        String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
        String audience = "everyone";
        String subject = "urn:F5CF2B90-DDF3-47EB-82EB-F67A5B561FD2";
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        properties.put("debug", "true");
        properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
        properties.put("subject", subject);
        properties.put("issuer", issuer);
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
        JwtParserCallout callout2 = new JwtParserCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);

        String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String isExpired = msgCtxt.getVariable("jwt_isExpired");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(jwt_issuer, issuer, "Issuer");
        Assert.assertEquals(isExpired, "false", "isExpired");
        Assert.assertEquals(isValid, "true", "isValid");
    }

    @Test()
    public void BasicCreateAndParseMultiAudience() {
        String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
        String audience = "everyone,anyone";
        String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
        Map properties = new HashMap();
        properties.put("algorithm", "HS256");
        properties.put("debug", "true");
        properties.put("secret-key", "ABCDEFGH12345678_ABCDEFGH12345678");
        properties.put("subject", subject);
        properties.put("issuer", issuer);
        properties.put("audience", audience);

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
        JwtParserCallout callout2 = new JwtParserCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);

        String jwt_issuer = msgCtxt.getVariable("jwt_issuer");
        String isValid = msgCtxt.getVariable("jwt_isValid");
        String isExpired = msgCtxt.getVariable("jwt_isExpired");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(jwt_issuer, issuer, "Issuer");
        Assert.assertEquals(isValid, "true", "isValid");
        Assert.assertEquals(isExpired, "false", "isExpired");

        // now verify audience "everyone"
        properties.put("claim_aud", "everyone");
        properties.put("claim_sub", subject);
        callout2 = new JwtParserCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);
        isValid = msgCtxt.getVariable("jwt_isValid");
        isExpired = msgCtxt.getVariable("jwt_isExpired");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "true", "isValid");
        Assert.assertEquals(isExpired, "false", "isExpired");

        // now try verify audience "someone", should return "not valid"
        properties.put("claim_aud", "someone");
        properties.put("claim_sub", subject);
        callout2 = new JwtParserCallout(properties);
        result = callout2.execute(msgCtxt, exeCtxt);
        isValid = msgCtxt.getVariable("jwt_isValid");
        isExpired = msgCtxt.getVariable("jwt_isExpired");
        String reason = msgCtxt.getVariable("jwt_reason");

        Assert.assertEquals(result, ExecutionResult.SUCCESS);
        Assert.assertEquals(isValid, "false", "isValid");
        Assert.assertEquals(isExpired, "false", "isExpired");
        Assert.assertEquals(reason, "audience violation", "audience");
    }


    private void tryDeserializeKey(String key, String password)
        throws InvalidKeySpecException, GeneralSecurityException, NoSuchAlgorithmException
    {
        byte[] keybytes = key.getBytes(StandardCharsets.UTF_8);
        // If the provided data is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        PKCS8Key pkcs8 = new PKCS8Key( keybytes, password.toCharArray() );

        // If an unencrypted PKCS8 key was provided, then getDecryptedBytes()
        // actually returns exactly what was originally passed in (with no
        // changes). If an OpenSSL key was provided, it gets reformatted as
        // PKCS #8.
        byte[] decrypted = pkcs8.getDecryptedBytes();
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec( decrypted );

        // A Java PrivateKey object is born.
        PrivateKey pk = null;
        if ( pkcs8.isDSA() ) {
            pk = KeyFactory.getInstance( "DSA" ).generatePrivate( spec );
        }
        else if ( pkcs8.isRSA() ) {
            pk = KeyFactory.getInstance( "RSA" ).generatePrivate( spec );
        }
        return;
    }

    @Test()
    public void CreateBoxJwt() throws Exception {
        String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
        String issuer = "api-key-goes-here-78B13CD0-CEFD-4F6A-BB76";
        String audience = "https://api.box.com/oauth2/token";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("private-key", privateKeyMap.get("rsa2"));
        properties.put("private-key-password", "Secret123");
        properties.put("subject", subject);
        properties.put("issuer", issuer);
        properties.put("audience", audience);
        properties.put("expiresIn", "30"); // seconds
        properties.put("claim_box_sub_type", "enterprise");
        properties.put("claim_jti", java.util.UUID.randomUUID().toString());

        tryDeserializeKey(privateKeyMap.get("rsa2"), "Secret123");

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
        properties.put("public-key", publicKeyMap.get("rsa2"));
        JwtParserCallout callout2 = new JwtParserCallout(properties);
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

}

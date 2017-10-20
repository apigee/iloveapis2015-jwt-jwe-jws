package com.apigee.testng.tests;

import com.apigee.callout.jwtsigned.JwtCreatorCallout;
import com.apigee.callout.jwtsigned.JwtParserCallout;
import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.message.MessageContext;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.TimeZone;
import mockit.Mock;
import mockit.MockUp;
import org.apache.commons.lang3.time.DateParser;
import org.apache.commons.lang3.time.FastDateFormat;
import org.apache.commons.ssl.PKCS8Key;
import org.testng.Assert;
import org.testng.annotations.BeforeMethod;
import org.testng.annotations.BeforeSuite;
import org.testng.annotations.BeforeTest;
import org.testng.annotations.Test;

public class TestJwtCreation {
    private final static ObjectMapper om = new ObjectMapper();

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
        // this one will use literal \n rather than actual newlines
        m.put("rsa2",
              "-----BEGIN PUBLIC KEY-----\\n" +
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA1Cu87vr/HH8LTsafFczZ\\n" +
              "YSF8Qee6cLOd2NQmEcTLQWnAKlebBLY58c63ig3QYWocravtkqULKfImjOg7xA5E\\n" +
              "npeiwlVyhfKwooFq5u40k2ob0Mq3LI+/ZCKGvraJ53D1PyLhAt/ZwFqwpJ8Ja111\\n" +
              "GnVtUf7rr6+wChXx7XlEDmNpIyn3eepVJcjE2Hpb6WCP7/mPgpRsDjYE5Yw2PxUt\\n" +
              "N2P26R8tVTsaIrex74yON7ERvB6Hud4YF+XQCypgQFcVhN5DG5WYX22snr1bt3XC\\n" +
              "pHbBk+cVJ5nJ8lRjpE0j9KU/30pYNOKWKChoEsnv2iMQkECf5hJU0e13bIUiROXn\\n" +
              "6wIDAQAB\\n" +
              "-----END PUBLIC KEY-----\n");
        m.put("rsa3",
              "-----BEGIN PUBLIC KEY-----\n" +
              "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA7Wb9p0wqUwq5ZIpUG0+MgKwidb0TXeEV\n" +
              "i86bhhoaHwzuwZPdrZLanBCQCxp2gzp5WxW3huO91P89fXaX4IPqLWZn/s9aLxJk+ZiMfSrc49mJ\n" +
              "H99pZ4/eHA9LyGNVvQ1Yj6WIrdQIMBypwyWTYqOBLsQp6Ouo7K0t5c0XhKJUDuebdRx9WM7PSXVX\n" +
              "r+u8BwL3+BW03lHp4tFgZhYae16mMV3DNlgHuBAusB6tQZT4yrn/lPhueTf2ie7pz2OVdjT9C5fZ\n" +
              "+vRA23tvanusyP5j9zMGKR5sMSnPijwOLiOBPuMWcsFiLeL+LY3uV0Ii5mtIbS78UUVmncrin/6u\n" +
              "9Es1AwIDAQAB\n" +
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

        m.put("rsa3",
              "-----BEGIN RSA PRIVATE KEY-----\n" +
              "MIIEowIBAAKCAQEA7Wb9p0wqUwq5ZIpUG0+MgKwidb0TXeEVi86bhhoaHwzuwZPd\n" +
              "rZLanBCQCxp2gzp5WxW3huO91P89fXaX4IPqLWZn/s9aLxJk+ZiMfSrc49mJH99p\n" +
              "Z4/eHA9LyGNVvQ1Yj6WIrdQIMBypwyWTYqOBLsQp6Ouo7K0t5c0XhKJUDuebdRx9\n" +
              "WM7PSXVXr+u8BwL3+BW03lHp4tFgZhYae16mMV3DNlgHuBAusB6tQZT4yrn/lPhu\n" +
              "eTf2ie7pz2OVdjT9C5fZ+vRA23tvanusyP5j9zMGKR5sMSnPijwOLiOBPuMWcsFi\n" +
              "LeL+LY3uV0Ii5mtIbS78UUVmncrin/6u9Es1AwIDAQABAoIBAQCwgm2/8KJbYdLb\n" +
              "zPmh4LBvjwyEC9OVbmANtczulQOs6HmwVddxUYnWlX3zs3ZANb67GVd+JGAlOK0o\n" +
              "Vn+vv4Tiwow56UN9UijfZyu1eKQJiNkqaHq/NDmJFVpcIHdD++NH0mTgEZEQ7I7P\n" +
              "+GUv5q+K7PDYLDdJ2a0Rej6tL+Bdvym95munxONdtbb7WlIem74SzRYujKv8vlRL\n" +
              "8CwEs9xuf+RUgBChDHf80iSDzmpL3/CM9FONdQ17ieXCSMlGxfHSBDNlkIe21ODL\n" +
              "t/B5+KNCLmtzmcwQeQKIoyX9uMEMGfuZ/hirfkQ6qO7Ffq3fzFOMyz41XOfOaXcq\n" +
              "UgBXOj/JAoGBAPhCmcsTb9Jx4lOOH6UTVYPiFSJ9/7CBm9XewwHEcCmiKMW5LkZe\n" +
              "zO3WN3jwQrTr7eH6D/PH5KOIZ7+v9bV/vS/U+URo1bjP4ViibhdGMnzAJ8YPZ/3U\n" +
              "7/Kk3m1uGAP56vAdFI9ioqcoanfQNrUf5lxLv+DgvQjBcUPzxX4YSbFXAoGBAPTN\n" +
              "u2cNSMeAtUsVbaPr0DrShaemkJKs+4Ncb4kOcFkrDYez6mz+Y00TPfPkHJ5RSTn5\n" +
              "2XdzxkWG5zkFf8Ad5XMh8MhNZSwKILPrFibiCTwAS9OIB5/dcneEGBHxcSv9Pq2D\n" +
              "mYyUYEocqf0QRpg/5qwKElYViXViqpJtZz9CPbI1AoGAA6jHp4yjy1BOa7jekopU\n" +
              "als8wINm720ZpO9hpHcGyDZRr4hpPDRNhPvxWWEBOrV3jisnbQp3PknWbabkUkaN\n" +
              "vVTAT9fTvqOhyLKsOL+aIuiaLXswpzcqSkNP3AERbY2TfvKOyQZFK32XBCkXhVfx\n" +
              "B08+hswJPUXMq5m+QXuOKoUCgYBoeViOHUQ/KDW2ynlVKLFgOTIjH1m5zyszn4JW\n" +
              "KpxV4aLPlD/qrhIw9ZJOAL8Z7bTjkjZ13SnzyCPr2OXxVpDytrxsr2MLDXNxdVWp\n" +
              "2HN6cOHrb7VZS4era+td1P2oeVaDdJNWRIhneJ4vSv/lv/ew2keDB4P3XdlPznLu\n" +
              "s1VjNQKBgBZJxVm31P78875PIFcP8l5QXObxey6gF+1MtTblB54sXozItvgqtMHC\n" +
              "grMhGMdyANdgOWaor/Ti+74UXCO3wNPhiKtuc8tMs/fEPVGLwK1FDYWm6MHRhftJ\n" +
              "PBRaWgUQ9xa6BkPQOWzxZ/YWjlAV8182J6qji+0YoTWK5s7d6T2m\n" +
              "-----END RSA PRIVATE KEY-----\n");

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
        JwtParserCallout callout2 = new JwtParserCallout(properties);
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
    public void CreateAndParseWithGeneratedId() {
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
        JwtParserCallout callout2 = new JwtParserCallout(properties);
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
    public void BasicCreateAndParseMultiAudience() {
        String issuer = "urn:78B13CD0-CEFD-4F6A-BB76-AF236D876239";
        String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
        msgCtxt.setVariable("audienceVar", new String[] {"everyone","anyone"});
        Arrays.stream(new String[] { "audience","claim_aud"}).forEach(audienceProperty -> {
            Arrays.stream(new String[]{"everyone,anyone", "{audienceVar}"}).forEach(audience -> {
                Arrays.stream(new String[]{null, "true", "false"}).forEach((String continueOnErrorString) -> {
                    ExecutionResult expectedResult = ("true".equals(continueOnErrorString)) ?
                            ExecutionResult.SUCCESS : ExecutionResult.ABORT;

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

                    Assert.assertEquals(result, expectedResult);
                    Assert.assertEquals(isValid, "false", "isValid");
                    Assert.assertEquals(isExpired, "false", "isExpired");
                    Assert.assertEquals(reason, "audience violation", "audience");
                });
            });
        });
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

    @Test
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

    @Test
    public void CreateJwtWithKid() throws Exception {
        String subject = "urn:75E70AF6-B468-4BCE-B096-88F13D6DB03F";
        String issuer = "api-key-goes-here-78B13CD0-CEFD-4F6A-BB76";
        String audience = "urn://example.com";
        String kid = java.util.UUID.randomUUID().toString().replace("-","");
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("private-key", privateKeyMap.get("rsa2"));
        properties.put("private-key-password", "Secret123");
        properties.put("subject", subject);
        properties.put("issuer", issuer);
        properties.put("kid", kid);
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

        String jwt_kid = msgCtxt.getVariable("jwt_kid");
        Assert.assertEquals(jwt_kid, kid, "jwt_kid");
    }

    @Test
    public void CreateEdgeMicroJwt() throws Exception {
        String subject = "urn:edge-micro-apigee-com";
        String issuer = "http://apigee.com/edgemicro/";
        String audience = "everybody";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("private-key", privateKeyMap.get("rsa3"));
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
        properties.put("public-key", publicKeyMap.get("rsa3"));
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


    @Test
    public void CreateJwtWithArrayClaim() throws Exception {
        String subject = "urn:edge-micro-apigee-com";
        String issuer = "http://apigee.com/edgemicro/";
        String audience = "everybody";
        String[] apiProducts = { "product1", "product2" };

        msgCtxt.setVariable("api_products", apiProducts);
        msgCtxt.setVariable("my_issuer", issuer);
        msgCtxt.setVariable("my_subject", subject);

        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("private-key", privateKeyMap.get("rsa3"));
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
        properties.put("public-key", publicKeyMap.get("rsa3"));
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

        String apiProductsOut = msgCtxt.getVariable("jwt_claim_api_products_provided");
        Assert.assertEquals(apiProductsOut, "product1|product2", "api_products");
    }

    @Test
    public void CreateJwt_DefaultNotBeforeTime() throws Exception {
        Date now = new Date();
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("private-key", privateKeyMap.get("rsa3"));
        properties.put("expiresIn", "300"); // seconds
        properties.put("claim_testname", "CreateJwt_DefaultNotBeforeTime");
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
        String iatAsText = claimsNode.get("iat").asText();
        Assert.assertEquals(iatAsText, nbfAsText, "nbf and iat");
        int nbfSeconds = Integer.parseInt(nbfAsText);
        int secondsNow = (int) (now.getTime()/1000);
        int delta = Math.abs(secondsNow - nbfSeconds);
        Assert.assertTrue(delta<=1, "nbf");
    }

    @Test
    public void CreateJwt_ExplicitNotBeforeTime() throws Exception {
        String notBeforeString = "2017-08-14T11:00:21.269-0700";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("not-before", notBeforeString);
        properties.put("private-key", privateKeyMap.get("rsa3"));
        properties.put("expiresIn", "300"); // seconds
        properties.put("claim_testname", "CreateJwt_ExplicitNotBeforeTime");
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

        DateParser dp = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss.SSSZ", TimeZone.getTimeZone("UTC"));
        Date notBefore = dp.parse(notBeforeString);
        int secondsNbfExpected = (int) (notBefore.getTime()/1000);
        int secondsNbfActual = Integer.parseInt(nbfAsText);
        Assert.assertEquals( secondsNbfActual, secondsNbfExpected, "nbf");
    }

    @Test
    public void CreateJwt_ExplicitNotBeforeTime2() throws Exception {
        String notBeforeString = "1508536333";
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("debug", "true");
        properties.put("not-before", notBeforeString);
        properties.put("private-key", privateKeyMap.get("rsa3"));
        properties.put("expiresIn", "300"); // seconds
        properties.put("claim_testname", "CreateJwt_ExplicitNotBeforeTime2");
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
        Assert.assertEquals( nbfAsText, notBeforeString, "notBeforeString");
    }

    @Test
    public void CreateJwt_ExcludeNotBeforeTime() throws Exception {
        Map properties = new HashMap();
        properties.put("algorithm", "RS256");
        properties.put("not-before", "false");
        properties.put("private-key", privateKeyMap.get("rsa3"));
        properties.put("expiresIn", "300"); // seconds
        properties.put("claim_testname", "CreateJwt_ExcludeNotBeforeTime");

        JwtCreatorCallout callout = new JwtCreatorCallout(properties);
        ExecutionResult result = callout.execute(msgCtxt, exeCtxt);

        // check result and output
        Assert.assertEquals(result, ExecutionResult.SUCCESS);

        // retrieve and check output
        String jwt = msgCtxt.getVariable("jwt_jwt");
        Assert.assertNotNull(jwt, "jwt");
        System.out.println("jwt: " + jwt);
        String jwtClaims = msgCtxt.getVariable("jwt_claims");
        Assert.assertNotNull(jwtClaims, "jwt_claims");
        System.out.println("claims: " + jwtClaims);

        JsonNode claimsNode = om.readTree(jwtClaims);
        Object nbf = claimsNode.get("nbf");
        Assert.assertNull(nbf, "nbf");

        Object iat = claimsNode.get("iat");
        Assert.assertNotNull(iat, "iat");
    }

}

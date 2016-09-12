package com.apigee.callout.jwe;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;

import java.io.IOException;
import java.io.InputStream;

import org.jose4j.jwk.JsonWebKey;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;

import org.apache.commons.ssl.PKCS8Key;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.text.StrSubstitutor;

import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.nio.charset.Charset;
// import java.security.interfaces.RSAPrivateKey;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

import com.apigee.utils.TemplateString;

@IOIntensive
public class JweEncryptorCallout implements Execution {
    private final static String _varPrefix = "jwe_";

    private Map<String,String> properties; // read-only

    public JweEncryptorCallout (Map properties) {
        // convert the untyped Map to a generic map
        Map<String,String> m = new HashMap<String,String>();
        Iterator iterator =  properties.keySet().iterator();
        while(iterator.hasNext()){
            Object key = iterator.next();
            Object value = properties.get(key);
            if ((key instanceof String) && (value instanceof String)) {
                m.put((String) key, (String) value);
            }
        }
        this.properties = m;
    }

    private static InputStream getResourceAsStream(String resourceName)
      throws IOException {
        // forcibly prepend a slash
        if (!resourceName.startsWith("/")) {
            resourceName = "/" + resourceName;
        }
        if (!resourceName.startsWith("/resources")) {
            resourceName = "/resources" + resourceName;
        }
        InputStream in = JweEncryptorCallout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
    }

    private String getPlainText(MessageContext msgCtxt) throws Exception {
        String plaintext = (String) this.properties.get("plaintext");
        if (plaintext == null || plaintext.equals("")) {
            throw new IllegalStateException("plaintext is not specified or is empty.");
        }
        plaintext = resolvePropertyValue(plaintext, msgCtxt);
        if (plaintext == null || plaintext.equals("")) {
            throw new IllegalStateException("plaintext is null or empty.");
        }
        return plaintext;
    }


    private String getSecretKey(MessageContext msgCtxt) throws Exception {
        String key = (String) this.properties.get("secret-key");
        if (key == null || key.equals("")) {
            throw new IllegalStateException("secret-key is not specified or is empty.");
        }
        key = resolvePropertyValue(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException("secret-key is null or empty.");
        }
        return key;
    }

    private String getAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = ((String) this.properties.get("algorithm")).trim();
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("algorithm is not specified or is empty.");
        }
        algorithm = resolvePropertyValue(algorithm, msgCtxt);
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        JweUtils.validateJweAlgorithm(algorithm);
        return algorithm;
    }


    private String getPrivateKeyPassword(MessageContext msgCtxt) {
        String password = (String) this.properties.get("private-key-password");
        if (password == null || password.equals("")) {
            // don't care. Use of a password on the private key is optional.
            return null;
        }
        password = resolvePropertyValue(password, msgCtxt);
        if (password == null || password.equals("")) { return null; }
        return password;
    }

    private PrivateKey getPrivateKey(MessageContext msgCtxt)
        throws IOException,
               GeneralSecurityException,
               NoSuchAlgorithmException,
               InvalidKeySpecException
    {
        byte[] keyBytes = null;
        String privateKey = (String) this.properties.get("private-key");
        String passwd = getPrivateKeyPassword(msgCtxt);
        if (privateKey==null) {
            String pemfile = (String) this.properties.get("pemfile");
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("must specify pemfile or private-key when algorithm is RS*");
            }
            pemfile = resolvePropertyValue(pemfile, msgCtxt);
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
            }

            InputStream in = getResourceAsStream(pemfile);

            keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();
        }
        else {
            if (privateKey.equals("")) {
                throw new IllegalStateException("private-key must be non-empty");
            }
            privateKey = resolvePropertyValue(privateKey, msgCtxt);
            if (privateKey==null || privateKey.equals("")) {
                throw new IllegalStateException("private-key variable resolves to empty; invalid when algorithm is RS*");
            }
            privateKey = privateKey.trim();
            // clear any leading whitespace on each line
            privateKey = privateKey.replaceAll("([\\r|\\n] +)","\n");
            keyBytes = privateKey.getBytes(Charset.forName("UTF-8"));
        }

        // If the provided data is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        PKCS8Key pkcs8 = new PKCS8Key( keyBytes, passwd.toCharArray() );

        // If an unencrypted PKCS8 key was provided, then getDecryptedBytes()
        // actually returns exactly what was originally passed in (with no
        // changes).  If an OpenSSL key was provided, it gets reformatted as
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
        return pk;
    }

    // If the value of a property value contains open and close curlies, eg,
    // {apiproxy.name} or ABC-{apikey}, then "resolve" the value by de-referencing
    // the context variables whose names appear between curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.indexOf('{') > -1 && spec.indexOf('}')>-1) {
            // Replace ALL curly-braced items in the spec string with
            // the value of the corresponding context variable.
            TemplateString ts = new TemplateString(spec);
            Map<String,String> valuesMap = new HashMap<String,String>();
            for (String s : ts.variableNames) {
                valuesMap.put(s, (String) msgCtxt.getVariable(s));
            }
            StrSubstitutor sub = new StrSubstitutor(valuesMap);
            String resolvedString = sub.replace(ts.template);
            return resolvedString;
        }
        return spec;
    }

    private static final String varName(String s) { return _varPrefix + s; }

    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt)
    {
        try {
            msgCtxt.removeVariable(varName("error"));
            String plaintext = getPlainText(msgCtxt);
            String secretKey = getSecretKey(msgCtxt);
            String algorithm = getAlgorithm(msgCtxt);
            String b64Key = Base64.encodeBase64String(secretKey.getBytes("UTF-8"));

            String jwkJson = "{\"kty\":\"oct\",\"k\":\""+ b64Key + "\"}";
            JsonWebKey jwk = JsonWebKey.Factory.newJwk(jwkJson);

            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setPlaintext(plaintext);
            jwe.setEncryptionMethodHeaderParameter(algorithm);
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.PBES2_HS256_A128KW);
            jwe.setKey(jwk.getKey());
            // do the encryption
            String compactSerialization = jwe.getCompactSerialization();
            msgCtxt.setVariable(varName("jwe"), compactSerialization);
        }
        catch (Exception e) {
            //e.printStackTrace();
            msgCtxt.setVariable(varName("error"), "Exception " + e.toString());
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}

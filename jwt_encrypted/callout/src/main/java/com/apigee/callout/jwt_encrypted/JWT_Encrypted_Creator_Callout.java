package com.apigee.callout.jwt_encrypted;

import java.io.IOException;
import java.io.InputStream;

import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.UUID;

import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang.exception.ExceptionUtils;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;
import org.jose4j.jwe.JsonWebEncryption;
import org.jose4j.jwe.KeyManagementAlgorithmIdentifiers;
import org.jose4j.jwt.JwtClaims;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import sun.misc.BASE64Encoder;

public class JWT_Encrypted_Creator_Callout implements Execution {
    private Map<String,String> properties; // read-only

    public JWT_Encrypted_Creator_Callout (Map properties) {
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


    // If the value of a property value begins and ends with curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variable whose name appears between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.startsWith("{") && spec.endsWith("}")) {
            String varname = spec.substring(1,spec.length() - 1);
            String value = msgCtxt.getVariable(varname);
            return value;
        }
        return spec;
    }


    private String getVarname(String label) {
        //String varName = "jwt." + stepName + "." + label;
        String varName = "jwt_" + label;
        return varName;
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
        InputStream in = JWT_Encrypted_Creator_Callout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
    }


    private static String getCleanEncodedKeyString(String publicKey)
        throws InvalidKeySpecException {
        publicKey = publicKey.trim();
        if (publicKey.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
            publicKey.endsWith("-----END RSA PUBLIC KEY-----")) {
            // figure PKCS#1
            publicKey = publicKey.substring(30, publicKey.length() - 28);
            publicKey = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + publicKey;
        }
        else if (publicKey.startsWith("-----BEGIN PUBLIC KEY-----") &&
                 publicKey.endsWith("-----END PUBLIC KEY-----")) {
            // figure PKCS#8
            publicKey = publicKey.substring(26, publicKey.length() - 24);
        }
        else {
            throw new InvalidKeySpecException("invalid key format");
        }

        publicKey = publicKey.replaceAll("\\|","\n");
        publicKey = publicKey.replaceAll("[\\r|\\n| ]","");
        return publicKey;
    }



    private PublicKey getPublicKey(MessageContext msgCtxt)
    // GeneralSecurityException,
        throws IOException,
               NoSuchAlgorithmException,
               InvalidKeySpecException
    {
        byte[] keyBytes = null;
        String publicKey = (String) this.properties.get("public-key");
        if (publicKey==null) {
            String pemfile = (String) this.properties.get("pemfile");
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("must specify pemfile or public-key when algorithm is RS*");
            }
            pemfile = resolvePropertyValue(pemfile, msgCtxt);
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
            }

            InputStream in = getResourceAsStream(pemfile);

            keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();

            publicKey = new String(keyBytes, "UTF-8");
        }
        else {
            if (publicKey.equals("")) {
                throw new IllegalStateException("public-key must be non-empty");
            }
            publicKey = resolvePropertyValue(publicKey, msgCtxt);
            if (publicKey==null || publicKey.equals("")) {
                throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
            }
        }

        publicKey = getCleanEncodedKeyString(publicKey);
        keyBytes = Base64.decodeBase64(publicKey);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }


    private String getIssuer(MessageContext msgCtxt) throws Exception {
        String issuer = (String) this.properties.get("issuer");
        if (issuer == null || issuer.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        issuer = resolvePropertyValue(issuer, msgCtxt);
        if (issuer == null || issuer.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        return issuer;
    }



    private String getExpirationInMinutes(MessageContext msgCtxt) throws Exception {
        String expirationInMinutes = (String) this.properties.get("expirationInMinutes");
        if (expirationInMinutes == null || expirationInMinutes.equals("")) {
            throw new IllegalStateException("expirationInMinutes is not specified or is empty.");
        }
        expirationInMinutes = resolvePropertyValue(expirationInMinutes, msgCtxt);
        if (expirationInMinutes == null || expirationInMinutes.equals("")) {
            throw new IllegalStateException("expirationInMinutes is not specified or is empty.");
        }
        return expirationInMinutes;
    }



    public ExecutionResult execute (MessageContext msgCtxt,
                                    ExecutionContext exeCtxt) {

        String varName;
        try {
            //JWTClaimsSet claims = new JWTClaimsSet();
            JwtClaims claims = new JwtClaims();
            String ISSUER = getIssuer(msgCtxt);
            claims.setIssuer(ISSUER);
            Float expirationInMinutes = Float.valueOf(getExpirationInMinutes(msgCtxt));
            claims.setExpirationTimeMinutesInTheFuture(expirationInMinutes);
            String uniqueID = UUID.randomUUID().toString();
            claims.setJwtId(uniqueID);

            /***************************SENDER'S END ***********************************/
            claims.setSubject("users");
            claims.setClaim("email", "users@test.com");
            claims.setClaim("Country", "USA");
            claims.setClaim("active", "true");
            claims.setClaim("dealerId", "1234");
            claims.setClaim("url", "www.mycompany.com");

            RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(msgCtxt);
            KeyGenerator keyGen = KeyGenerator.getInstance("AES");
            keyGen.init(256);
            SecretKey contentEncryptKey = keyGen.generateKey();

            JsonWebEncryption jwe = new JsonWebEncryption();
            jwe.setKey(publicKey);
            jwe.setPayload(claims.toJson());
            jwe.setAlgorithmHeaderValue(KeyManagementAlgorithmIdentifiers.RSA_OAEP_256);
            jwe.setContentEncryptionKey(contentEncryptKey.getEncoded());
            jwe.setEncryptionMethodHeaderParameter(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256);
            SecureRandom iv = SecureRandom.getInstance("SHA1PRNG");
            jwe.setIv(iv.generateSeed(16));
            String encryptedJwt = jwe.getCompactSerialization();
            System.out.println("Encrypted ::" + encryptedJwt);
            varName = getVarname("encryptedJwt");
            msgCtxt.setVariable(varName, encryptedJwt);
        }

        catch (Exception e) {
            //e.printStackTrace();
            varName = getVarname( "error");
            msgCtxt.setVariable(varName, "Exception (A): " + e.toString());
            System.out.println("exception: " + e.toString());
            varName = getVarname("stacktrace");
            msgCtxt.setVariable(varName, "Stack (A): " + ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;

    }
}

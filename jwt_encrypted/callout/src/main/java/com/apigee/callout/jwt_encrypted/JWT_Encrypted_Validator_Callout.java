package com.apigee.callout.jwt_encrypted;

import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.Charset;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;

import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;

import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.ssl.PKCS8Key;

import org.jose4j.jwt.JwtClaims;
import org.jose4j.jwt.consumer.JwtConsumer;
import org.jose4j.jwt.consumer.JwtConsumerBuilder;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import sun.misc.BASE64Encoder;

public class JWT_Encrypted_Validator_Callout implements Execution {
    private Map<String,String> properties; // read-only

    public JWT_Encrypted_Validator_Callout (Map properties) {
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


    private String getJwt(MessageContext msgCtxt) throws Exception {
        String jwt = (String) this.properties.get("jwt");
        if (jwt == null || jwt.equals("")) {
            throw new IllegalStateException("jwt is not specified or is empty.");
        }
        jwt = resolvePropertyValue(jwt, msgCtxt);
        if (jwt == null || jwt.equals("")) {
            throw new IllegalStateException("jwt is null or empty.");
        }

        // strip the Bearer prefix if necessary
        if (jwt.startsWith("Bearer ")) {
            jwt = jwt.substring(7);
        }

        return jwt.trim();
    }


    // If the value of a property value begins and ends with curlies,
    // and has no intervening spaces, eg, {apiproxy.name}, then
    // "resolve" the value by de-referencing the context variable whose
    // name appears between the curlies.
    private String resolvePropertyValue(String spec, MessageContext msgCtxt) {
        if (spec.startsWith("{") && spec.endsWith("}") && (spec.indexOf(" ") == -1)) {
            String varname = spec.substring(1,spec.length() - 1);
            String value = msgCtxt.getVariable(varname);
            return value;
        }
        return spec;
    }

    private String getVarname(String label) {
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
        InputStream in = JWT_Encrypted_Validator_Callout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
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
        //String privateKey = msgCtxt.getVariable("privateKeyFromVault");
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
            // replace pipe characters with newline
            privateKey = privateKey.replaceAll("\\|","\n");
            msgCtxt.setVariable("post-processed-privkey", privateKey);
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


    public ExecutionResult execute (MessageContext msgCtxt,
            ExecutionContext exeCtxt) {
        String varName;

        try {
            String encryptedJwt = getJwt(msgCtxt); // dot-separated JWT
            // diagnostic purposes
            varName = getVarname("jwt");
            msgCtxt.setVariable(varName, encryptedJwt);

            RSAPrivateKey privateKey = (RSAPrivateKey) getPrivateKey(msgCtxt);
            BASE64Encoder b64 = new BASE64Encoder();
            varName = getVarname("PrivateKey");
            msgCtxt.setVariable(varName, b64.encode(privateKey.getEncoded()));

            /***************************RECEIVER'S END ***********************************/

            JwtConsumer consumer = new JwtConsumerBuilder()
                //.setExpectedAudience("Admins")
                //.setExpectedIssuer("CA")
                //.setRequireSubject()
                //.setRequireExpirationTime()
                .setDecryptionKey(privateKey)
                .setDisableRequireSignature()
                .build();
            JwtClaims receivedClaims = consumer.processToClaims(encryptedJwt);
            //System.out.println("SUCESS :: JWT Validation :: " + receivedClaims);
            String receivedClaimsJSON = receivedClaims.getRawJson();

            varName = getVarname("receivedClaims");
            msgCtxt.setVariable(varName, receivedClaimsJSON);
        }
        catch (Exception e) {
            //e.printStackTrace();
            varName = getVarname("error");
            msgCtxt.setVariable(varName, "Exception (A): " + e.toString());
            varName = getVarname("stacktrace");
            msgCtxt.setVariable(varName, "Stack (A): " + ExceptionUtils.getStackTrace(e));
        }
        return ExecutionResult.SUCCESS;

    }
}

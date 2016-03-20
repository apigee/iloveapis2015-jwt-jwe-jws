package com.apigee.callout.jwtsigned;

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

import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.apache.commons.ssl.PKCS8Key;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.text.StrSubstitutor;

import java.security.PrivateKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.KeyFactory;
import java.io.InputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.interfaces.RSAPrivateKey;
import java.security.GeneralSecurityException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;

// Google's Guava collections tools
import com.google.common.collect.Collections2;
import com.google.common.collect.Maps;
import com.google.common.base.Predicate;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.CacheLoader;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;

import com.apigee.utils.TemplateString;

@IOIntensive
public class JwtCreatorCallout implements Execution {
    private static final String _varPrefix = "jwt_";
    private LoadingCache<String, JWSSigner> macKeyCache;
    private LoadingCache<PrivateKeyInfo, JWSSigner> rsaKeyCache;
    private Map<String,String> properties; // read-only

    public JwtCreatorCallout (Map properties) {
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

        macKeyCache = CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            //.weakKeys()
            .maximumSize(1048000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(new CacheLoader<String, JWSSigner>() {
                    public JWSSigner load(String key) throws UnsupportedEncodingException {
                        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
                        // NB: this will throw if the string is not at least 16 chars long
                        return new MACSigner(keyBytes);
                    }
                }
                );

        rsaKeyCache = CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(1048000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(new CacheLoader<PrivateKeyInfo, JWSSigner>() {
                    public JWSSigner load(PrivateKeyInfo info) throws InvalidKeySpecException, GeneralSecurityException {
                        RSAPrivateKey privateKey = (RSAPrivateKey) getPrivateKey(info);
                        return new RSASSASigner(privateKey);
                    }
                }
                );
    }


    private JWSSigner getMacSigner(MessageContext msgCtxt) throws Exception {
        String key = getSecretKey(msgCtxt);
        return macKeyCache.get(key);
    }

    private JWSSigner getRsaSigner(MessageContext msgCtxt)
        throws IOException, ExecutionException {
        PrivateKeyInfo info = new PrivateKeyInfo(getPrivateKeyBytes(msgCtxt), getPrivateKeyPassword(msgCtxt));
        return rsaKeyCache.get(info);
    }

    class PrivateKeyInfo {
        public PrivateKeyInfo(byte[] bytes, String p) { keyBytes = bytes; password = p;}
        public byte[] keyBytes;
        public String password;
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
        InputStream in = JwtCreatorCallout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
    }

    private static final String varName(String s) { return _varPrefix + s; }

    private String getSubject(MessageContext msgCtxt) throws Exception {
        String subject = (String) this.properties.get("subject");
        if (subject == null || subject.equals("")) {
            throw new IllegalStateException("subject is not specified or is empty.");
        }
        subject = resolvePropertyValue(subject, msgCtxt);
        if (subject == null || subject.equals("")) {
            throw new IllegalStateException("subject is null or empty.");
        }
        return subject;
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

    private String getAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = ((String) this.properties.get("algorithm")).trim();
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("algorithm is not specified or is empty.");
        }
        algorithm = resolvePropertyValue(algorithm, msgCtxt);
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("issuer is not specified or is empty.");
        }
        if (!(algorithm.equals("HS256") || algorithm.equals("RS256"))) {
            throw new IllegalStateException("unsupported algorithm: '" + algorithm+"'");
        }
        return algorithm;
    }

    private String[] getAudience(MessageContext msgCtxt) throws Exception {
        String audience = (String) this.properties.get("audience");
        if (audience == null || audience.equals("")) {
            // don't care. Audience is optional, per JWT Spec sec 4.1.3
            return null;
        }

        String[] audiences = StringUtils.split(audience,",");
        for(int i=0; i<audiences.length; i++) {
            audiences[i] = resolvePropertyValue(audiences[i], msgCtxt);
        }

        return audiences;
    }

    private String getJwtId(MessageContext msgCtxt) throws Exception {
        String jti = (String) this.properties.get("id");
        if (jti == null || jti.equals("")) {
            // don't care. ID is optional, per JWT Spec sec 4.1.7
            return null;
        }
        jti = resolvePropertyValue(jti, msgCtxt);
        if (jti == null || jti.equals("")) {
            // The variable resolves to nothing. still don't care.
            return null;
        }
        return jti;
    }

    // private String getPemfile(MessageContext msgCtxt) throws Exception {
    //     String pemfile = (String) this.properties.get("pemfile");
    //     if (pemfile == null || pemfile.equals("")) {
    //         throw new IllegalStateException("must specify pemfile when algorithm is RS*");
    //     }
    //     pemfile = resolvePropertyValue(pemfile, msgCtxt);
    //     if (pemfile == null || pemfile.equals("")) {
    //         throw new IllegalStateException("must specify pemfile when algorithm is RS*");
    //     }
    //     return pemfile;
    // }

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


    private int getExpiresIn(MessageContext msgCtxt) throws IllegalStateException {
        String expiry = (String) this.properties.get("expiresIn");
        if (expiry == null || expiry.equals("")) {
            return 60*60; // one hour
        }
        expiry = resolvePropertyValue(expiry, msgCtxt);
        if (expiry == null || expiry.equals("")) {
            throw new IllegalStateException("variable " + expiry + " resolves to nothing.");
        }
        int expiresIn = Integer.parseInt(expiry);
        return expiresIn;
    }

    private Date getExpiryDate(Date current,MessageContext msgCtxt) throws Exception {
        Calendar cal = Calendar.getInstance();
        cal.setTime(current);
        int secondsToAdd = getExpiresIn(msgCtxt);
        if (secondsToAdd == 0) { return null; /* no expiry */ }
        cal.add(Calendar.SECOND, secondsToAdd);
        Date then = cal.getTime();
        return then;
    }

    // Return all properties that begin with claim_
    // This allows this Create callout to embed each of these
    // claims into the JWT.
    private Map<String, String> customClaimsProperties(final MessageContext msgCtxt) {
        Predicate<Map.Entry<String, String>> p1 =
            new Predicate<Map.Entry<String, String>>() {
            @Override
            public boolean apply(Map.Entry<String, String> entry) {
                boolean result = entry.getKey().startsWith("claim_");
                // diagnostics
                msgCtxt.setVariable("jwt_property_" + entry.getKey(), entry.getValue());
                return result;
            }
        };
        Map<String, String> claimsProps = Maps.filterEntries(properties, p1);
        return claimsProps;
    }


    private byte[] getPrivateKeyBytes(MessageContext msgCtxt)
        throws IOException
               // GeneralSecurityException,
               // NoSuchAlgorithmException,
               // InvalidKeySpecException
    {
        byte[] keyBytes = null;
        String privateKey = (String) this.properties.get("private-key");
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
            keyBytes = privateKey.getBytes(StandardCharsets.UTF_8);
        }
        return keyBytes;
    }

    private PrivateKey getPrivateKey(PrivateKeyInfo info)
        throws InvalidKeySpecException, GeneralSecurityException,NoSuchAlgorithmException
    {
        // If the provided data is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        PKCS8Key pkcs8 = new PKCS8Key( info.keyBytes, info.password.toCharArray() );

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
        return pk;
    }

    // If the value of a property value begins and ends with curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variable whose name appears between the curlies.
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


    public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt)
    {
        String wantDebug = this.properties.get("debug");
        boolean debug = (wantDebug != null) && Boolean.parseBoolean(wantDebug);
        try {
            JWSAlgorithm jwsAlg;
            String ISSUER = getIssuer(msgCtxt);
            String ALG = getAlgorithm(msgCtxt);
            String[] AUDIENCE = getAudience(msgCtxt);
            String SUBJECT = getSubject(msgCtxt);
            String JTI = getJwtId(msgCtxt);
            JWSSigner signer;
            String[] audiences = null;
            Date now = new Date();

            // 1. Prepare JWT with the set of standard claims
            JWTClaimsSet claims = new JWTClaimsSet();
            claims.setIssuer(ISSUER);
            claims.setSubject(SUBJECT);
            if (AUDIENCE != null) {
                claims.setAudience(java.util.Arrays.asList(AUDIENCE));
            }
            if (JTI != null) { claims.setJWTID(JTI); }
            claims.setIssueTime(now);
            Date expiry = getExpiryDate(now,msgCtxt);
            if (expiry != null) { claims.setExpirationTime(expiry); }

            // 2. add all the provided custom claims to the set
            Map<String,String> customClaims = customClaimsProperties(msgCtxt);
            if (customClaims.size() > 0) {
                // iterate the map
                for (Map.Entry<String, String> entry : customClaims.entrySet()) {
                    String key = entry.getKey();
                    String providedValue = entry.getValue();
                    String[] parts = StringUtils.split(key,"_");
                    // sanity check - is this a valid claim?
                    if (parts.length == 2 && parts[0].equals("claim") &&
                        providedValue != null) {
                        String claimName =  parts[1];
                        // special case aud, which can be an array
                        if (claimName.equals("aud") && providedValue.indexOf(",")!=-1) {
                            audiences = StringUtils.split(providedValue,",");
                            for(int i=0; i<audiences.length; i++) {
                                audiences[i] = resolvePropertyValue(audiences[i], msgCtxt);
                            }
                            claims.setAudience(java.util.Arrays.asList(audiences));
                        }
                        else {
                            providedValue = resolvePropertyValue(providedValue, msgCtxt);
                            claims.setCustomClaim(claimName, providedValue);
                        }
                        msgCtxt.setVariable(varName("provided_")+claimName, providedValue);
                    }
                }
            }

            // 3. serialize to a string, for diagnostics purposes
            net.minidev.json.JSONObject json = claims.toJSONObject();
            msgCtxt.setVariable(varName("claims"), json.toString());

            // 3. vet the algorithm, and set up the signer
            if (ALG.equals("HS256")) {
                signer = getMacSigner(msgCtxt);
                jwsAlg = JWSAlgorithm.HS256;
            }
            else if (ALG.equals("RS256")) {
                // Create RSA-signer with the private key
                signer = getRsaSigner(msgCtxt);
                jwsAlg = JWSAlgorithm.RS256;
            }
            else {
                throw new IllegalStateException("unsupported algorithm: " + ALG);
            }

            // 4. Apply the signature
            JWSHeader h = new JWSHeader(jwsAlg);
            //h.setType("JWT"); // why not?
            SignedJWT signedJWT = new SignedJWT(h, claims);
            signedJWT.sign(signer);

            // 5. serialize to compact form, produces something like
            // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onOUhyuz0Y18UASXlSc1eS0NkWyA
            String jwt = signedJWT.serialize();
            msgCtxt.setVariable(varName("jwt"), jwt);
        }
        catch (Exception e) {
            // unhandled exceptions
            if (debug) { e.printStackTrace(); }
            String error = e.toString();
            msgCtxt.setVariable(varName("error"), error);
            int ch = error.indexOf(':');
            if (ch >= 0) {
                msgCtxt.setVariable(varName("reason"), error.substring(ch+2));
            }
            else {
                msgCtxt.setVariable(varName("reason"), error);
            }
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}

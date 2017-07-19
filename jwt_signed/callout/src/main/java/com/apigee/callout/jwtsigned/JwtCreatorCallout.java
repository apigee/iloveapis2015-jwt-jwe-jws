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
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;

import org.apache.commons.codec.binary.Base64;
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
    private final static JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");

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
                        RSAPrivateKey privateKey = (RSAPrivateKey) generatePrivateKey(info);
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

    private static InputStream getResourceAsStream(String resourceName) throws IOException {
        // forcibly prepend a slash
        if (!resourceName.startsWith("/")) {
            resourceName = "/" + resourceName;
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
            // throw new IllegalStateException("subject is not specified or is empty.");
            return null; // subject is OPTIONAL
        }
        subject = (String) resolvePropertyValue(subject, msgCtxt);
        if (subject == null || subject.equals("")) {
            //throw new IllegalStateException("subject is null or empty.");
            return null; // subject is OPTIONAL
        }
        return subject;
    }

    private String getSecretKey(MessageContext msgCtxt) throws Exception {
        String key = (String) this.properties.get("secret-key");
        if (key == null || key.equals("")) {
            throw new IllegalStateException("secret-key is not specified or is empty.");
        }
        key = (String) resolvePropertyValue(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException("secret-key is null or empty.");
        }
        return key;
    }

    private String getIssuer(MessageContext msgCtxt) throws Exception {
        String issuer = (String) this.properties.get("issuer");
        if (issuer == null || issuer.equals("")) {
            //throw new IllegalStateException("issuer is not specified or is empty.");
            return null; // "iss" is OPTIONAL per RFC-7519
        }
        issuer = (String) resolvePropertyValue(issuer, msgCtxt);
        if (issuer == null || issuer.equals("")) {
            // throw new IllegalStateException("issuer is not specified or is empty.");
            return null; // "iss" is OPTIONAL per RFC-7519
        }
        return issuer;
    }

    private String getAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = ((String) this.properties.get("algorithm")).trim();
        if (algorithm == null || algorithm.equals("")) {
            throw new IllegalStateException("algorithm is not specified or is empty.");
        }
        algorithm = (String) resolvePropertyValue(algorithm, msgCtxt);
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
            // Audience is optional, per JWT Spec sec 4.1.3
            return null;
        }

        Object resolvedValue = resolvePropertyValue(audience, msgCtxt);
        if (resolvedValue instanceof String[]) {
            // we might already have an array from a property
            return (String[])resolvedValue;
        } else if (resolvedValue instanceof org.mozilla.javascript.NativeArray) {
            return nativeToJavaArray((org.mozilla.javascript.NativeArray)resolvedValue);
        } else {
            // Audience is an array, or a simple string. We always return array
            String[] audiences = StringUtils.split(resolvedValue.toString(), ",");
            for (int i = 0; i < audiences.length; i++) {
                audiences[i] = (String) resolvePropertyValue(audiences[i], msgCtxt);
            }
            return audiences;
        }
    }

    private String getJwtId(MessageContext msgCtxt) throws Exception {
        if (!this.properties.containsKey("id")) {
            // ID is optional, per JWT Spec sec 4.1.7
            return null;
        }
        String jti = (String) this.properties.get("id");
        if (jti == null || jti.equals("")) {
            // The value is not specified. Generate a UUID.
            return java.util.UUID.randomUUID().toString();
        }
        jti = (String) resolvePropertyValue(jti, msgCtxt);
        if (jti == null || jti.equals("")) {
            // The variable resolves to nothing. Generate one.
            return java.util.UUID.randomUUID().toString();
        }
        return jti;
    }

    private String getKeyId(MessageContext msgCtxt) throws Exception {
        if (!this.properties.containsKey("kid")) return null;
        String keyid = (String) this.properties.get("kid");
        if (keyid == null || keyid.equals("")) return null;
        keyid = (String) resolvePropertyValue(keyid, msgCtxt);
        if (keyid == null || keyid.equals("")) return null;
        return keyid;
    }

    private String getPrivateKeyPassword(MessageContext msgCtxt) {
        String password = (String) this.properties.get("private-key-password");
        if (password == null || password.equals("")) {
            // don't care. Use of a password on the private key is optional.
            return null;
        }
        password = (String) resolvePropertyValue(password, msgCtxt);
        if (password == null || password.equals("")) { return null; }
        return password;
    }


    private int getExpiresIn(MessageContext msgCtxt) throws IllegalStateException {
        String expiry = (String) this.properties.get("expiresIn");
        if (expiry == null || expiry.equals("")) {
            return 60*60; // one hour
        }
        expiry = (String) resolvePropertyValue(expiry, msgCtxt);
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


    private byte[] getPrivateKeyBytes(MessageContext msgCtxt) throws IOException {
        byte[] keyBytes = null;
        String privateKey = (String) this.properties.get("private-key");
        if (privateKey==null) {
            String pemfile = (String) this.properties.get("pemfile");
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("must specify pemfile or private-key when algorithm is RS*");
            }
            pemfile = (String) resolvePropertyValue(pemfile, msgCtxt);
            if (pemfile == null || pemfile.equals("")) {
                throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
            }

            InputStream in = getResourceAsStream(pemfile);

            keyBytes = new byte[in.available()];
            in.read(keyBytes);
            in.close();
        }
        else {
            // it's a string...
            if (privateKey.equals("")) {
                throw new IllegalStateException("private-key must be non-empty");
            }
            privateKey = (String) resolvePropertyValue(privateKey, msgCtxt);
            if (privateKey==null || privateKey.equals("")) {
                throw new IllegalStateException("private-key variable resolves to empty; invalid when algorithm is RS*");
            }
            privateKey = privateKey.trim();

            if (privateKey.startsWith("-----BEGIN PRIVATE KEY-----") &&
                privateKey.endsWith("-----END PRIVATE KEY-----")) {
                privateKey = privateKey.substring(27, privateKey.length() - 25);
            }
            else if (privateKey.startsWith("-----BEGIN RSA PRIVATE KEY-----") &&
                privateKey.endsWith("-----END RSA PRIVATE KEY-----")) {
                privateKey = privateKey.substring(31, privateKey.length() - 29);
            }

            // clear any leading whitespace on each line
            privateKey = privateKey.replaceAll("([\\r|\\n] +)","\n");
            keyBytes = Base64.decodeBase64(privateKey);
            //keyBytes = privateKey.getBytes(StandardCharsets.UTF_8);
        }
        return keyBytes;
    }


    private static PrivateKey generatePrivateKey(PrivateKeyInfo info)
        throws InvalidKeySpecException, GeneralSecurityException,NoSuchAlgorithmException
    {
        // If the provided data is encrypted, we need a password to decrypt
        // it. If the InputStream is not encrypted, then the password is ignored
        // (can be null).  The InputStream can be DER (raw ASN.1) or PEM (base64).
        char[] password = (info.password != null && !info.password.isEmpty()) ?
            info.password.toCharArray() : null;

        PKCS8Key pkcs8 = new PKCS8Key( info.keyBytes, password );

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

    // If the value of a property value contains open and close curlies, eg,
    // {apiproxy.name} or ABC-{apikey}, then "resolve" the value by de-referencing
    // the context variables whose names appear between curlies.
    //
    // This can return a String or an String[].
    //
    private Object resolvePropertyValue(String spec, MessageContext msgCtxt) {
        int open = spec.indexOf('{'), close = spec.indexOf('}'), L = spec.length();
        if (open == 0 && close == L-1) {
            // if there is a single set of braces around the entire property,
            // the value may resolve to a non-string, for example an array of strings.
            if (spec.indexOf('{', 1) == -1) {
                String v = spec.substring(1,L-1);
                return msgCtxt.getVariable(v);
            }
        }

        if (open > -1 && close >-1) {
            // Replace ALL curly-braced items in the spec string with
            // the value of the corresponding context variable.
            TemplateString ts = new TemplateString(spec);
            Map<String,String> valuesMap = new HashMap<String,String>();
            for (String s : ts.variableNames) {
                valuesMap.put(s, msgCtxt.getVariable(s).toString());
            }
            StrSubstitutor sub = new StrSubstitutor(valuesMap);
            String resolvedString = sub.replace(ts.template);
            return resolvedString;
        }
        return spec;
    }

    private String[] nativeToJavaArray(org.mozilla.javascript.NativeArray a) {
        String [] result = new String[(int) a.getLength()];
        for (Object o : a.getIds()) {
            int index = (Integer) o;
            result[index] = a.get(index, null).toString();
        }
        return result;
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
            String KEYID = getKeyId(msgCtxt);
            JWSSigner signer;
            String[] audiences = null;
            Date now = new Date();

            // 1. Prepare JWT with the set of standard claims
            JWTClaimsSet claims = new JWTClaimsSet();
            if (ISSUER != null) claims.setIssuer(ISSUER);
            if (SUBJECT != null) claims.setSubject(SUBJECT);
            if (AUDIENCE != null) claims.setAudience(java.util.Arrays.asList(AUDIENCE));
            if (JTI != null) claims.setJWTID(JTI);
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
                    String[] parts = StringUtils.split(key,"_",2);
                    // sanity check - is this a valid claim?
                    if (parts.length == 2 && parts[0].equals("claim") &&
                        providedValue != null) {
                        String claimName =  parts[1];
                        Object resolvedValue = resolvePropertyValue(providedValue, msgCtxt);
                        // special case aud, which can be an array
                        if (claimName.equals("aud") && resolvedValue instanceof String) {
                            audiences = StringUtils.split(providedValue,",");
                            claims.setAudience(java.util.Arrays.asList(audiences));
                        }
                        else {
                            if (resolvedValue instanceof String[]) {
                                claims.setClaim(claimName, java.util.Arrays.asList((String[])resolvedValue));
                            }
                            else if (resolvedValue instanceof org.mozilla.javascript.NativeArray) {
                                // an array set in a JavaScript callout
                                claims.setClaim(claimName, java.util.Arrays.asList(nativeToJavaArray((org.mozilla.javascript.NativeArray)resolvedValue)));
                            }
                            else if (resolvedValue != null){
                                //claims.setCustomClaim(claimName, providedValue);
                                claims.setClaim(claimName, resolvedValue.toString());
                            }
                            else {
                                claims.setClaim(claimName, null);
                            }
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
                msgCtxt.setVariable(varName("alg-missing"), ALG);
                throw new IllegalStateException("unsupported algorithm: " + ALG);
            }
            msgCtxt.setVariable(varName("alg"), ALG);

            // 4. Apply the signature
            JWSHeader.Builder builder = new JWSHeader.Builder(jwsAlg).type(TYP_JWT);
            if (KEYID != null) builder.keyID(KEYID);
            JWSHeader h = builder.build();
            SignedJWT signedJWT = new SignedJWT(h, claims);
            signedJWT.sign(signer);

            // 5. serialize to compact form, produces something like
            // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onOUhyuz0Y18UASXlSc1eS0NkWyA
            String jwt = signedJWT.serialize();
            msgCtxt.setVariable(varName("jwt"), jwt);
        }
        catch (Exception e) {
            // unhandled exceptions
            //if (debug) { e.printStackTrace(); /* to MP system.log */ }
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

package com.apigee.callout.jwtsigned;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.common.base.Predicate;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Collections2;
import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.text.ParseException;
import java.util.Arrays;
import java.util.Calendar;
import java.util.Date;
import java.util.HashMap;
import java.util.Iterator;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.codec.binary.Base64;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.exception.ExceptionUtils;
import org.apache.commons.lang3.time.DateParser;
import org.apache.commons.lang3.time.FastDateFormat;
import org.apache.commons.ssl.PKCS8Key;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

@IOIntensive
public class JwtCreatorCallout implements Execution {
    private static final String _varPrefix = "jwt_";
    private LoadingCache<String, JWSSigner> macKeyCache;
    private LoadingCache<PrivateKeyInfo, JWSSigner> rsaKeyCache;
    private Map<String,String> properties; // read-only
    private final static JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");
    private final static int DEFAULT_EXPIRY_IN_SECONDS = 60*60; // one hour
    private static final String dateStringPatternString = "[1-2][0-9]{9}";
    private final static Pattern secondsSinceEpochPattern = Pattern.compile(dateStringPatternString);
    private static final String variableReferencePatternString = "(.*?)\\{([^\\{\\} ]+?)\\}(.*?)";
    private static final Pattern variableReferencePattern = Pattern.compile(variableReferencePatternString);

    private static final FastDateFormat fdf = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss.SSSZ", TimeZone.getTimeZone("UTC")); // 2017-08-14T11:00:21.269-0700
    private static final DateParser DATE_FORMAT_RFC_3339 = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ssXXX"); // 2017-08-14T11:00:21-07:00
    private static final DateParser DATE_FORMAT_RFC_1123 = FastDateFormat.getInstance("EEE, dd MMM yyyy HH:mm:ss zzz"); // Mon, 14 Aug 2017 11:00:21 PDT
    private static final DateParser DATE_FORMAT_RFC_850 = FastDateFormat.getInstance("EEEE, dd-MMM-yy HH:mm:ss zzz"); // Monday, 14-Aug-17 11:00:21 PDT
    private static final DateParser DATE_FORMAT_ANSI_C = FastDateFormat.getInstance("EEE MMM d HH:mm:ss yyyy"); // Mon Aug 14 11:00:21 2017
    private static final DateParser allowableInputFormats[] = {
        DATE_FORMAT_RFC_3339,
        DATE_FORMAT_RFC_1123,
        DATE_FORMAT_RFC_850,
        DATE_FORMAT_ANSI_C,
        (DateParser)fdf
    };

    static {
        java.security.Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

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
                    public JWSSigner load(PrivateKeyInfo info) throws InvalidKeySpecException, GeneralSecurityException, IOException {
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
        if (StringUtils.isBlank(subject)) {
            // throw new IllegalStateException("subject is not specified or is empty.");
            return null; // subject is OPTIONAL
        }
        subject = (String) resolvePropertyValue(subject, msgCtxt);
        if (StringUtils.isBlank(subject)) {
            //throw new IllegalStateException("subject is null or empty.");
            return null; // subject is OPTIONAL
        }
        return subject;
    }

    private String getSecretKey(MessageContext msgCtxt) throws Exception {
        String key = (String) this.properties.get("secret-key");
        if (StringUtils.isBlank(key)) {
            throw new IllegalStateException("secret-key is not specified or is empty.");
        }
        key = (String) resolvePropertyValue(key, msgCtxt);
        if (StringUtils.isBlank(key)) {
            throw new IllegalStateException("secret-key is null or empty.");
        }
        return key;
    }

    private String getIssuer(MessageContext msgCtxt) throws Exception {
        String issuer = (String) this.properties.get("issuer");
        if (StringUtils.isBlank(issuer)) {
            //throw new IllegalStateException("issuer is not specified or is empty.");
            return null; // "iss" is OPTIONAL per RFC-7519
        }
        issuer = (String) resolvePropertyValue(issuer, msgCtxt);
        if (StringUtils.isBlank(issuer)) {
            // throw new IllegalStateException("issuer is not specified or is empty.");
            return null; // "iss" is OPTIONAL per RFC-7519
        }
        return issuer;
    }

    private String getAlgorithm(MessageContext msgCtxt) throws Exception {
        String algorithm = ((String) this.properties.get("algorithm")).trim();
        if (StringUtils.isBlank(algorithm)) {
            throw new IllegalStateException("algorithm is not specified or is empty.");
        }
        algorithm = (String) resolvePropertyValue(algorithm, msgCtxt);
        if (StringUtils.isBlank(algorithm)) {
            throw new IllegalStateException("algorithm is not specified or is empty.");
        }
        if (!(algorithm.equals("HS256") || algorithm.equals("RS256"))) {
            throw new IllegalStateException("unsupported algorithm: '" + algorithm+"'");
        }
        return algorithm;
    }

    private String[] getAudience(MessageContext msgCtxt) throws Exception {
        String audience = (String) this.properties.get("audience");
        if (StringUtils.isBlank(audience)) {
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
        if (StringUtils.isBlank(jti)) {
            // The value is not specified. Generate a UUID.
            return java.util.UUID.randomUUID().toString();
        }
        jti = (String) resolvePropertyValue(jti, msgCtxt);
        if (StringUtils.isBlank(jti)) {
            // The variable resolves to nothing. Generate one.
            return java.util.UUID.randomUUID().toString();
        }
        return jti;
    }

    private String getKeyId(MessageContext msgCtxt) throws Exception {
        if (!this.properties.containsKey("kid")) return null;
        String keyid = (String) this.properties.get("kid");
        if (StringUtils.isBlank(keyid)) return null;
        keyid = (String) resolvePropertyValue(keyid, msgCtxt);
        if (StringUtils.isBlank(keyid)) return null;
        return keyid;
    }

    private String getPrivateKeyPassword(MessageContext msgCtxt) {
        String password = (String) this.properties.get("private-key-password");
        if (StringUtils.isBlank(password)) {
            // don't care. Use of a password on the private key is optional.
            return null;
        }
        password = (String) resolvePropertyValue(password, msgCtxt);
        if (StringUtils.isBlank(password)) { return null; }
        return password;
    }

    private int getExpiresIn(MessageContext msgCtxt) throws IllegalStateException {
        String expiry = (String) this.properties.get("expiresIn");
        if (StringUtils.isBlank(expiry)) {
            return DEFAULT_EXPIRY_IN_SECONDS;
        }
        expiry = (String) resolvePropertyValue(expiry, msgCtxt);
        if (StringUtils.isBlank(expiry)) {
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

    private Date getNotBefore(MessageContext msgCtxt, Date now) throws Exception {
        String key = "not-before";
        if (!this.properties.containsKey(key)) return null;
        String value = (String) this.properties.get(key);
        if (StringUtils.isBlank(value)) return now;
        value = (String) resolvePropertyValue(value, msgCtxt);
        if (StringUtils.isBlank(value)) return now;
        return parseDate(value.trim()); // unparsed date string
    }

    private static Date parseDate(String dateString) {
        if (dateString == null) return null;
        Matcher m = secondsSinceEpochPattern.matcher(dateString);
        if (m.matches()) {
            return new Date(Long.parseLong(dateString) * 1000);
        }
        for (DateParser format : allowableInputFormats){
            try {
                return format.parse(dateString);
            }
            catch (ParseException ex) {
            }
        }
        return null;
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
            if (StringUtils.isBlank(pemfile)) {
                throw new IllegalStateException("must specify pemfile or private-key when algorithm is RS*");
            }
            pemfile = (String) resolvePropertyValue(pemfile, msgCtxt);
            if (StringUtils.isBlank(pemfile)) {
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
            if (StringUtils.isBlank(privateKey)) {
                throw new IllegalStateException("private-key variable resolves to empty; invalid when algorithm is RS*");
            }
            privateKey = privateKey.trim();

            // clear any leading whitespace on each line
            privateKey = privateKey.replaceAll("([\\r|\\n] +)","\n");

            //keyBytes = Base64.decodeBase64(privateKey);
            keyBytes = privateKey.getBytes(StandardCharsets.UTF_8);
        }
        return keyBytes;
    }

    private static PrivateKey generatePrivateKey(PrivateKeyInfo info)
        throws InvalidKeySpecException, GeneralSecurityException, NoSuchAlgorithmException, IOException, PEMException
    {
        JcaPEMKeyConverter   converter = new JcaPEMKeyConverter().setProvider("BC");
        PEMParser pr = new PEMParser(new StringReader(new String(info.keyBytes, StandardCharsets.UTF_8)));
        Object o = pr.readObject();

        if (o == null || !((o instanceof PEMKeyPair) || (o instanceof PEMEncryptedKeyPair))) {
            throw new IllegalStateException("Didn't find OpenSSL key");
        }
        KeyPair kp;
        if (o instanceof PEMEncryptedKeyPair) {
            PEMDecryptorProvider decProv = new JcePEMDecryptorProviderBuilder().setProvider("BC")
                .build(info.password.toCharArray());
            kp = converter.getKeyPair(((PEMEncryptedKeyPair)o).decryptKeyPair(decProv));
        }
        else {
            kp = converter.getKeyPair((PEMKeyPair)o);
        }

        PrivateKey privKey = kp.getPrivate();
        return privKey;
    }


    private static PrivateKey old_generatePrivateKey(PrivateKeyInfo info)
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

    // If the value of a property contains any pairs of curlies,
    // eg, {apiproxy.name}, then "resolve" the value by de-referencing
    // the context variables whose names appear between curlies.
    private Object resolvePropertyValue(String spec, MessageContext msgCtxt) {
        int open = spec.indexOf('{'), close = spec.indexOf('}'), L = spec.length();
        if (open == 0 && close == L-1) {
            // if there is a single set of braces around the entire property,
            // the value may resolve to a non-string, for example an array of strings.
            if ((spec.indexOf('{', 1) == -1) && spec.charAt(1)!=' ' && spec.charAt(1)!='"') {
                String v = spec.substring(1,L-1);
                return msgCtxt.getVariable(v);
            }
        }

        Matcher matcher = variableReferencePattern.matcher(spec);
        StringBuffer sb = new StringBuffer();
        while (matcher.find()) {
            matcher.appendReplacement(sb, "");
            sb.append(matcher.group(1));
            Object v = msgCtxt.getVariable(matcher.group(2));
            if (v != null){
                Class clz = v.getClass();
                if (clz.isArray()) {
                    sb.append ( Arrays.stream((Object[])v).map(Object::toString).toArray(String[]::new) );
                }
                else {
                    sb.append( v.toString() );
                }
            }
            sb.append(matcher.group(3));
        }
        matcher.appendTail(sb);
        return sb.toString();
    }

    // private Object resolvePropertyValue(String spec, MessageContext msgCtxt) {
    //     int open = spec.indexOf('{'), close = spec.indexOf('}'), L = spec.length();
    //     if (open == 0 && close == L-1) {
    //         // if there is a single set of braces around the entire property,
    //         // the value may resolve to a non-string, for example an array of strings.
    //         if (spec.indexOf('{', 1) == -1) {
    //             String v = spec.substring(1,L-1);
    //             return msgCtxt.getVariable(v);
    //         }
    //     }
    //
    //     if (open > -1 && close >-1) {
    //         // Replace ALL curly-braced items in the spec string with
    //         // the value of the corresponding context variable.
    //         TemplateString ts = new TemplateString(spec);
    //         Map<String,String> valuesMap = new HashMap<String,String>();
    //         for (String s : ts.variableNames) {
    //             valuesMap.put(s, msgCtxt.getVariable(s).toString());
    //         }
    //         StrSubstitutor sub = new StrSubstitutor(valuesMap);
    //         String resolvedString = sub.replace(ts.template);
    //         return resolvedString;
    //     }
    //     return spec;
    // }

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
            Date now = new Date();
            JWSAlgorithm jwsAlg;
            String ISSUER = getIssuer(msgCtxt);
            String ALG = getAlgorithm(msgCtxt);
            String[] AUDIENCE = getAudience(msgCtxt);
            String SUBJECT = getSubject(msgCtxt);
            String JTI = getJwtId(msgCtxt);
            String KEYID = getKeyId(msgCtxt);
            Date NOTBEFORE = getNotBefore(msgCtxt, now);
            JWSSigner signer;
            String[] audiences = null;

            // 1. Prepare JWT with the set of standard claims
            JWTClaimsSet claims = new JWTClaimsSet();
            if (ISSUER != null) claims.setIssuer(ISSUER);
            if (SUBJECT != null) claims.setSubject(SUBJECT);
            if (AUDIENCE != null) claims.setAudience(java.util.Arrays.asList(AUDIENCE));
            if (JTI != null) claims.setJWTID(JTI);
            claims.setIssueTime(now);

            if (NOTBEFORE != null) {
                claims.setNotBeforeTime(NOTBEFORE);
            }

            Date expiry = getExpiryDate(now,msgCtxt);
            if (expiry != null) claims.setExpirationTime(expiry);

            // 2. add all the provided custom claims to the set
            Map<String,String> customClaims = customClaimsProperties(msgCtxt);
            if (customClaims.size() > 0) {
                // iterate the map
                for (Map.Entry<String, String> entry : customClaims.entrySet()) {
                    String key = entry.getKey();
                    String providedValue = entry.getValue();
                    String[] parts = StringUtils.split(key,"_",2);
                    // sanity check - is this a valid claim?
                    if (parts.length == 2 && parts[0].equals("claim") && providedValue != null) {
                        String claimName =  parts[1];
                        Object resolvedValue = resolvePropertyValue(providedValue, msgCtxt);
                        if (claimName.startsWith("json")) {
                            String[] nameParts = StringUtils.split(claimName,"_",2);
                            if (nameParts.length != 2 || StringUtils.isBlank(parts[1])) {
                                throw new IllegalStateException("invalid json claim configuration: " + claimName);
                            }
                            net.minidev.json.parser.JSONParser parser = new net.minidev.json.parser.JSONParser();
                            net.minidev.json.JSONObject thisClaim = (net.minidev.json.JSONObject) parser.parse(resolvedValue.toString());
                            claims.setClaim(nameParts[1], thisClaim);
                        }
                        else if (claimName.equals("aud") && resolvedValue instanceof String) {
                            // special case aud, which can be an array
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

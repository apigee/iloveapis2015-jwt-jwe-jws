package com.apigee.callout.jwtsigned;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.apache.commons.lang.time.DurationFormatUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.StringUtils;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import org.apache.commons.lang3.time.FastDateFormat;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import java.io.InputStream;
import java.io.IOException;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateException;

// for collections and Guava Cache magic
import com.google.common.collect.Maps;
import com.google.common.base.Predicate;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.LoadingCache;
import com.google.common.cache.CacheLoader;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.ExecutionException;

@IOIntensive
public class JwtParserCallout implements Execution {
    private final static String _varPrefix = "jwt_";
    private static LoadingCache<String, JWSVerifier> macVerifierCache;
    private static LoadingCache<PublicKeySource, JWSVerifier> rsaVerifierCache;
    // We may wish to allow a grace period on the expiry or a not-before-time
    // of a JWT.  In particular, for the nbf, if the token is acquired from a
    // remote system and then immediately presented here, the nbf may yet be
    // in the future. This number quantifies the allowance for time skew
    // between issuer and verifier (=this code).
    private final static long defaultTimeAllowanceMilliseconds = 1000L;
    private final static int MAX_CACHE_ENTRIES = 10240;

    // NB: SimpleDateFormat is not thread-safe
    private static final FastDateFormat fdf = FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

    private Map<String,String> properties; // read-only

    public JwtParserCallout (Map properties) {
        // convert the untyped Map to a generic map
        Map<String,String> m = new HashMap<String,String>();
        Iterator iterator = properties.keySet().iterator();
        while(iterator.hasNext()){
            Object key = iterator.next();
            Object value = properties.get(key);
            if ((key instanceof String) && (value instanceof String)) {
                m.put((String) key, (String) value);
            }
        }
        this.properties = m;

        macVerifierCache = CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(new CacheLoader<String, JWSVerifier>() {
                    public JWSVerifier load(String key)
                        throws UnsupportedEncodingException, IllegalArgumentException {
                        if (key == null) {
                            throw new IllegalArgumentException("the key is null");
                        }
                        byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
                        // NB: this will throw if the string is not at least 16 chars long
                        return new MACVerifier(keyBytes);
                    }
                }
                );

        rsaVerifierCache = CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(new CacheLoader<PublicKeySource, JWSVerifier>() {
                    public JWSVerifier load(PublicKeySource source)
                        throws NoSuchAlgorithmException, InvalidKeySpecException,
                               IllegalArgumentException, CertificateException, UnsupportedEncodingException {
                        RSAPublicKey publicKey = (RSAPublicKey) source.getPublicKey();
                        if (publicKey == null) {
                            throw new IllegalArgumentException("there was no public key specified.");
                        }
                        return new RSASSAVerifier(publicKey);
                    }
                }
                );
    }

    private static InputStream getResourceAsStream(String resourceName) throws IOException {
        // forcibly prepend a slash
        if (!resourceName.startsWith("/")) {
            resourceName = "/" + resourceName;
        }
        InputStream in = JwtParserCallout.class.getResourceAsStream(resourceName);
        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }
        return in;
    }

    private static final String varName(String s) {
        return _varPrefix + s;
    }

    private boolean getContinueOnError(MessageContext msgCtxt) {
        String continueOnError = properties.get("continueOnError");
        if (StringUtils.isBlank(continueOnError)) {
            return false;
        }
        continueOnError = resolvePropertyValue(continueOnError, msgCtxt);
        return Boolean.parseBoolean(continueOnError);
    }

    private boolean getWantVerify(MessageContext msgCtxt) {
        String wantVerify = properties.get("wantVerify");
        if (StringUtils.isBlank(wantVerify)) {
            return true;
        }
        wantVerify = resolvePropertyValue(wantVerify, msgCtxt);
        return Boolean.parseBoolean(wantVerify);
    }

    private String getJwt(MessageContext msgCtxt) throws Exception {
        String jwt = (String) this.properties.get("jwt");
        if (jwt == null || jwt.equals("")) {
            throw new IllegalArgumentException("jwt is not specified or is empty.");
        }
        jwt = resolvePropertyValue(jwt, msgCtxt);
        if (jwt == null || jwt.equals("")) {
            throw new IllegalArgumentException("jwt is null or empty.");
        }

        // strip the Bearer prefix if necessary.
        // RFC 6750 "The OAuth 2.0 Authorization Framework: Bearer Token Usage", section 2.1
        // states that the prefix is "Bearer ", case-sensitive.
        if (jwt.startsWith("Bearer ")) {
            jwt = jwt.substring(7);
        }

        return jwt.trim();
    }

    private long getTimeAllowance(MessageContext msgCtxt) {
        String timeAllowance = (String) this.properties.get("timeAllowance");
        if (StringUtils.isBlank(timeAllowance)) {
            return defaultTimeAllowanceMilliseconds;
        }
        timeAllowance = resolvePropertyValue(timeAllowance, msgCtxt);
        if (StringUtils.isBlank(timeAllowance)) {
            return defaultTimeAllowanceMilliseconds;
        }
        long longValue = StringUtils.isBlank(timeAllowance) ?
            defaultTimeAllowanceMilliseconds :
            Long.parseLong(timeAllowance, 10);
        return longValue;
    }

    private String getAlgorithm(MessageContext msgCtxt) throws IllegalStateException {
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

    private String getSecretKey(MessageContext msgCtxt) throws IllegalStateException {
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

    private void recordTimeVariable(MessageContext msgContext, Date d, String label) {
        msgContext.setVariable(varName(label), d.getTime() + "");
        msgContext.setVariable(varName(label + "Formatted"), fdf.format(d));
    }

    private PublicKeySource getPublicKeySource(MessageContext msgCtxt)
        throws IOException {
        // There are various ways to specify the public key in configuration

        // 1. Try "public-key"
        String publicKeyString = (String) this.properties.get("public-key");
        if (publicKeyString !=null) {
            if (publicKeyString.equals("")) {
                throw new IllegalStateException("public-key must be non-empty");
            }
            publicKeyString = resolvePropertyValue(publicKeyString, msgCtxt);

            if (publicKeyString==null || publicKeyString.equals("")) {
                throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
            }
            return PublicKeySource.fromString(publicKeyString);
        }

        // 2. Try "modulus" + "exponent"
        String modulus = (String) this.properties.get("modulus");
        String exponent = (String) this.properties.get("exponent");

        if ((modulus != null) && (exponent != null)) {
            modulus = resolvePropertyValue(modulus, msgCtxt);
            exponent = resolvePropertyValue(exponent, msgCtxt);

            if (modulus==null || modulus.equals("") ||
                exponent==null || exponent.equals("")) {
                throw new IllegalStateException("modulus or exponent resolves to empty; invalid when algorithm is RS*");
            }

            return PublicKeySource.fromModulusAndExponent(modulus, exponent);
        }

        // 3. Try certificate
        String certString = (String) this.properties.get("certificate");
        if (certString !=null) {
            if (certString.equals("")) {
                throw new IllegalStateException("certificate must be non-empty");
            }
            certString = resolvePropertyValue(certString, msgCtxt);
            //msgCtxt.setVariable("jwt_certstring", certString);
            if (certString==null || certString.equals("")) {
                throw new IllegalStateException("certificate variable resolves to empty; invalid when algorithm is RS*");
            }

            return PublicKeySource.fromCertificate(certString);
        }

        // 4. last chance, try pemfile
        String pemfile = (String) this.properties.get("pemfile");
        if (pemfile == null || pemfile.equals("")) {
            throw new IllegalStateException("must specify pemfile or public-key or certificate when algorithm is RS*");
        }
        pemfile = resolvePropertyValue(pemfile, msgCtxt);
        if (pemfile == null || pemfile.equals("")) {
            throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
        }

        InputStream in = getResourceAsStream(pemfile);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();
        publicKeyString = new String(keyBytes, "UTF-8");

        return PublicKeySource.fromPemFileString(pemfile,publicKeyString);
    }

    private JWSVerifier getMacVerifier(MessageContext msgCtxt) throws Exception {
        String key = getSecretKey(msgCtxt);
        return macVerifierCache.get(key);
    }

    private JWSVerifier getRsaVerifier(MessageContext msgCtxt) throws Exception {
        PublicKeySource source = getPublicKeySource(msgCtxt);
        return rsaVerifierCache.get(source);
    }

    private JWSVerifier getVerifier(String alg, MessageContext msgCtxt)
        throws Exception {
        if (alg.equals("HS256")) {
            return getMacVerifier(msgCtxt);
        }
        else if (alg.equals("RS256")) {
            return getRsaVerifier(msgCtxt);
        }

        throw new IllegalStateException("algorithm is unsupported: " + alg);
    }

    // Return all properties that begin with claim_
    // This allows this Verify callout to check each one of those
    // claims and only return success only if they all check out.
    private Map<String, String> requiredClaimsProperties() {
        Predicate<Map.Entry<String, String>> p1 =
            new Predicate<Map.Entry<String, String>>() {
            @Override
            public boolean apply(Map.Entry<String, String> entry) {
                return entry.getKey().startsWith("claim_");
            }
        };
        Map<String, String> claimsProps = Maps.filterEntries(properties, p1);
        return claimsProps;
    }

    public ExecutionResult execute (MessageContext msgCtxt, ExecutionContext exeCtxt) {
        // The validity of the JWT depends on:
        // - the structure. it must be valid.
        // - the algorithm. must match what is required.
        // - the signature. It must verify.
        // - the times. Must not be expired, also respect "notbefore".
        // - the enforced claims. They all must match.
        ExecutionResult result = ExecutionResult.ABORT;
        String wantDebug = this.properties.get("debug");
        boolean debug = (wantDebug != null) && Boolean.parseBoolean(wantDebug);
        boolean continueOnError = false;
        boolean wantVerify = getWantVerify(msgCtxt);
        try {
            boolean valid = true;
            boolean verified = false;
            continueOnError = getContinueOnError(msgCtxt);
            // 1. read the JWT
            String jwt = getJwt(msgCtxt); // a dot-separated JWT
            SignedJWT signedJWT = null;
            try {
                signedJWT = SignedJWT.parse(jwt);
            }
            catch ( java.text.ParseException pe1) {
                msgCtxt.setVariable(varName("isValid"), "false");
                msgCtxt.setVariable(varName("reason"), "the JWT did not parse.");
                return (continueOnError) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
            }
            ReadOnlyJWTClaimsSet claims = null;
            msgCtxt.setVariable(varName("isSigned"), "true");

            // emit the jwt and header, and potentially the kid
            msgCtxt.setVariable(varName("jwt"), jwt);
            JWSHeader jwsh = signedJWT.getHeader();
            net.minidev.json.JSONObject json = jwsh.toJSONObject();
            msgCtxt.setVariable(varName("jwtheader"), json.toString());
            String kid = (String) json.get("kid");
            if (kid != null) msgCtxt.setVariable(varName("kid"), kid);

            if (wantVerify) {
                // 2. check that the provided algorithm matches what is required
                String requiredAlgorithm = getAlgorithm(msgCtxt);
                String providedAlgorithm = jwsh.getAlgorithm().toString();
                if (!providedAlgorithm.equals("HS256") && !providedAlgorithm.equals("RS256")) {
                    // invalid configuration, throw an exception (fault)
                    throw new UnsupportedOperationException("provided Algorithm=" + providedAlgorithm);
                }
                if (!providedAlgorithm.equals(requiredAlgorithm)) {
                    msgCtxt.setVariable(varName("isValid"), "false");
                    msgCtxt.setVariable(varName("reason"),
                                        String.format("Algorithm mismatch. provided=%s, required=%s",
                                                      providedAlgorithm, requiredAlgorithm));
                    return (continueOnError) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
                }

                // 3. conditionally verify the signature
                JWSVerifier verifier = getVerifier(requiredAlgorithm, msgCtxt);
                if (signedJWT.verify(verifier)) {
                    verified = true;
                    msgCtxt.setVariable(varName("verified"), "true");
                }
                else {
                    msgCtxt.setVariable(varName("verified"), "false");
                    msgCtxt.setVariable(varName("isValid"), "false");
                    msgCtxt.setVariable(varName("reason"), "the signature could not be verified");
                }
            }
            else {
                msgCtxt.setVariable(varName("isValid"), "false");
                msgCtxt.setVariable(varName("verified"), "false");
                msgCtxt.setVariable(varName("reason"), "the signature was not verified");
            }

            // 4. Retrieve and parse the JWT claims
            // diagnostics: emit all claims, formatted as json, into a variable
            claims = signedJWT.getJWTClaimsSet();
            json = claims.toJSONObject();

            msgCtxt.setVariable(varName("claims"), json.toString());

            // 5. emit some specific standard claims into their own context variables
            // 5a. subject
            String subject = claims.getSubject();
            msgCtxt.setVariable(varName("subject"), subject);

            // 5b. audience (optional)
            List<String> auds = claims.getAudience();
            if (auds != null) {
                String[] audiences = auds.toArray(new String[0]);
                if (audiences != null && audiences.length>0) {
                    msgCtxt.setVariable(varName("audience"), StringUtils.join(audiences, ","));
                }
                else {
                    msgCtxt.removeVariable(varName("audience"));
                }
            }
            else {
                msgCtxt.removeVariable(varName("audience"));
            }

            // 5c. issuer
            String issuer = claims.getIssuer();
            msgCtxt.setVariable(varName("issuer"), issuer);

            // 5d. issued-at
            Date now = new Date();
            if (this.properties.containsKey("currentTime")) {
                now = new Date(Long.parseLong(this.properties.get("currentTime"),10));
            }
            recordTimeVariable(msgCtxt, now, "now");
            
            long timeAllowance = getTimeAllowance(msgCtxt);
            msgCtxt.setVariable(varName("timeAllowance"), Long.toString(timeAllowance, 10));
            if (timeAllowance < 0L) {
                msgCtxt.setVariable(varName("timeCheckDisabled"), "true");
            }

            long ms, secsRemaining;
            Date t1 = claims.getIssueTime();
            if (t1 != null) {
                recordTimeVariable(msgCtxt, t1, "issueTime");
                ms = now.getTime() - t1.getTime();
                if (timeAllowance >= 0L) {
                    valid = (ms + timeAllowance >= 0L);
                    if (!valid) {
                        msgCtxt.setVariable(varName("reason"), "issuedAt is in the future");
                    }
                }
            }

            // 5e. expiration
            Date t2 = claims.getExpirationTime();
            if (t2 != null) {
                msgCtxt.setVariable(varName("hasExpiry"), "true");
                recordTimeVariable(msgCtxt, t2, "expirationTime");

                // 5f. elaborated values for expiry
                ms = t2.getTime() - now.getTime(); // positive means still valid
                secsRemaining = ms/1000;
                msgCtxt.setVariable(varName("secondsRemaining"), secsRemaining + "");
                msgCtxt.setVariable(varName("timeRemainingFormatted"),
                                    (ms<0) ?
                                    "-" + DurationFormatUtils.formatDurationHMS(0-ms) :
                                    DurationFormatUtils.formatDurationHMS(ms));

                // 5g. computed boolean expired
                boolean expired = (ms <= 0L);
                msgCtxt.setVariable(varName("isActuallyExpired"), expired + "");
                if (timeAllowance >= 0L) {
                    expired = (ms + timeAllowance <= 0L);
                    msgCtxt.setVariable(varName("hasExpiryAllowance"), "true");
                    msgCtxt.setVariable(varName("isExpired"), expired + "");
                    if (expired) {
                        valid = false;
                        msgCtxt.setVariable(varName("reason"), "the token is expired");
                    }
                }
                else {
                    msgCtxt.setVariable(varName("hasExpiryAllowance"), "false");
                    msgCtxt.setVariable(varName("isExpired"), "false");
                }
            }
            else {
                msgCtxt.setVariable(varName("isExpired"), "false");
                msgCtxt.setVariable(varName("hasExpiry"), "false");
            }

            // 5h. the id, if any
            String jti = claims.getJWTID();
            if (jti != null) {
                msgCtxt.setVariable(varName("jti"), jti);
            }

            // optional nbf (not-Before) (Sec 4.1.5)
            Date t3 = claims.getNotBeforeTime();

            // 6. validate not-before-time
            if (t3 != null) {
                // log whether valid or not
                recordTimeVariable(msgCtxt,t3,"notBeforeTime");
                if (valid) {
                    ms = now.getTime() - t3.getTime(); // positive means valid
                    msgCtxt.setVariable(varName("nbf_delta"), Long.toString(ms,10));
                    if (timeAllowance >= 0L) {
                        if (ms + timeAllowance < 0L ) {
                            msgCtxt.setVariable(varName("reason"), "notBeforeTime is in the future");
                            valid = false;
                        }
                    }
                }
            }

            // 7. evaluate all the claims that have been configured as
            // required on this token.
            if (valid) {
                Map<String,String> requiredClaims = requiredClaimsProperties();
                if (requiredClaims.size() > 0) {
                    // iterate the map
                    for (Map.Entry<String, String> entry : requiredClaims.entrySet()) {
                        if (valid) {
                            String key = entry.getKey();
                            String expectedValue = entry.getValue();
                            expectedValue = resolvePropertyValue(expectedValue, msgCtxt);
                            // diagnostics: show the expected value
                            msgCtxt.setVariable(varName(key + "_expected"), expectedValue);

                            String[] parts = StringUtils.split(key,"_",2);
                            // sanity check - is this a required claim?
                            if (parts.length == 2 && parts[0].equals("claim")) {
                                String claimName = parts[1];
                                // special case aud, which is always an array
                                if (claimName.equals("aud")) {
                                    if (auds.indexOf(expectedValue) == -1) {
                                        valid = false;
                                        msgCtxt.setVariable(varName("reason"), "audience violation");
                                    }
                                }
                                else {
                                    // sometimes a List<String>, and sometimes not.
                                    Object providedValue = claims.getClaim(claimName);
                                    boolean match = false;
                                    if (providedValue == null) {
                                        msgCtxt.setVariable(varName("reason"),
                                                            String.format("mismatch in claim %s, expected:%s provided:null",
                                                                          claimName, expectedValue));
                                                valid = false;
                                    }
                                    else {
                                        String type = providedValue.getClass().getCanonicalName();
                                        if (type.equals("java.lang.String")) {
                                            // simple string match

                                            msgCtxt.setVariable(varName(key + "_provided"), providedValue);
                                            match = expectedValue.equals((String)providedValue);
                                            if (!match) {
                                                msgCtxt.setVariable(varName("reason"),
                                                                    String.format("mismatch in claim %s, expected:%s provided:%s",
                                                                                  claimName, expectedValue, providedValue));
                                                valid = false;
                                            }
                                        }
                                        else if (type.equals("net.minidev.json.JSONArray")) {
                                            // it's a list of Object (often String)
                                            net.minidev.json.JSONArray a = (net.minidev.json.JSONArray) providedValue;
                                            msgCtxt.setVariable(varName(key + "_provided"), StringUtils.join(a,"|"));
                                            match = false;
                                            for (Object item : a) {
                                                if (item.getClass().getCanonicalName().equals("java.lang.String")) {
                                                    if (expectedValue.equals((String) item)) { match = true;}
                                                }
                                            }
                                            if (!match) {
                                                msgCtxt.setVariable(varName("reason"),
                                                                    String.format("mismatch in claim %s, expected:%s provided:%s",
                                                                                  claimName, expectedValue, StringUtils.join(a,"|")));
                                                valid = false;
                                            }
                                        }
                                        else {
                                            msgCtxt.setVariable(varName("reason"),
                                                                String.format("could not verify claim %s, expected:%s", claimName, expectedValue));
                                            valid = false;
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
            }

            // 8. set context variables for custom claims if they are strings.
            Map<String,Object> customClaims = claims.getCustomClaims();
            if (customClaims.size() > 0) {
                for (Map.Entry<String, Object> entry : customClaims.entrySet()) {
                    String key = entry.getKey();
                    Object value = entry.getValue();
                    if (value instanceof String) {
                        msgCtxt.setVariable(varName("claim_" + key), (String) value);
                    }
                }
            }

            // 9. finally, set the valid context variable
            msgCtxt.setVariable(varName("isValid"), (valid && verified) + "");
            if ((valid && verified) || continueOnError || !wantVerify) {
                result = ExecutionResult.SUCCESS;
            }
        }
        catch (Exception e) {
            // unhandled exceptions
            if (debug) { e.printStackTrace(); /* to MP system.log */ }
            String error = e.toString();
            msgCtxt.setVariable(varName("error"), error);
            int ch = error.lastIndexOf(':');
            if (ch >= 0) {
                msgCtxt.setVariable(varName("reason"), error.substring(ch+2));
            }
            else {
                msgCtxt.setVariable(varName("reason"), error);
            }
            msgCtxt.setVariable(varName("isValid"), "false");

            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            if (continueOnError) {
                result = ExecutionResult.SUCCESS;
            }
        }
        return result;
    }
}

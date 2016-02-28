package com.apigee.callout.jwtsigned;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;

import org.apache.commons.lang.time.DurationFormatUtils;
import org.apache.commons.lang.exception.ExceptionUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.ssl.PKCS8Key;
import org.apache.commons.codec.binary.Base64;

import java.util.Date;
import java.util.Map;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.text.SimpleDateFormat;

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
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.KeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateException;

// Google's Guava collections tools
import com.google.common.collect.Collections2;
import com.google.common.collect.Maps;
import com.google.common.base.Predicate;

import com.apigee.callout.jwtsigned.KeyUtils;


@IOIntensive
public class JwtParserCallout implements Execution {
    private static final String _varPrefix = "jwt_";
    private static long defaultTimeAllowanceMilliseconds = 1000L;
    private final static SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
    private Map<String,String> properties; // read-only

    public JwtParserCallout (Map properties) {
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
        InputStream in = JwtParserCallout.class.getResourceAsStream(resourceName);

        if (in == null) {
            throw new IOException("resource \"" + resourceName + "\" not found");
        }

        return in;
    }

    private static final String varName(String s) { return _varPrefix + s; }

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
        msgContext.setVariable(varName(label + "Formatted"), sdf.format(d));
    }


    private PublicKey getPublicKey(MessageContext msgCtxt)
        throws IOException,
               NoSuchAlgorithmException,
               InvalidKeySpecException,
               CertificateException
    {
        String publicKeyString = (String) this.properties.get("public-key");

        // There are various ways to specify the public key.

        // Try "public-key"
        if (publicKeyString !=null) {
            if (publicKeyString.equals("")) {
                throw new IllegalStateException("public-key must be non-empty");
            }
            publicKeyString = resolvePropertyValue(publicKeyString, msgCtxt);

            if (publicKeyString==null || publicKeyString.equals("")) {
                throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
            }
            PublicKey key = KeyUtils.publicKeyStringToPublicKey(publicKeyString);
            if (key==null) {
                throw new InvalidKeySpecException("must be PKCS#1 or PKCS#8");
            }
            return key;
        }

        // Try "modulus" + "exponent"
        String modulus = (String) this.properties.get("modulus");
        String exponent = (String) this.properties.get("exponent");

        if ((modulus != null) && (exponent != null)) {
            modulus = resolvePropertyValue(modulus, msgCtxt);
            exponent = resolvePropertyValue(exponent, msgCtxt);

            if (modulus==null || modulus.equals("") ||
                exponent==null || exponent.equals("")) {
                throw new IllegalStateException("modulus or exponent resolves to empty; invalid when algorithm is RS*");
            }

            PublicKey key = KeyUtils.pubKeyFromModulusAndExponent(modulus, exponent);
            return key;
        }

        // Try certificate
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
            PublicKey key = KeyUtils.certStringToPublicKey(certString);
            if (key==null) {
                throw new InvalidKeySpecException("invalid certificate format");
            }
            return key;
        }

        // last chance
        String pemfile = (String) this.properties.get("pemfile");
        if (pemfile == null || pemfile.equals("")) {
            throw new IllegalStateException("must specify pemfile or public-key or certificate when algorithm is RS*");
        }
        pemfile = resolvePropertyValue(pemfile, msgCtxt);
        //msgCtxt.setVariable("jwt_pemfile", pemfile);
        if (pemfile == null || pemfile.equals("")) {
            throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
        }

        InputStream in = getResourceAsStream(pemfile);
        byte[] keyBytes = new byte[in.available()];
        in.read(keyBytes);
        in.close();
        publicKeyString = new String(keyBytes, "UTF-8");

        // allow pemfile resolution as Certificate or Public Key
        PublicKey key = KeyUtils.pemFileStringToPublicKey(publicKeyString);
        if (key==null) {
            throw new InvalidKeySpecException("invalid pemfile format");
        }
        return key;
    }


    private JWSVerifier generateVerifier(String alg, MessageContext msgCtxt)
        throws IllegalStateException,
               UnsupportedEncodingException,
               IOException,
               InvalidKeySpecException,
               CertificateException,
               NoSuchAlgorithmException {

        if (alg.equals("HS256")) {
            String key = getSecretKey(msgCtxt);
            // byte[] keyBytes = KeyUtils.getKeyBytesForHmac256(key);
            byte[] keyBytes = key.getBytes("UTF-8");
            // NB: this will throw if the string is not at least 16 chars long
            return new MACVerifier(keyBytes);
        }
        else if (alg.equals("RS256")) {
            RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(msgCtxt);
            return new RSASSAVerifier(publicKey);
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

    public ExecutionResult execute (MessageContext msgCtxt,
                                    ExecutionContext exeCtxt) {
        // The validity of the JWT depends on:
        // - the structure. it must be valid.
        // - the algorithm. must match what is required.
        // - the signature. It must verify.
        // - the times. Must not be expired, also respect "notbefore".
        // - the enforced claims. They all must match.
        String wantDebug = this.properties.get("debug");
        boolean debug = (wantDebug != null) && Boolean.parseBoolean(wantDebug);
        try {
            // 1. read the JWT
            String jwt = getJwt(msgCtxt); // a dot-separated JWT
            SignedJWT signedJWT = null;
            try {
                signedJWT = SignedJWT.parse(jwt);
            }
            catch ( java.text.ParseException pe1) {
                msgCtxt.setVariable(varName("isValid"),"false");
                msgCtxt.setVariable(varName("reason"), "the JWT did not parse.");
                return ExecutionResult.SUCCESS;
            }
            ReadOnlyJWTClaimsSet claims = null;
            msgCtxt.setVariable(varName("isSigned"), "true");

            // diagnostics: emit the jwt and header
            msgCtxt.setVariable(varName("jwt"), jwt);
            JWSHeader jwsh = signedJWT.getHeader();
            net.minidev.json.JSONObject json = jwsh.toJSONObject();
            msgCtxt.setVariable(varName("jwtheader"), json.toString());

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
                return ExecutionResult.SUCCESS;
            }

            // 3. set up the signature verifier according to the required algorithm and its inputs
            boolean valid = true;
            JWSVerifier verifier = generateVerifier(requiredAlgorithm, msgCtxt);

            // 4. actually verify the signature
            if (!signedJWT.verify(verifier)) {
                msgCtxt.setVariable(varName("verified"), "false");
                msgCtxt.setVariable(varName("isValid"), "false");
                msgCtxt.setVariable(varName("reason"), "the signature could not be verified");
                return ExecutionResult.SUCCESS;
            }
            else {
                msgCtxt.setVariable(varName("verified"), "true");
            }

            // 5. Retrieve and parse the JWT claims
            // diagnostics: emit all claims, formatted as json, into a variable
            claims = signedJWT.getJWTClaimsSet();
            json = claims.toJSONObject();

            msgCtxt.setVariable(varName("claims"), json.toString());

            // 6. emit some specific standard claims into their own context variables
            // 6a. subject
            String subject = claims.getSubject();
            msgCtxt.setVariable(varName("subject"), subject);

            // 6b. audience (optional)
            List<String> auds = claims.getAudience();
            if (auds != null) {
                String[] audiences = auds.toArray(new String[0]);
                if (audiences != null && audiences.length>0) {
                    msgCtxt.setVariable(varName("audience"), StringUtils.join(audiences, ","));
                }
                else {
                    msgCtxt.setVariable(varName("audience"), "-not-set-");
                }
            }
            else {
                msgCtxt.setVariable(varName("audience"), "-not-set-");
            }

            // 6c. issuer
            String issuer = claims.getIssuer();
            msgCtxt.setVariable(varName("issuer"), issuer);

            Date now = new Date();
            recordTimeVariable(msgCtxt,now,"now");

            // 6d. issued-at
            long ms, secsRemaining;
            Date t1 = claims.getIssueTime();
            if (t1 != null) {
                recordTimeVariable(msgCtxt,t1,"issueTime");
                ms = now.getTime() - t1.getTime();
                valid = (ms >= 0);
            }

            // 6e. expiration
            long timeAllowance = getTimeAllowance(msgCtxt);
            msgCtxt.setVariable(varName("timeAllowance"), Long.toString(timeAllowance,10));
            if (timeAllowance < 0L) {
                msgCtxt.setVariable(varName("timeCheckDisabled"), "true");
            }
            Date t2 = claims.getExpirationTime();
            if (t2 != null) {
                msgCtxt.setVariable(varName("hasExpiry"), "true");
                recordTimeVariable(msgCtxt,t2,"expirationTime");

                // 6f. elaborated values for expiry
                ms = t2.getTime() - now.getTime();
                secsRemaining = ms/1000;
                msgCtxt.setVariable(varName("secondsRemaining"), secsRemaining + "");
                msgCtxt.setVariable(varName("timeRemainingFormatted"),
                                    (ms<0) ?
                                    "-" + DurationFormatUtils.formatDurationHMS(0-ms) :
                                    DurationFormatUtils.formatDurationHMS(ms));

                // 6g. computed boolean isExpired
                boolean expired = (ms <= timeAllowance);
                msgCtxt.setVariable(varName("isExpired"), expired + "");
                if (timeAllowance >= 0L) {
                    if (expired) {
                        valid = false;
                        msgCtxt.setVariable(varName("reason"), "the token is expired");
                    }
                }
            }
            else {
                msgCtxt.setVariable(varName("isExpired"), "false");
                msgCtxt.setVariable(varName("hasExpiry"), "false");
            }

            // optional nbf (not-Before) (Sec 4.1.5)
            Date t3 = claims.getNotBeforeTime();

            // 7. validate not-before-time
            if (t3 != null) {
                // log whether valid or not
                recordTimeVariable(msgCtxt,t3,"notBeforeTime");
                if (valid) {
                    ms = now.getTime() - t3.getTime(); // positive means valid
                    msgCtxt.setVariable(varName("nbf_delta"), Long.toString(ms,10));
                    if (timeAllowance >= 0L) {
                        if (ms < timeAllowance) {
                            msgCtxt.setVariable(varName("reason"), "notBeforeTime is in the future");
                            valid = false;
                        }
                    }
                }
            }

            // 8. evaluate all the claims that have been configured as
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

                        String[] parts = StringUtils.split(key,"_");
                        // sanity check - is this a required claim?
                        if (parts.length == 2 && parts[0].equals("claim")) {
                            String claimName =  parts[1];
                            // special case aud, which is an array
                            if (claimName.equals("aud")) {
                                if (auds.indexOf(expectedValue) == -1) {
                                    valid = false;
                                    msgCtxt.setVariable(varName("reason"), "audience violation");
                                }
                            }
                            else {
                                // string match all other required claims
                                String providedValue = claims.getStringClaim(claimName);
                                boolean match = expectedValue.equals(providedValue);
                                if (!match) {
                                    msgCtxt.setVariable(varName("reason"),
                                                        String.format("mismatch in claim %s, expected:%s provided:%s",
                                                                      claimName, expectedValue, providedValue));
                                    valid = false;
                                }
                                msgCtxt.setVariable(varName(key + "_provided"), providedValue);
                            }
                        }
                        }
                    }
                }
            }

            // 9. finally, set the valid context variable
            msgCtxt.setVariable(varName("isValid"), valid + "");
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

            //System.out.println("exception: " + e.toString());
            msgCtxt.setVariable(varName("stacktrace"), ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}

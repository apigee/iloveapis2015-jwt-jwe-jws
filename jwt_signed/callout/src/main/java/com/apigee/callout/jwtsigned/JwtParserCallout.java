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
import java.text.SimpleDateFormat;

import com.nimbusds.jwt.SignedJWT;
import com.nimbusds.jwt.PlainJWT;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import com.nimbusds.jwt.ReadOnlyJWTClaimsSet;

import java.io.InputStream;
import java.io.IOException;
import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.security.interfaces.RSAPublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateException;


import org.apache.commons.ssl.PKCS8Key;
import org.apache.commons.codec.binary.Base64;


// Google's Guava collections tools
import com.google.common.collect.Collections2;
import com.google.common.collect.Maps;
import com.google.common.base.Predicate;


@IOIntensive
public class JwtParserCallout implements Execution {

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

    private String getKey(MessageContext msgCtxt) throws Exception {
        String key = (String) this.properties.get("key");
        if (key == null || key.equals("")) {
            throw new IllegalStateException("key is not specified or is empty.");
        }
        key = resolvePropertyValue(key, msgCtxt);
        if (key == null || key.equals("")) {
            throw new IllegalStateException("key is null or empty.");
        }
        return key;
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

    private String getVarname(String prefix, String label) {
        return prefix + "_" + label;
    }

    private void recordTimeVariable(MessageContext msgContext, String stepName,
                                    SimpleDateFormat sdf, Date d, String label) {
        String varName = getVarname(stepName,label);
        msgContext.setVariable(varName, d.getTime() + "");
        varName = getVarname(stepName,label + "Formatted");
        msgContext.setVariable(varName, sdf.format(d));
    }


    private static PublicKey publicKeyStringToPublicKey(String s)
        throws InvalidKeySpecException, NoSuchAlgorithmException {
        s = s.trim();
        if (s.startsWith("-----BEGIN RSA PUBLIC KEY-----") &&
            s.endsWith("-----END RSA PUBLIC KEY-----")) {
            // figure PKCS#1
            s = s.substring(30, s.length() - 28);
            // add the boilerplate to convert to pkcs#8
            s = "MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8A" + s;
        }
        else if (s.startsWith("-----BEGIN PUBLIC KEY-----") &&
                 s.endsWith("-----END PUBLIC KEY-----")) {
            // figure PKCS#8
            s = s.substring(26, s.length() - 24);
        }
        else {
            return null;
        }

        s = s.replaceAll("[\\r|\\n| ]","");
        byte[] keyBytes = Base64.decodeBase64(s);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }


    private static PublicKey certStringToPublicKey(String s)
        throws InvalidKeySpecException, CertificateException, UnsupportedEncodingException {
        s = s.trim();

        if (s.startsWith("-----BEGIN CERTIFICATE-----") &&
            s.endsWith("-----END CERTIFICATE-----")) {
            // This is an X509 cert;
            // Strip the prefix and suffix.
            s = s.substring(27, s.length() - 25);

            s = s.replaceAll("[\\r|\\n| ]","");
            // base64-decode it, and  produce a public key from the result
            byte[] certBytes = Base64.decodeBase64(s);
            ByteArrayInputStream is = new ByteArrayInputStream(certBytes);
            CertificateFactory fact = CertificateFactory.getInstance("X.509");
            X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
            PublicKey key = cer.getPublicKey();
            return key;
        }

        return null;
    }


    private PublicKey pemFileStringToPublicKey(String s)
        throws InvalidKeySpecException,
               CertificateException,
               UnsupportedEncodingException,
               NoSuchAlgorithmException {

        PublicKey key = publicKeyStringToPublicKey(s);
        if (key==null) {
            key = certStringToPublicKey(s);
        }
        return key; // maybe null
    }


    private PublicKey getPublicKey(MessageContext msgCtxt)
        throws IOException,
               NoSuchAlgorithmException,
               InvalidKeySpecException,
               CertificateException
    {
        String publicKeyString = (String) this.properties.get("public-key");

        if (publicKeyString !=null) {
            if (publicKeyString.equals("")) {
                throw new IllegalStateException("public-key must be non-empty");
            }
            publicKeyString = resolvePropertyValue(publicKeyString, msgCtxt);
            //msgCtxt.setVariable("jwt_publickey", publicKeyString);
            if (publicKeyString==null || publicKeyString.equals("")) {
                throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
            }
            PublicKey key = publicKeyStringToPublicKey(publicKeyString);
            if (key==null) {
                throw new InvalidKeySpecException("must be PKCS#1 or PKCS#8");
            }
            return key;
        }

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
            PublicKey key = certStringToPublicKey(certString);
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
        PublicKey key = pemFileStringToPublicKey(publicKeyString);
        if (key==null) {
            throw new InvalidKeySpecException("invalid pemfile format");
        }
        return key;
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
        String varName;
        String varPrefix = "jwt";
        try {
            String ALG = getAlgorithm(msgCtxt);
            String jwt = getJwt(msgCtxt); // dot-separated JWT
            ReadOnlyJWTClaimsSet claims = null;
            SignedJWT signedJWT = null;
            JWSVerifier verifier;
            // diagnostic purposes
            varName = getVarname(varPrefix,"jwt");
            msgCtxt.setVariable(varName, jwt);

            if (ALG.equals("HS256")) {
                String key = getKey(msgCtxt);
                if (key != null && !key.equals("")) {
                    // we have a key, we want to verify the JWT
                    byte[] keyBytes = key.getBytes("UTF-8");
                    signedJWT = SignedJWT.parse(jwt);
                    verifier = new MACVerifier(keyBytes);

                    // verify - check the hash against the key
                    if (!signedJWT.verify(verifier)) {
                        System.out.println("signature is not valid...");
                        varName = getVarname(varPrefix,"error");
                        msgCtxt.setVariable(varName, "Error (A): JWT does not decrypt");
                        return ExecutionResult.ABORT;
                    }

                    // Retrieve and parse the JWT claims
                    claims = signedJWT.getJWTClaimsSet();
                    varName = getVarname(varPrefix,"verified");
                    msgCtxt.setVariable(varName, true+"");
                    varName = getVarname(varPrefix, "isSigned");
                    msgCtxt.setVariable(varName, true+"");
                }
                else {
                    try {
                        signedJWT = SignedJWT.parse(jwt);
                        claims = signedJWT.getJWTClaimsSet();
                        varName = getVarname(varPrefix,"verified");
                        msgCtxt.setVariable(varName, false+"");
                        varName = getVarname(varPrefix, "isSigned");
                        msgCtxt.setVariable(varName, true+"");
                    }
                    catch (java.text.ParseException pe) {
                        System.out.println("exception: " + pe.toString());
                        System.out.println("trying to parse as plain jwt...");
                        try {
                            PlainJWT plainJwt = PlainJWT.parse(jwt);
                            claims = plainJwt.getJWTClaimsSet();
                            varName = getVarname(varPrefix,"verified");
                            msgCtxt.setVariable(varName, false+"");
                            varName = getVarname(varPrefix, "isSigned");
                            msgCtxt.setVariable(varName, false+"");
                        }
                        catch (Exception exc2) {
                            varName = getVarname(varPrefix,"error");
                            System.out.println("Exception (B): " + exc2.toString());
                            msgCtxt.setVariable(varName, "cannot parse that JWT");
                            return ExecutionResult.ABORT;
                        }
                    }
                }
            }
            else if (ALG.equals("RS256")) {
                signedJWT = SignedJWT.parse(jwt);
                RSAPublicKey publicKey = (RSAPublicKey) getPublicKey(msgCtxt);
                verifier = new RSASSAVerifier(publicKey);

                // verify the signature
                if (!signedJWT.verify(verifier)) {
                    System.out.println("signature is not valid...");
                    varName = getVarname(varPrefix,"error");
                    msgCtxt.setVariable(varName, "Error (C): JWT does not decrypt");
                    return ExecutionResult.ABORT;
                }

                // Retrieve and parse the JWT claims
                claims = signedJWT.getJWTClaimsSet();
                varName = getVarname(varPrefix,"verified");
                msgCtxt.setVariable(varName, true+"");
                varName = getVarname(varPrefix, "isSigned");
                msgCtxt.setVariable(varName, true+"");
            }
            else {
                throw new UnsupportedOperationException("Algorithm=" + ALG);
            }

            SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd'T'HH:mm:ss.SSSZ");
            net.minidev.json.JSONObject json = claims.toJSONObject();
            System.out.println("JWT payload:" + json.toString());

            // emit all claims, formatted as json, into a variable
            varName = getVarname(varPrefix, "claims");
            msgCtxt.setVariable(varName, json.toString());

            // emit some specific claims into their own variables
            String subject = claims.getSubject();
            varName = getVarname(varPrefix,"subject");
            msgCtxt.setVariable(varName, subject);

            // audience is optional
            List<String> auds = claims.getAudience();
            if (auds != null) {
                String[] audiences = auds.toArray(new String[0]);
                varName = getVarname(varPrefix, "audience");
                if (audiences != null && audiences.length>0) {
                    msgCtxt.setVariable(varName, StringUtils.join(audiences, ","));
                }
                else {
                    msgCtxt.setVariable(varName, "-not-set-");
                }
            }
            else {
                msgCtxt.setVariable(varName, "-not-set-");
            }

            String issuer = claims.getIssuer();
            varName = getVarname(varPrefix, "issuer");
            msgCtxt.setVariable(varName, issuer);

            Date now = new Date();
            recordTimeVariable(msgCtxt,varPrefix,sdf,now,"now");

            Date t1 = claims.getIssueTime();
            recordTimeVariable(msgCtxt,varPrefix,sdf,t1,"issueTime");

            // TODO: verify that the token was not marked as having been
            // issued in the future. The issueTime must be before "now".

            Date t2 = claims.getExpirationTime();
            recordTimeVariable(msgCtxt,varPrefix,sdf,t2,"expirationTime");

            varName = getVarname(varPrefix, "secondsRemaining");
            int ms = (int) (t2.getTime() - now.getTime());
            int secsRemaining = ms/1000;
            msgCtxt.setVariable(varName, secsRemaining + "");
            varName = getVarname(varPrefix, "timeRemainingFormatted");
            if (ms<0) {
                msgCtxt.setVariable(varName, "-" + DurationFormatUtils.formatDurationHMS(0-ms));
            }
            else {
                msgCtxt.setVariable(varName, DurationFormatUtils.formatDurationHMS(ms));
            }

            varName = getVarname(varPrefix, "isExpired");
            boolean expired = (ms <= 0);
            msgCtxt.setVariable(varName, expired + "");

            // optional nbf (not-Before) (Sec 4.1.5)
            Date t3 = claims.getNotBeforeTime();

            // The validity of the JWT depends on the times,
            // and the various claims that must be enforced.
            boolean valid = !expired;
            if (t3 != null) {
                recordTimeVariable(msgCtxt,varPrefix,sdf,t3,"notBeforeTime");

                ms = (int) (now.getTime() - t3.getTime());
                //int secsValid = ms/1000;
                valid = valid && (ms >= 0);
            }

            // evaluate all the claims that have been configured as
            // required on this token.
            Map<String,String> requiredClaims = requiredClaimsProperties();
            if (requiredClaims.size() > 0) {
                // iterate the map
                for (Map.Entry<String, String> entry : requiredClaims.entrySet()) {
                    String key = entry.getKey();
                    String expectedValue = entry.getValue();
                    expectedValue = resolvePropertyValue(expectedValue, msgCtxt);
                    varName = getVarname(varPrefix, key + "_expected");
                    msgCtxt.setVariable(varName, expectedValue);

                    String[] parts = StringUtils.split(key,"_");
                    // sanity check - is this a required claim?
                    if (parts.length == 2 && parts[0].equals("claim")) {
                        String claimName =  parts[1];
                        // special case aud, which is an array
                        if (claimName.equals("aud")) {
                            valid = valid && (auds.indexOf(expectedValue) != -1);
                        }
                        else {
                            String providedValue = claims.getStringClaim(claimName);
                            valid = valid && expectedValue.equals(providedValue);
                            varName = getVarname(varPrefix, key + "_provided");
                            msgCtxt.setVariable(varName, providedValue);
                        }
                    }
                }
            }

            // finally, set the valid field
            varName = getVarname(varPrefix, "isValid");
            msgCtxt.setVariable(varName, valid + "");
        }
        catch (Exception e) {
            e.printStackTrace();
            varName = getVarname(varPrefix, "error");
            msgCtxt.setVariable(varName, "Exception (A): " + e.toString());
            System.out.println("exception: " + e.toString());
            varName = getVarname(varPrefix, "stacktrace");
            msgCtxt.setVariable(varName, "Stack (A): " + ExceptionUtils.getStackTrace(e));
            return ExecutionResult.ABORT;
        }
        return ExecutionResult.SUCCESS;
    }
}

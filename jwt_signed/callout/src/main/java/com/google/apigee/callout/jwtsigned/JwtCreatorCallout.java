// Copyright 2018-2020 Google LLC.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package com.google.apigee.callout.jwtsigned;

import com.apigee.flow.execution.ExecutionContext;
import com.apigee.flow.execution.ExecutionResult;
import com.apigee.flow.execution.IOIntensive;
import com.apigee.flow.execution.spi.Execution;
import com.apigee.flow.message.MessageContext;
import com.google.apigee.util.TimeResolver;
import com.google.common.base.Predicate;
import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.text.ParseException;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DateParser;
import org.apache.commons.lang3.time.FastDateFormat;

@IOIntensive
public class JwtCreatorCallout extends SignerCallout implements Execution {
  private static final JOSEObjectType TYP_JWT = new JOSEObjectType("JWT");
  private static final int DEFAULT_EXPIRY_IN_SECONDS = 60 * 60; // one hour
  private static final Pattern secondsSinceEpochPattern = Pattern.compile("[1-2][0-9]{9}");

  private static final FastDateFormat fdf =
      FastDateFormat.getInstance(
          "yyyy-MM-dd'T'HH:mm:ss.SSSZ",
          TimeZone.getTimeZone("UTC")); // 2017-08-14T11:00:21.269-0700
  private static final DateParser DATE_FORMAT_RFC_3339 =
      FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ssXXX"); // 2017-08-14T11:00:21-07:00
  private static final DateParser DATE_FORMAT_RFC_1123 =
      FastDateFormat.getInstance("EEE, dd MMM yyyy HH:mm:ss zzz"); // Mon, 14 Aug 2017 11:00:21 PDT
  private static final DateParser DATE_FORMAT_RFC_850 =
      FastDateFormat.getInstance("EEEE, dd-MMM-yy HH:mm:ss zzz"); // Monday, 14-Aug-17 11:00:21 PDT
  private static final DateParser DATE_FORMAT_ANSI_C =
      FastDateFormat.getInstance("EEE MMM d HH:mm:ss yyyy"); // Mon Aug 14 11:00:21 2017
  private static final DateParser allowableInputFormats[] = {
    DATE_FORMAT_RFC_3339,
    DATE_FORMAT_RFC_1123,
    DATE_FORMAT_RFC_850,
    DATE_FORMAT_ANSI_C,
    (DateParser) fdf
  };

  public JwtCreatorCallout(Map properties) {
    super("jwt_", properties);
  }

  private String getSubject(MessageContext msgCtxt) throws Exception {
    String subject = (String) this.properties.get("subject");
    if (StringUtils.isBlank(subject)) {
      // throw new IllegalStateException("subject is not specified or is empty.");
      return null; // subject is OPTIONAL
    }
    subject = (String) resolvePropertyValue(subject, msgCtxt);
    if (StringUtils.isBlank(subject)) {
      // throw new IllegalStateException("subject is null or empty.");
      return null; // subject is OPTIONAL
    }
    return subject;
  }

  private String getIssuer(MessageContext msgCtxt) throws Exception {
    String issuer = (String) this.properties.get("issuer");
    if (StringUtils.isBlank(issuer)) {
      // throw new IllegalStateException("issuer is not specified or is empty.");
      return null; // "iss" is OPTIONAL per RFC-7519
    }
    issuer = (String) resolvePropertyValue(issuer, msgCtxt);
    if (StringUtils.isBlank(issuer)) {
      // throw new IllegalStateException("issuer is not specified or is empty.");
      return null; // "iss" is OPTIONAL per RFC-7519
    }
    return issuer;
  }

  private String[] getAudience(MessageContext msgCtxt) throws Exception {
    String audience = (String) this.properties.get("audience");
    if (StringUtils.isBlank(audience)) {
      // Audience is optional, per JWT Spec sec 4.1.3
      return null;
    }

    Object resolvedValue = resolvePropertyValueToObject(audience, msgCtxt);
    if (resolvedValue instanceof String[]) {
      // we might already have an array from a property
      return (String[]) resolvedValue;
    } else if (resolvedValue instanceof org.mozilla.javascript.NativeArray) {
      return nativeToJavaArray((org.mozilla.javascript.NativeArray) resolvedValue);
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

  private int getExpiresIn(MessageContext msgCtxt) throws IllegalStateException {
    String expiry = (String) this.properties.get("expiresIn");
    if (StringUtils.isBlank(expiry)) {
      return DEFAULT_EXPIRY_IN_SECONDS;
    }
    expiry = (String) resolvePropertyValue(expiry, msgCtxt);
    if (StringUtils.isBlank(expiry)) {
      throw new IllegalStateException("variable " + expiry + " resolves to nothing.");
    }
    Long durationInMilliseconds = TimeResolver.resolveExpression(expiry);
    return ((Long) (durationInMilliseconds / 1000L)).intValue();
  }

  private static Date parseDateOrTimespan(String dateString, Instant now) {
    if (dateString == null) return null;

    Matcher m = secondsSinceEpochPattern.matcher(dateString);
    if (m.matches()) {
      return new Date(Long.parseLong(dateString) * 1000);
    }

    Long durationInMilliseconds = TimeResolver.resolveExpression(dateString);
    if (durationInMilliseconds >= 0) {
      return Date.from(now.plus(durationInMilliseconds, ChronoUnit.MILLIS));
    }

    for (DateParser format : allowableInputFormats) {
      try {
        return format.parse(dateString);
      } catch (ParseException ex) {
      }
    }
    return null;
  }

  private Date getNotBefore(MessageContext msgCtxt, Instant now) throws Exception {
    String key = "not-before";
    if (!this.properties.containsKey(key)) return null;
    String value = (String) this.properties.get(key);
    if (StringUtils.isBlank(value)) return Date.from(now);
    value = (String) resolvePropertyValue(value, msgCtxt);
    if (StringUtils.isBlank(value)) return Date.from(now);
    return parseDateOrTimespan(value.trim(), now);
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

  private String[] nativeToJavaArray(org.mozilla.javascript.NativeArray a) {
    String[] result = new String[(int) a.getLength()];
    for (Object o : a.getIds()) {
      int index = (Integer) o;
      result[index] = a.get(index, null).toString();
    }
    return result;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = getDebug();
    try {
      Instant now = Instant.now();
      JWSAlgorithm jwsAlg;
      String ISSUER = getIssuer(msgCtxt);
      String ALG = getAlgorithm(msgCtxt);
      String[] AUDIENCE = getAudience(msgCtxt);
      String SUBJECT = getSubject(msgCtxt);
      String JTI = getJwtId(msgCtxt);
      String KEYID = getKeyId(msgCtxt);
      Date NOTBEFORE = getNotBefore(msgCtxt, now);
      int LIFETIME = getExpiresIn(msgCtxt);
      JWSSigner signer;
      String[] audiences = null;

      // 1. Prepare JWT with the set of standard claims
      JWTClaimsSet.Builder claimsBuilder = new JWTClaimsSet.Builder().issueTime(Date.from(now));
      if (ISSUER != null) claimsBuilder.issuer(ISSUER);
      if (SUBJECT != null) claimsBuilder.subject(SUBJECT);
      if (AUDIENCE != null) claimsBuilder.audience(java.util.Arrays.asList(AUDIENCE));
      if (JTI != null) claimsBuilder.jwtID(JTI);

      if (LIFETIME > 0) {
        Instant exp = now.plus(LIFETIME, ChronoUnit.SECONDS);
        claimsBuilder.expirationTime(Date.from(exp));
      }
      if (NOTBEFORE != null) {
        claimsBuilder.notBeforeTime(NOTBEFORE);
      }

      // 2. add all the provided custom claims to the set
      Map<String, String> customClaims = customClaimsProperties(msgCtxt);
      if (customClaims.size() > 0) {
        // iterate the map
        for (Map.Entry<String, String> entry : customClaims.entrySet()) {
          String key = entry.getKey();
          String providedValue = entry.getValue();
          String[] parts = StringUtils.split(key, "_", 2);
          // sanity check - is this a valid claim?
          if (parts.length == 2 && parts[0].equals("claim") && providedValue != null) {
            String claimName = parts[1];
            // msgCtxt.setVariable(varName("resolving_")+claimName, providedValue);
            Object resolvedValue = resolvePropertyValueToObject(providedValue, msgCtxt);
            msgCtxt.setVariable(varName("resolved_") + claimName, resolvedValue.toString());
            if (claimName.startsWith("json")) {
              String[] nameParts = StringUtils.split(claimName, "_", 2);
              if (nameParts.length != 2 || StringUtils.isBlank(parts[1])) {
                throw new IllegalStateException("invalid json claim configuration: " + claimName);
              }
              try {
                net.minidev.json.parser.JSONParser parser =
                    new net.minidev.json.parser.JSONParser();
                net.minidev.json.JSONObject thisClaim =
                    (net.minidev.json.JSONObject) parser.parse(resolvedValue.toString());
                claimsBuilder.claim(nameParts[1], thisClaim);
              } catch (java.lang.Exception exc1) {
                throw new IllegalStateException("cannot parse claim as json: " + claimName, exc1);
              }

            } else if (claimName.equals("aud") && resolvedValue instanceof String) {
              // special case aud, which can be an array
              audiences = StringUtils.split(providedValue, ",");
              claimsBuilder.audience(java.util.Arrays.asList(audiences));
            } else {
              if (resolvedValue instanceof String[]) {
                claimsBuilder.claim(claimName, java.util.Arrays.asList((String[]) resolvedValue));
              } else if (resolvedValue instanceof org.mozilla.javascript.NativeArray) {
                // an array set in a JavaScript callout
                claimsBuilder.claim(
                    claimName,
                    java.util.Arrays.asList(
                        nativeToJavaArray((org.mozilla.javascript.NativeArray) resolvedValue)));
              } else if (resolvedValue != null) {
                // claims.setCustomClaim(claimName, providedValue);
                claimsBuilder.claim(claimName, resolvedValue.toString());
              } else {
                claimsBuilder.claim(claimName, null);
              }
            }
            if (debug) {
              msgCtxt.setVariable(varName("provided_") + claimName, resolvedValue.toString());
            }
          }
        }
      }

      // 3. serialize to a string, for diagnostics purposes
      JWTClaimsSet claims = claimsBuilder.build();
      net.minidev.json.JSONObject json = claims.toJSONObject();
      msgCtxt.setVariable(varName("claims"), json.toString());

      // 3. vet the algorithm, and set up the signer
      if (ALG.equals("HS256")) {
        signer = getMacSigner(msgCtxt);
        jwsAlg = JWSAlgorithm.HS256;
      } else if (ALG.equals("RS256")) {
        signer = getRsaSigner(msgCtxt);
        jwsAlg = JWSAlgorithm.RS256;
      } else if (ALG.equals("PS256")) {
        signer = getRsaSigner(msgCtxt);
        jwsAlg = JWSAlgorithm.PS256;
      } else {
        msgCtxt.setVariable(varName("alg-missing"), ALG);
        throw new IllegalStateException("unsupported algorithm: " + ALG);
      }
      msgCtxt.setVariable(varName("alg"), ALG);

      // 4. Apply the signature
      JWSHeader.Builder headerBuilder = new JWSHeader.Builder(jwsAlg).type(TYP_JWT);
      if (KEYID != null) headerBuilder.keyID(KEYID);
      // TODO: add in b64 header possibly
      JWSHeader h = headerBuilder.build();
      SignedJWT signedJWT = new SignedJWT(h, claims);
      signedJWT.sign(signer);

      // 5. serialize to compact form, produces something like
      // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onOUhyuz0Y18UASXlSc1eS0NkWyA
      String jwt = signedJWT.serialize();
      msgCtxt.setVariable(varName("jwt"), jwt);

    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      return ExecutionResult.ABORT;
    } catch (Exception e) {
      if (getDebug()) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      return ExecutionResult.ABORT;
    }
    return ExecutionResult.SUCCESS;
  }
}

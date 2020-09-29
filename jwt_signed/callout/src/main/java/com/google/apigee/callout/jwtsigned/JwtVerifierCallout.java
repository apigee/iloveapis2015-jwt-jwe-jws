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
import com.google.common.base.Predicate;
import com.google.common.collect.Maps;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import java.util.Date;
import java.util.List;
import java.util.Map;
import java.util.stream.Collectors;
import org.apache.commons.lang3.StringUtils;
import org.apache.commons.lang3.time.DurationFormatUtils;
import org.apache.commons.lang3.time.FastDateFormat;

@IOIntensive
public class JwtVerifierCallout extends VerifierCallout implements Execution {
  // We may wish to allow a grace period on the expiry or a not-before-time
  // of a JWT.  In particular, for the nbf, if the token is acquired from a
  // remote system and then immediately presented here, the nbf may yet be
  // in the future. This number quantifies the allowance for time skew
  // between issuer and verifier (=this code).
  private static final long defaultTimeAllowanceMilliseconds = 1000L;
  // NB: SimpleDateFormat is not thread-safe
  private static final FastDateFormat fdf =
      FastDateFormat.getInstance("yyyy-MM-dd'T'HH:mm:ss.SSSZ");

  public JwtVerifierCallout(Map properties) {
    super("jwt_", properties);
  }

  private boolean getIgnoreIssuedAt(MessageContext msgCtxt) {
    String value = properties.get("ignore-issued-at");
    if (StringUtils.isBlank(value)) {
      return false;
    }
    value = resolvePropertyValue(value, msgCtxt);
    return Boolean.parseBoolean(value);
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
    long longValue =
        StringUtils.isBlank(timeAllowance)
            ? defaultTimeAllowanceMilliseconds
            : Long.parseLong(timeAllowance, 10);
    return longValue;
  }

  private void recordTimeVariable(MessageContext msgContext, Date d, String label) {
    msgContext.setVariable(varName(label), d.getTime() + "");
    msgContext.setVariable(varName(label + "Formatted"), fdf.format(d));
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

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    // The validity of the JWT depends on:
    // - the structure. it must be valid.
    // - the algorithm. must match what is required.
    // - the signature. It must verify.
    // - the times. Must not be expired, also respect "notbefore".
    // - the enforced claims. They all must match.
    msgCtxt.setVariable(varName("isValid"), "false");
    ExecutionResult result = ExecutionResult.ABORT;
    boolean debug = getDebug();
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
      } catch (java.text.ParseException pe1) {
        msgCtxt.setVariable(varName("reason"), "the JWT did not parse.");
        return (continueOnError) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      }
      JWTClaimsSet claims = null;
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
          msgCtxt.setVariable(
              varName("reason"),
              String.format(
                  "Algorithm mismatch. provided=%s, required=%s",
                  providedAlgorithm, requiredAlgorithm));
          return (continueOnError) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
        }

        // 3. conditionally verify the signature
        JWSVerifier verifier = getVerifier(requiredAlgorithm, msgCtxt);
        if (signedJWT.verify(verifier)) {
          verified = true;
          msgCtxt.setVariable(varName("verified"), "true");
        } else {
          msgCtxt.setVariable(varName("verified"), "false");
          msgCtxt.setVariable(varName("reason"), "the signature could not be verified");
        }
      } else {
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
        if (audiences != null && audiences.length > 0) {
          msgCtxt.setVariable(varName("audience"), StringUtils.join(audiences, ","));
        } else {
          msgCtxt.removeVariable(varName("audience"));
        }
      } else {
        msgCtxt.removeVariable(varName("audience"));
      }

      // 5c. issuer
      String issuer = claims.getIssuer();
      msgCtxt.setVariable(varName("issuer"), issuer);

      Date now = new Date();
      recordTimeVariable(msgCtxt, now, "now");

      long timeAllowance = getTimeAllowance(msgCtxt);
      msgCtxt.setVariable(varName("timeAllowance"), Long.toString(timeAllowance, 10));
      if (timeAllowance < 0L) {
        msgCtxt.setVariable(varName("timeCheckDisabled"), "true");
      }

      // 5d. issued-at
      long ms, secsRemaining;
      boolean ignoreIssuedAt = getIgnoreIssuedAt(msgCtxt);
      if (!ignoreIssuedAt) {
        Date t1 = claims.getIssueTime();
        if (t1 != null) {
          recordTimeVariable(msgCtxt, t1, "issueTime");
          ms = now.getTime() - t1.getTime(); // positive means issued in the past
          valid = (timeAllowance >= 0L) ? (ms + timeAllowance >= 0) : (ms >= 0);
        }
      }

      // 5e. expiration
      Date t2 = claims.getExpirationTime();
      if (t2 != null) {
        msgCtxt.setVariable(varName("hasExpiry"), "true");
        recordTimeVariable(msgCtxt, t2, "expirationTime");

        // 5f. elaborated values for expiry
        ms = t2.getTime() - now.getTime(); // positive means still valid
        secsRemaining = ms / 1000;
        msgCtxt.setVariable(varName("secondsRemaining"), secsRemaining + "");
        msgCtxt.setVariable(
            varName("timeRemainingFormatted"),
            (ms < 0)
                ? "-" + DurationFormatUtils.formatDurationHMS(0 - ms)
                : DurationFormatUtils.formatDurationHMS(ms));

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
        } else {
          msgCtxt.setVariable(varName("hasExpiryAllowance"), "false");
          msgCtxt.setVariable(varName("isExpired"), "false");
        }
      } else {
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
        recordTimeVariable(msgCtxt, t3, "notBeforeTime");
        if (valid) {
          ms = now.getTime() - t3.getTime(); // positive means valid
          msgCtxt.setVariable(varName("nbf_delta"), Long.toString(ms, 10));
          if (timeAllowance >= 0L) {
            if (ms + timeAllowance < 0L) {
              msgCtxt.setVariable(varName("reason"), "notBeforeTime is in the future");
              valid = false;
            }
          }
        }
      }

      // 7. evaluate all the claims that have been configured as
      // required on this token.
      if (valid) {
        Map<String, String> requiredClaims = requiredClaimsProperties();
        if (requiredClaims.size() > 0) {
          // iterate the map
          for (Map.Entry<String, String> entry : requiredClaims.entrySet()) {
            if (valid) {
              String key = entry.getKey();
              String expectedValue = entry.getValue();
              expectedValue = resolvePropertyValue(expectedValue, msgCtxt);
              // diagnostics: show the expected value
              msgCtxt.setVariable(varName(key + "_expected"), expectedValue);

              String[] parts = StringUtils.split(key, "_", 2);
              // sanity check - is this a required claim?
              if (parts.length == 2 && parts[0].equals("claim")) {
                String claimName = parts[1];
                // special case aud, which is always an array
                if (claimName.equals("aud")) {
                  if (auds.indexOf(expectedValue) == -1) {
                    valid = false;
                    msgCtxt.setVariable(varName("reason"), "audience violation");
                  }
                } else {
                  // sometimes a List<String>, and sometimes not.
                  Object providedValue = claims.getClaim(claimName);
                  boolean match = false;
                  if (providedValue == null) {
                    msgCtxt.setVariable(
                        varName("reason"),
                        String.format(
                            "mismatch in claim %s, expected:%s provided:null",
                            claimName, expectedValue));
                    valid = false;
                  } else {
                    String type = providedValue.getClass().getCanonicalName();
                    if (type.equals("java.lang.String")) {
                      // simple string match

                      msgCtxt.setVariable(varName(key + "_provided"), providedValue);
                      match = expectedValue.equals((String) providedValue);
                      if (!match) {
                        msgCtxt.setVariable(
                            varName("reason"),
                            String.format(
                                "mismatch in claim %s, expected:%s provided:%s",
                                claimName, expectedValue, providedValue));
                        valid = false;
                      }
                    } else if (type.equals("net.minidev.json.JSONArray")) {
                      // it's a list of Object (often String)
                      net.minidev.json.JSONArray a = (net.minidev.json.JSONArray) providedValue;
                      msgCtxt.setVariable(varName(key + "_provided"), StringUtils.join(a, "|"));
                      match = false;
                      for (Object item : a) {
                        if (item.getClass().getCanonicalName().equals("java.lang.String")) {
                          if (expectedValue.equals((String) item)) {
                            match = true;
                          }
                        }
                      }
                      if (!match) {
                        msgCtxt.setVariable(
                            varName("reason"),
                            String.format(
                                "mismatch in claim %s, expected:%s provided:%s",
                                claimName, expectedValue, StringUtils.join(a, "|")));
                        valid = false;
                      }
                    } else {
                      msgCtxt.setVariable(
                          varName("reason"),
                          String.format(
                              "could not verify claim %s, expected:%s", claimName, expectedValue));
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
      Map<String, Object> customClaims =
          claims.getClaims().entrySet().stream()
              .filter(x -> !JWTClaimsSet.getRegisteredNames().contains(x.getKey()))
              .collect(Collectors.toMap(x -> x.getKey(), x -> x.getValue()));

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
    } catch (IllegalStateException exc1) {
      setExceptionVariables(exc1, msgCtxt);
      if (continueOnError) {
        result = ExecutionResult.SUCCESS;
      }
    } catch (Exception e) {
      if (debug) {
        String stacktrace = getStackTraceAsString(e);
        msgCtxt.setVariable(varName("stacktrace"), stacktrace);
      }
      setExceptionVariables(e, msgCtxt);
      if (continueOnError) {
        result = ExecutionResult.SUCCESS;
      }
    }
    return result;
  }
}

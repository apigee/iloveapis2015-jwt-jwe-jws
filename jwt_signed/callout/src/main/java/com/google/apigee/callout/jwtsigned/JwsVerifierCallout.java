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
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.Payload;
import java.util.Map;

@IOIntensive
public class JwsVerifierCallout extends VerifierCallout implements Execution {

  public JwsVerifierCallout(Map properties) {
    super("jws_", properties);
  }

  private String getJws(MessageContext msgCtxt) throws Exception {
    String jws = (String) this.properties.get("jws");
    if (jws == null || jws.equals("")) {
      throw new IllegalArgumentException("jws is not specified or is empty.");
    }
    jws = resolvePropertyValue(jws, msgCtxt);
    if (jws == null || jws.equals("")) {
      throw new IllegalArgumentException("jwt is null or empty.");
    }
    return jws.trim();
  }

  private String getDetachedContent(MessageContext msgCtxt) throws Exception {
    String content = (String) this.properties.get("detached-content");
    if (content == null) {
      return null;
    }
    if (content.equals("")) {
      return content;
    }
    content = resolvePropertyValue(content, msgCtxt);
    return content;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    // The validity of the JWS depends on:
    // - the structure. it must be valid.
    // - the algorithm. must match what is required.
    // - the signature. It must verify.
    msgCtxt.setVariable(varName("isValid"), "false");
    ExecutionResult result = ExecutionResult.ABORT;
    boolean debug = getDebug();
    boolean continueOnError = false;
    boolean wantVerify = getWantVerify(msgCtxt);
    try {
      boolean valid = true;
      boolean verified = false;
      continueOnError = getContinueOnError(msgCtxt);
      // 1. read the JWS
      String jws = getJws(msgCtxt); // a dot-separated JWS
      String detachedContent = getDetachedContent(msgCtxt);
      JWSObject jwsObject = null;

      try {
        jwsObject =
            (detachedContent != null)
                ? JWSObject.parse(jws, new Payload(detachedContent))
                : JWSObject.parse(jws);

      } catch (java.text.ParseException pe1) {
        msgCtxt.setVariable(varName("reason"), "the JWS did not parse.");
        return (continueOnError) ? ExecutionResult.SUCCESS : ExecutionResult.ABORT;
      }

      JWSHeader jwsh = jwsObject.getHeader();
      net.minidev.json.JSONObject json = jwsh.toJSONObject();
      msgCtxt.setVariable(varName("jwsheader"), json.toString());
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
        JWSVerifier verifier = getVerifier(requiredAlgorithm, jwsh, msgCtxt);
        if (jwsObject.verify(verifier)) {
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

      // 4. finally, set the valid context variable
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

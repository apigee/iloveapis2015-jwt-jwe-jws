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
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSObject;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.Payload;
import java.util.Date;
import java.util.Map;

@IOIntensive
public class JwsCreatorCallout extends SignerCallout implements Execution {
  public JwsCreatorCallout(Map properties) {
    super("jws_", properties);
  }

  private String getPayload(MessageContext msgCtxt) throws Exception {
    String payload = (String) this.properties.get("payload");
    if (payload == null) {
      throw new IllegalStateException("payload is not specified.");
    }
    if (payload.equals("")) {
      return ""; // empty payload. Weird but not illegal.
    }
    payload = (String) resolvePropertyValue(payload, msgCtxt);
    // TODO: maybe deal with payload encoding
    // String encoding = (String) this.properties.get("payload-encoding");
    return payload;
  }

  private boolean isDetachContent(MessageContext msgCtxt) throws Exception {
    String value = (String) this.properties.get("detach-content");
    if (value == null || value.trim().equals("")) return false;
    value = (String) resolvePropertyValue(value, msgCtxt);
    if (value.trim().toLowerCase().equals("true")) return true;
    return false;
  }

  public ExecutionResult execute(MessageContext msgCtxt, ExecutionContext exeCtxt) {
    boolean debug = getDebug();
    try {
      Date now = new Date();
      JWSAlgorithm jwsAlg;
      String ALG = getAlgorithm(msgCtxt);
      String KEYID = getKeyId(msgCtxt);
      JWSSigner signer;

      // 1. Prepare the payload
      Payload payload = new Payload(getPayload(msgCtxt));

      // 2. vet the algorithm, and set up the signer
      if (ALG.equals("HS256")) {
        signer = getMacSigner(msgCtxt);
        jwsAlg = JWSAlgorithm.HS256;
      } else if (ALG.equals("RS256")) {
        // Create RSA-signer with the private key
        signer = getRsaSigner(msgCtxt);
        jwsAlg = JWSAlgorithm.RS256;
      } else {
        msgCtxt.setVariable(varName("alg-missing"), ALG);
        throw new IllegalStateException("unsupported algorithm: " + ALG);
      }
      msgCtxt.setVariable(varName("alg"), ALG);

      // 3. Set up the header
      JWSHeader.Builder builder = new JWSHeader.Builder(jwsAlg);
      if (KEYID != null) builder.keyID(KEYID);

      // 4. Apply the signature
      JWSObject jwsObject = new JWSObject(builder.build(), payload);
      jwsObject.sign(signer);

      // 5. serialize to compact form, to produce something like:
      // eyJhbGciOiJIUzI1NiJ9.SGVsbG8sIHdvcmxkIQ.onOUhyuz0Y18UASXlSc1eS0NkWyA
      String serializedBlob = jwsObject.serialize(isDetachContent(msgCtxt));
      msgCtxt.setVariable(varName("jws"), serializedBlob);

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

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
import com.nimbusds.jose.JWSObject;
import com.apigee.flow.message.MessageContext;
import com.google.common.base.Predicate;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.google.common.collect.Maps;
import com.nimbusds.jose.JOSEObjectType;
import com.nimbusds.jose.JWSAlgorithm;
import com.nimbusds.jose.JWSHeader;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import com.nimbusds.jose.Payload;
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
import java.util.Calendar;
import java.util.Date;
import java.util.Map;
import java.util.TimeZone;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
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
      return ""; // empty payload
    }
    payload = (String) resolvePropertyValue(payload, msgCtxt);
    // TODO: deal with payload encoding
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
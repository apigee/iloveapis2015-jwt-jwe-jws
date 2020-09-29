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

import com.apigee.flow.message.MessageContext;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSVerifier;
import com.nimbusds.jose.crypto.MACVerifier;
import com.nimbusds.jose.crypto.RSASSAVerifier;
import java.io.IOException;
import java.io.InputStream;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;

public abstract class VerifierCallout extends JoseCalloutBase {
  protected LoadingCache<String, JWSVerifier> macVerifierCache;
  protected LoadingCache<PublicKeySource, JWSVerifier> rsaVerifierCache;
  private static final int MAX_CACHE_ENTRIES = 10240;

  protected VerifierCallout(String varPrefix, Map properties) {
    super(varPrefix, properties);

    macVerifierCache =
        CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(
                new CacheLoader<String, JWSVerifier>() {
                  public JWSVerifier load(String key)
                      throws UnsupportedEncodingException, IllegalArgumentException, JOSEException {
                    if (key == null) {
                      throw new IllegalArgumentException("the key is null");
                    }
                    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
                    // NB: this will throw if the string is not at least 16 chars long
                    return new MACVerifier(keyBytes);
                  }
                });

    rsaVerifierCache =
        CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(MAX_CACHE_ENTRIES)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(
                new CacheLoader<PublicKeySource, JWSVerifier>() {
                  public JWSVerifier load(PublicKeySource source)
                      throws NoSuchAlgorithmException, InvalidKeySpecException,
                          IllegalArgumentException, CertificateException,
                          UnsupportedEncodingException {
                    RSAPublicKey publicKey = (RSAPublicKey) source.getPublicKey();
                    if (publicKey == null) {
                      throw new IllegalArgumentException("there was no public key specified.");
                    }
                    return new RSASSAVerifier(publicKey);
                  }
                });
  }

  protected boolean getContinueOnError(MessageContext msgCtxt) {
    String continueOnError = properties.get("continueOnError");
    if (StringUtils.isBlank(continueOnError)) {
      return false;
    }
    continueOnError = resolvePropertyValue(continueOnError, msgCtxt);
    return Boolean.parseBoolean(continueOnError);
  }

  protected boolean getWantVerify(MessageContext msgCtxt) {
    String wantVerify = properties.get("wantVerify");
    if (StringUtils.isBlank(wantVerify)) {
      return true;
    }
    wantVerify = resolvePropertyValue(wantVerify, msgCtxt);
    return Boolean.parseBoolean(wantVerify);
  }

  private PublicKeySource getPublicKeySource(MessageContext msgCtxt) throws IOException {
    // There are various ways to specify the public key in configuration

    // 1. Try "public-key"
    String publicKeyString = (String) this.properties.get("public-key");
    if (publicKeyString != null) {
      if (publicKeyString.equals("")) {
        throw new IllegalStateException("public-key must be non-empty");
      }
      publicKeyString = resolvePropertyValue(publicKeyString, msgCtxt);

      if (publicKeyString == null || publicKeyString.equals("")) {
        throw new IllegalStateException(
            "public-key variable resolves to empty; invalid when algorithm is RS*");
      }
      return PublicKeySource.fromString(publicKeyString);
    }

    // 2. Try "modulus" + "exponent"
    String modulus = (String) this.properties.get("modulus");
    String exponent = (String) this.properties.get("exponent");

    if ((modulus != null) && (exponent != null)) {
      modulus = resolvePropertyValue(modulus, msgCtxt);
      exponent = resolvePropertyValue(exponent, msgCtxt);

      if (modulus == null || modulus.equals("") || exponent == null || exponent.equals("")) {
        throw new IllegalStateException(
            "modulus or exponent resolves to empty; invalid when algorithm is RS*");
      }

      return PublicKeySource.fromModulusAndExponent(modulus, exponent);
    }

    // 3. Try certificate
    String certString = (String) this.properties.get("certificate");
    if (certString != null) {
      if (certString.equals("")) {
        throw new IllegalStateException("certificate must be non-empty");
      }
      certString = resolvePropertyValue(certString, msgCtxt);
      // msgCtxt.setVariable("jwt_certstring", certString);
      if (certString == null || certString.equals("")) {
        throw new IllegalStateException(
            "certificate variable resolves to empty; invalid when algorithm is RS*");
      }

      return PublicKeySource.fromCertificate(certString);
    }

    // 4. last chance, try pemfile
    String pemfile = (String) this.properties.get("pemfile");
    if (pemfile == null || pemfile.equals("")) {
      throw new IllegalStateException(
          "must specify pemfile or public-key or certificate when algorithm is RS*");
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

    return PublicKeySource.fromPemFileString(pemfile, publicKeyString);
  }

  private JWSVerifier getMacVerifier(MessageContext msgCtxt) throws Exception {
    String key = getSecretKey(msgCtxt);
    return macVerifierCache.get(key);
  }

  private JWSVerifier getRsaVerifier(MessageContext msgCtxt) throws Exception {
    PublicKeySource source = getPublicKeySource(msgCtxt);
    return rsaVerifierCache.get(source);
  }

  protected JWSVerifier getVerifier(String alg, MessageContext msgCtxt) throws Exception {
    if (alg.equals("HS256")) {
      return getMacVerifier(msgCtxt);
    } else if (alg.equals("RS256")) {
      return getRsaVerifier(msgCtxt);
    }

    throw new IllegalStateException("algorithm is unsupported: " + alg);
  }
}

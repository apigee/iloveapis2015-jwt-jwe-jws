package com.google.apigee.callout.jwtsigned;

import com.apigee.flow.message.MessageContext;
import com.google.common.cache.CacheBuilder;
import com.google.common.cache.CacheLoader;
import com.google.common.cache.LoadingCache;
import com.nimbusds.jose.JOSEException;
import com.nimbusds.jose.JWSSigner;
import com.nimbusds.jose.crypto.MACSigner;
import com.nimbusds.jose.crypto.RSASSASigner;
import java.io.IOException;
import java.io.InputStream;
import java.io.StringReader;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.util.Map;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;
import org.apache.commons.lang3.StringUtils;
import org.bouncycastle.openssl.PEMDecryptorProvider;
import org.bouncycastle.openssl.PEMEncryptedKeyPair;
import org.bouncycastle.openssl.PEMException;
import org.bouncycastle.openssl.PEMKeyPair;
import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.openssl.jcajce.JcaPEMKeyConverter;
import org.bouncycastle.openssl.jcajce.JcePEMDecryptorProviderBuilder;

public abstract class SignerCallout extends JoseCalloutBase {
  protected LoadingCache<String, JWSSigner> macKeyCache;
  protected LoadingCache<PrivateKeyInfo, JWSSigner> rsaKeyCache;

  protected SignerCallout (String varPrefix, Map properties) {
    super(varPrefix, properties);
    macKeyCache =
      CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(1048000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(
                new CacheLoader<String, JWSSigner>() {
                  public JWSSigner load(String key) throws UnsupportedEncodingException, JOSEException {
                    byte[] keyBytes = key.getBytes(StandardCharsets.UTF_8);
                    // NB: this will throw if the string is not at least 16 chars long
                    return new MACSigner(keyBytes);
                  }
                });

    rsaKeyCache =
        CacheBuilder.newBuilder()
            .concurrencyLevel(4)
            .maximumSize(1048000)
            .expireAfterAccess(10, TimeUnit.MINUTES)
            .build(
                new CacheLoader<PrivateKeyInfo, JWSSigner>() {
                  public JWSSigner load(PrivateKeyInfo info)
                      throws InvalidKeySpecException, GeneralSecurityException, IOException {
                    try {
                      RSAPrivateKey privateKey = (RSAPrivateKey) generatePrivateKey(info);
                      return new RSASSASigner(privateKey);
                    } catch (java.lang.Exception exc1) {
                      info.msgCtxt.setVariable(
                          varName("getRsaKey_stacktrace"), getStackTraceAsString(exc1));
                      throw exc1;
                    }
                  }
                });

    }

  protected JWSSigner getMacSigner(MessageContext msgCtxt) throws Exception {
    String key = getSecretKey(msgCtxt);
    return macKeyCache.get(key);
  }

  protected JWSSigner getRsaSigner(MessageContext msgCtxt) throws IOException, ExecutionException {
    PrivateKeyInfo info =
        new PrivateKeyInfo(msgCtxt, getPrivateKeyBytes(msgCtxt), getPrivateKeyPassword(msgCtxt));
    return rsaKeyCache.get(info);
  }

  protected String getKeyId(MessageContext msgCtxt) throws Exception {
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
    if (StringUtils.isBlank(password)) {
      return null;
    }
    return password;
  }

  private byte[] getPrivateKeyBytes(MessageContext msgCtxt) throws IOException {
    byte[] keyBytes = null;
    String privateKey = (String) this.properties.get("private-key");
    if (privateKey == null) {
      String pemfile = (String) this.properties.get("pemfile");
      if (StringUtils.isBlank(pemfile)) {
        throw new IllegalStateException(
            "must specify pemfile or private-key when algorithm is RS*");
      }
      pemfile = (String) resolvePropertyValue(pemfile, msgCtxt);
      if (StringUtils.isBlank(pemfile)) {
        throw new IllegalStateException(
            "pemfile resolves to nothing; invalid when algorithm is RS*");
      }

      InputStream in = getResourceAsStream(pemfile);

      keyBytes = new byte[in.available()];
      in.read(keyBytes);
      in.close();
    } else {
      // it's a string...
      if (privateKey.equals("")) {
        throw new IllegalStateException("private-key must be non-empty");
      }
      privateKey = (String) resolvePropertyValue(privateKey, msgCtxt);
      if (StringUtils.isBlank(privateKey)) {
        throw new IllegalStateException(
            "private-key variable resolves to empty; invalid when algorithm is RS*");
      }
      privateKey = privateKey.trim();

      // clear any leading whitespace on each line
      privateKey = privateKey.replaceAll("([\\r|\\n] +)", "\n");

      // keyBytes = Base64.decodeBase64(privateKey);
      keyBytes = privateKey.getBytes(StandardCharsets.UTF_8);
    }
    return keyBytes;
  }

  private static PrivateKey generatePrivateKey(PrivateKeyInfo info)
      throws InvalidKeySpecException, GeneralSecurityException, NoSuchAlgorithmException,
          IOException, PEMException {
    JcaPEMKeyConverter converter = new JcaPEMKeyConverter().setProvider("BC");
    PEMParser pr =
        new PEMParser(new StringReader(new String(info.keyBytes, StandardCharsets.UTF_8)));
    Object o = pr.readObject();

    if (o == null || !((o instanceof PEMKeyPair) || (o instanceof PEMEncryptedKeyPair))) {
      throw new IllegalStateException("Didn't find OpenSSL key");
    }
    KeyPair kp;
    if (o instanceof PEMEncryptedKeyPair) {
      JcePEMDecryptorProviderBuilder bcDecProvider =
          new JcePEMDecryptorProviderBuilder().setProvider("BC");
      char[] charArray = info.password.toCharArray();
      PEMDecryptorProvider decProv = bcDecProvider.build(charArray);
      kp = converter.getKeyPair(((PEMEncryptedKeyPair) o).decryptKeyPair(decProv));
    } else {
      kp = converter.getKeyPair((PEMKeyPair) o);
    }

    PrivateKey privKey = kp.getPrivate();
    return privKey;
  }


}

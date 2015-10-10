package com.apigee.callout.jwtsigned;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.spec.RSAPublicKeySpec;
import java.security.NoSuchAlgorithmException;
import java.security.spec.InvalidKeySpecException;
import java.security.cert.CertificateException;
import java.security.spec.X509EncodedKeySpec;
import java.security.cert.X509Certificate;
import java.security.cert.CertificateFactory;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

import org.apache.commons.codec.binary.Base64;
import org.apache.commons.codec.binary.Hex;

public final class KeyUtils {

    private KeyUtils() {}

    public static PublicKey publicKeyStringToPublicKey(String s)
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
        // else, try parsing it as a "bare" base64 encoded PEM string

        s = s.replaceAll("[\\r|\\n| ]","");
        byte[] keyBytes = Base64.decodeBase64(s);
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        PublicKey key = keyFactory.generatePublic(spec);
        return key;
    }

    public static PublicKey certStringToPublicKey(String s)
        throws InvalidKeySpecException, CertificateException, UnsupportedEncodingException {
        s = s.trim();

        if (s.startsWith("-----BEGIN CERTIFICATE-----") &&
            s.endsWith("-----END CERTIFICATE-----")) {
            // This is an X509 cert;
            // Strip the prefix and suffix.
            s = s.substring(27, s.length() - 25);
        }
        // else, assume it is a bare base-64 encoded string

        s = s.replaceAll("[\\r|\\n| ]","");
        // base64-decode it, and  produce a public key from the result
        byte[] certBytes = Base64.decodeBase64(s);
        ByteArrayInputStream is = new ByteArrayInputStream(certBytes);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        PublicKey key = cer.getPublicKey();
        return key;
    }

    public static PublicKey pemFileStringToPublicKey(String s)
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

    private static String unUrlSafe(String s) {
        s = s.replaceAll("-","+")
            .replaceAll("_","/");
        return s;
    }

    public static PublicKey pubKeyFromModulusAndExponent(String modulus_b64, String exponent_b64)
        throws NoSuchAlgorithmException,
               InvalidKeySpecException    {

        modulus_b64 = KeyUtils.unUrlSafe(modulus_b64)
            .replaceAll("[\\r|\\n| ]","");
        exponent_b64 = KeyUtils.unUrlSafe(exponent_b64)
            .replaceAll("[\\r|\\n| ]","");

        byte[] decodedModulus = Base64.decodeBase64(modulus_b64);
        byte[] decodedExponent = Base64.decodeBase64(exponent_b64);

        String modulus_hex =  Hex.encodeHexString( decodedModulus );
        String exponent_hex =  Hex.encodeHexString( decodedExponent );

        BigInteger modulus = new BigInteger(modulus_hex, 16);
        BigInteger publicExponent = new BigInteger(exponent_hex, 16);

        PublicKey publicKey = KeyFactory
            .getInstance("RSA")
            .generatePublic(new RSAPublicKeySpec(modulus, publicExponent));

        return publicKey;
    }

    public static String publicKeyPem(PublicKey rsaKey) {
        byte[] data = rsaKey.getEncoded();
        String base64encoded = Base64.encodeBase64String(data);
        Pattern p = Pattern.compile(".{1,64}");
        Matcher m = p.matcher(base64encoded);
        String pem = "-----BEGIN PUBLIC KEY-----\n" +
            m.replaceAll("$0\n") +
            "-----END PUBLIC KEY-----\n";
        return pem;
    }

}

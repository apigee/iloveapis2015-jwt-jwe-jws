package com.google.apigee.callout.jwtsigned;

import java.io.ByteArrayInputStream;
import java.io.UnsupportedEncodingException;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.KeyFactory;
import java.security.Provider;
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

public class PublicKeySource {
    enum SourceType { SourceString, SourceModExp, SourceCert, SourcePemFile };

    public SourceType sourceType;
    public String publicKeyString;
    public String modulus;
    public String exponent;
    public String certificateString;
    public String pemFileName;

    private PublicKeySource() {}

    public String toString() {
        if (sourceType == SourceType.SourcePemFile) {
            return String.format("PublicKeySource: %s (%s)",
                                 sourceType.toString(), pemFileName);
        }
        else
            return String.format("PublicKeySource: %s", sourceType.toString());
    }

    public static PublicKeySource fromString(String s) {
        PublicKeySource source = new PublicKeySource();
        source.sourceType = SourceType.SourceString;
        source.publicKeyString = s;
        return source;
    }

    public static PublicKeySource fromCertificate(String s) {
        PublicKeySource source = new PublicKeySource();
        source.sourceType = SourceType.SourceCert;
        source.certificateString = s;
        return source;
    }

    public static PublicKeySource fromPemFileString(String filename, String contents) {
        PublicKeySource source = new PublicKeySource();
        source.sourceType = SourceType.SourcePemFile;
        source.publicKeyString = contents;
        source.pemFileName = filename;
        return source;
    }

    public static PublicKeySource fromModulusAndExponent(String mod, String exp) {
        PublicKeySource source = new PublicKeySource();
        source.sourceType = SourceType.SourceModExp;
        source.modulus = mod;
        source.exponent = exp;
        return source;
    }

    public PublicKey getPublicKey()
        throws NoSuchAlgorithmException, InvalidKeySpecException, InvalidKeySpecException,
               CertificateException, UnsupportedEncodingException {
        PublicKey key = null;
        switch (sourceType) {
            case SourceModExp:
                key = PublicKeySource.pubKeyFromModulusAndExponent(modulus, exponent);
                break;
            case SourcePemFile:
                // allow pemfile resolution as Certificate or Public Key
                key = PublicKeySource.pemFileStringToPublicKey(publicKeyString);
                break;
            case SourceCert:
                key = PublicKeySource.certStringToPublicKey(certificateString);
                break;
            case SourceString:
                key = PublicKeySource.publicKeyStringToPublicKey(publicKeyString);
                break;
        }
        return key; // maybe null
    }

    private static PublicKey pemFileStringToPublicKey(String s)
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

    private static PublicKey certStringToPublicKey(String s)
        throws InvalidKeySpecException, CertificateException, UnsupportedEncodingException {
        if (s==null) return null;
        s = s.trim();

        if (s.startsWith("-----BEGIN CERTIFICATE-----") &&
            s.endsWith("-----END CERTIFICATE-----")) {
            // This is an X509 cert;
            // Strip the prefix and suffix.
            s = s.substring(27, s.length() - 25);
        }
        // else, assume it is a bare base-64 encoded string

        s = s.replaceAll("\\\\n","");
        s = s.replaceAll("[\\r|\\n| ]","");
        // base64-decode it, and  produce a public key from the result
        byte[] certBytes = Base64.decodeBase64(s);
        ByteArrayInputStream is = new ByteArrayInputStream(certBytes);
        CertificateFactory fact = CertificateFactory.getInstance("X.509");
        X509Certificate cer = (X509Certificate) fact.generateCertificate(is);
        PublicKey key = cer.getPublicKey();
        return key;
    }

    private static PublicKey publicKeyStringToPublicKey(String s)
        throws IllegalArgumentException, NoSuchAlgorithmException {
        if (s==null) return null;
        try {
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

            s = s.replaceAll("\\\\n","");
            s = s.replaceAll("[\\r|\\n| ]","");

            byte[] keyBytes = Base64.decodeBase64(s);
            X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PublicKey key = keyFactory.generatePublic(spec);
            return key;
        }
        catch (java.security.spec.InvalidKeySpecException ikse) {
            IllegalArgumentException exc1 =
                new IllegalArgumentException("an invalid public key was provided", ikse);
            throw exc1;
        }
    }

    private static String unUrlSafe(String s) {
        s = s.replaceAll("-","+")
            .replaceAll("_","/");
        return s;
    }

    private static PublicKey pubKeyFromModulusAndExponent(String modulus_b64, String exponent_b64)
        throws NoSuchAlgorithmException,
               InvalidKeySpecException {

        modulus_b64 = unUrlSafe(modulus_b64)
            .replaceAll("\\\\n","")
            .replaceAll("[\\r|\\n| ]","");

        exponent_b64 = unUrlSafe(exponent_b64)
            .replaceAll("\\\\n","")
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

    private static String publicKeyPem(PublicKey rsaKey) {
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


// private PublicKey getPublicKey(MessageContext msgCtxt)
//     throws IOException,
//            NoSuchAlgorithmException,
//            InvalidKeySpecException,
//            CertificateException
// {
//     String publicKeyString = (String) this.properties.get("public-key");
//
//     // There are various ways to specify the public key.
//
//     // Try "public-key"
//     if (publicKeyString !=null) {
//         if (publicKeyString.equals("")) {
//             throw new IllegalStateException("public-key must be non-empty");
//         }
//         publicKeyString = resolvePropertyValue(publicKeyString, msgCtxt);
//
//         if (publicKeyString==null || publicKeyString.equals("")) {
//             throw new IllegalStateException("public-key variable resolves to empty; invalid when algorithm is RS*");
//         }
//         PublicKey key = KeyUtils.publicKeyStringToPublicKey(publicKeyString);
//         if (key==null) {
//             throw new InvalidKeySpecException("must be PKCS#1 or PKCS#8");
//         }
//         return key;
//     }
//
//     // Try "modulus" + "exponent"
//     String modulus = (String) this.properties.get("modulus");
//     String exponent = (String) this.properties.get("exponent");
//
//     if ((modulus != null) && (exponent != null)) {
//         modulus = resolvePropertyValue(modulus, msgCtxt);
//         exponent = resolvePropertyValue(exponent, msgCtxt);
//
//         if (modulus==null || modulus.equals("") ||
//             exponent==null || exponent.equals("")) {
//             throw new IllegalStateException("modulus or exponent resolves to empty; invalid when algorithm is RS*");
//         }
//
//         PublicKey key = KeyUtils.pubKeyFromModulusAndExponent(modulus, exponent);
//         return key;
//     }
//
//     // Try certificate
//     String certString = (String) this.properties.get("certificate");
//     if (certString !=null) {
//         if (certString.equals("")) {
//             throw new IllegalStateException("certificate must be non-empty");
//         }
//         certString = resolvePropertyValue(certString, msgCtxt);
//         //msgCtxt.setVariable("jwt_certstring", certString);
//         if (certString==null || certString.equals("")) {
//             throw new IllegalStateException("certificate variable resolves to empty; invalid when algorithm is RS*");
//         }
//         PublicKey key = KeyUtils.certStringToPublicKey(certString);
//         if (key==null) {
//             throw new InvalidKeySpecException("invalid certificate format");
//         }
//         return key;
//     }
//
//     // last chance
//     String pemfile = (String) this.properties.get("pemfile");
//     if (pemfile == null || pemfile.equals("")) {
//         throw new IllegalStateException("must specify pemfile or public-key or certificate when algorithm is RS*");
//     }
//     pemfile = resolvePropertyValue(pemfile, msgCtxt);
//     //msgCtxt.setVariable("jwt_pemfile", pemfile);
//     if (pemfile == null || pemfile.equals("")) {
//         throw new IllegalStateException("pemfile resolves to nothing; invalid when algorithm is RS*");
//     }
//
//     InputStream in = getResourceAsStream(pemfile);
//     byte[] keyBytes = new byte[in.available()];
//     in.read(keyBytes);
//     in.close();
//     publicKeyString = new String(keyBytes, "UTF-8");
//
//     // allow pemfile resolution as Certificate or Public Key
//     PublicKey key = KeyUtils.pemFileStringToPublicKey(publicKeyString);
//     if (key==null) {
//         throw new InvalidKeySpecException("invalid pemfile format");
//     }
//     return key;
// }

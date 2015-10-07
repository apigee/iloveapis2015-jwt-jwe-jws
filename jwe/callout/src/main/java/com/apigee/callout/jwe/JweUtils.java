package com.apigee.callout.jwe;

import org.jose4j.jwe.ContentEncryptionAlgorithmIdentifiers;

public final class JweUtils {

    // private JewUtils() {
    //     throw new UnsupportedOperationException();
    // }

    public static void validateJweAlgorithm(String alg) throws Exception {
        if (!alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_128_CBC_HMAC_SHA_256) &&
            !alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_192_CBC_HMAC_SHA_384) &&
            !alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_256_CBC_HMAC_SHA_512) &&

            !alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_128_GCM) &&
            !alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_192_GCM) &&
            !alg.equals(ContentEncryptionAlgorithmIdentifiers.AES_256_GCM)) {

            throw new IllegalStateException("unsupported algorithm: '" + alg + "'");
        }
    }
}

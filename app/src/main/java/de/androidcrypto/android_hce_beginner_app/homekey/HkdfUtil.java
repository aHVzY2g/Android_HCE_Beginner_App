package de.androidcrypto.android_hce_beginner_app.homekey;

import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

/**
 * HKDF-SHA256 (RFC 5869) used by the Apple Home Key FAST authentication cryptogram.
 */
public class HkdfUtil {

    private static final String HMAC = "HmacSHA256";
    private static final int HASH_LEN = 32;

    /** Extract step. Null salt is replaced by 32 zero bytes (RFC 5869 §2.2). */
    public static byte[] extract(byte[] salt, byte[] ikm) throws Exception {
        if (salt == null || salt.length == 0) salt = new byte[HASH_LEN];
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(salt, HMAC));
        return mac.doFinal(ikm);
    }

    /** Expand step. */
    public static byte[] expand(byte[] prk, byte[] info, int outputLen) throws Exception {
        Mac mac = Mac.getInstance(HMAC);
        mac.init(new SecretKeySpec(prk, HMAC));
        byte[] result = new byte[outputLen];
        byte[] t = new byte[0];
        int pos = 0;
        for (int i = 1; pos < outputLen; i++) {
            mac.reset();
            mac.update(t);
            if (info != null) mac.update(info);
            mac.update((byte) i);
            t = mac.doFinal();
            int copyLen = Math.min(t.length, outputLen - pos);
            System.arraycopy(t, 0, result, pos, copyLen);
            pos += copyLen;
        }
        return result;
    }

    /** Combined extract-then-expand with null salt. */
    public static byte[] derive(byte[] ikm, byte[] info, int outputLen) throws Exception {
        return expand(extract(null, ikm), info, outputLen);
    }
}

package de.androidcrypto.android_hce_beginner_app.homekey;

import android.content.Context;
import android.content.SharedPreferences;
import android.util.Base64;
import android.util.Log;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;

import javax.crypto.KeyAgreement;

/**
 * Cryptographic operations for Apple Home Key emulation.
 *
 * Covers:
 *  - secp256r1 device long-term key pair (persisted in SharedPreferences)
 *  - Ephemeral key pair per transaction
 *  - HKDF-based FAST authentication cryptogram
 *  - ECDSA signing for STANDARD AUTH1
 *  - ECDH-based persistent key derivation (enables FAST on repeat taps)
 */
public class HomeKeyCrypto {

    private static final String TAG            = "HomeKeyCrypto";
    private static final String PREFS_NAME     = "HomeKeyCrypto";
    private static final String KEY_PRIV       = "device_priv";
    private static final String KEY_PUB        = "device_pub";
    private static final String KEY_ID         = "device_id";
    private static final String PREFIX_PERSIST = "persistent_";
    private static final String PREFIX_READER  = "reader_pub_";

    private final SharedPreferences prefs;

    private KeyPair deviceKeyPair;     // long-term
    private byte[]  deviceIdentifier; // 6 bytes, returned in STANDARD response
    private KeyPair ephemeralKeyPair;  // refreshed each transaction

    public HomeKeyCrypto(Context context) {
        prefs = context.getSharedPreferences(PREFS_NAME, Context.MODE_PRIVATE);
        loadOrGenerateDeviceKey();
    }

    // -----------------------------------------------------------------------
    // Device key
    // -----------------------------------------------------------------------

    private void loadOrGenerateDeviceKey() {
        String privB64 = prefs.getString(KEY_PRIV, null);
        String pubB64  = prefs.getString(KEY_PUB,  null);
        String idB64   = prefs.getString(KEY_ID,   null);
        if (privB64 != null && pubB64 != null && idB64 != null) {
            try {
                KeyFactory kf = KeyFactory.getInstance("EC");
                PrivateKey priv = kf.generatePrivate(
                        new PKCS8EncodedKeySpec(Base64.decode(privB64, Base64.DEFAULT)));
                PublicKey pub = kf.generatePublic(
                        new X509EncodedKeySpec(Base64.decode(pubB64, Base64.DEFAULT)));
                deviceKeyPair    = new KeyPair(pub, priv);
                deviceIdentifier = Base64.decode(idB64, Base64.DEFAULT);
                Log.i(TAG, "Loaded device key");
                return;
            } catch (Exception e) {
                Log.w(TAG, "Key load failed, regenerating: " + e.getMessage());
            }
        }
        generateDeviceKey();
    }

    public void generateDeviceKey() {
        try {
            KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
            kpg.initialize(new ECGenParameterSpec("secp256r1"));
            deviceKeyPair    = kpg.generateKeyPair();
            deviceIdentifier = new byte[6];
            new SecureRandom().nextBytes(deviceIdentifier);
            prefs.edit()
                .putString(KEY_PRIV, Base64.encodeToString(
                        deviceKeyPair.getPrivate().getEncoded(), Base64.DEFAULT))
                .putString(KEY_PUB,  Base64.encodeToString(
                        deviceKeyPair.getPublic().getEncoded(), Base64.DEFAULT))
                .putString(KEY_ID,   Base64.encodeToString(deviceIdentifier, Base64.DEFAULT))
                .apply();
            Log.i(TAG, "New device key generated");
        } catch (Exception e) {
            Log.e(TAG, "Key generation failed", e);
        }
    }

    // -----------------------------------------------------------------------
    // Ephemeral key (fresh per transaction)
    // -----------------------------------------------------------------------

    public void generateEphemeralKeyPair() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("EC");
        kpg.initialize(new ECGenParameterSpec("secp256r1"));
        ephemeralKeyPair = kpg.generateKeyPair();
    }

    /** Returns device ephemeral public key as 65-byte uncompressed point. */
    public byte[] getEphemeralPublicKeyBytes() {
        return ephemeralKeyPair == null ? null
                : encodeUncompressed((ECPublicKey) ephemeralKeyPair.getPublic());
    }

    /** Returns device long-term public key as 65-byte uncompressed point. */
    public byte[] getDevicePublicKeyBytes() {
        return deviceKeyPair == null ? null
                : encodeUncompressed((ECPublicKey) deviceKeyPair.getPublic());
    }

    public byte[] getDeviceIdentifier() { return deviceIdentifier; }

    // -----------------------------------------------------------------------
    // STANDARD AUTH1: ECDSA signing
    // -----------------------------------------------------------------------

    /**
     * Signs authHashInput with the device long-term key.
     * Returns 64-byte point-form signature (r || s).
     */
    public byte[] signAuthHash(byte[] input) throws Exception {
        Signature sig = Signature.getInstance("SHA256withECDSA");
        sig.initSign(deviceKeyPair.getPrivate());
        sig.update(input);
        return derToPointForm(sig.sign());
    }

    // -----------------------------------------------------------------------
    // FAST AUTH0: cryptogram
    // -----------------------------------------------------------------------

    /**
     * Computes the 16-byte FAST authentication cryptogram (kcmac) per spec:
     *
     *   sharedInfo = readerPubX | "VolatileFast" | readerId | 0x5E
     *              | versionsTlv | selectedVersionTlv
     *              | readerEphemX | txNonce | txFlags | deviceEphemX
     *
     *   hkdf = HKDF-SHA256(ikm=kPersistent, salt=null, info=sharedInfo, len=64)
     *   cryptogram = hkdf[0:16]
     */
    public static byte[] computeFastCryptogram(
            byte[] kPersistent,
            byte[] readerLongTermPub,  // 65-byte uncompressed, or null -> zeros
            byte[] readerId,
            byte[] readerEphemPub,
            byte[] txNonce,
            byte[] versionsTlv,
            byte[] selectedVersion,
            byte[] txFlags,
            byte[] deviceEphemPub) throws Exception {

        byte[] readerPubX = (readerLongTermPub != null && readerLongTermPub.length == 65)
                ? Arrays.copyOfRange(readerLongTermPub, 1, 33)
                : new byte[32];
        byte[] readerEphemX = Arrays.copyOfRange(readerEphemPub,  1, 33);
        byte[] deviceEphemX = Arrays.copyOfRange(deviceEphemPub,  1, 33);
        byte[] volatileFast = "VolatileFast".getBytes("UTF-8");
        byte[] selVerTlv    = new byte[]{0x5C, 0x02, selectedVersion[0], selectedVersion[1]};

        byte[] sharedInfo = TlvUtils.concat(
                readerPubX, volatileFast, readerId,
                new byte[]{0x5E},
                versionsTlv, selVerTlv,
                readerEphemX, txNonce, txFlags, deviceEphemX);

        byte[] hkdf = HkdfUtil.derive(kPersistent, sharedInfo, 64);
        return Arrays.copyOf(hkdf, 16);
    }

    // -----------------------------------------------------------------------
    // Persistent key (ECDH-derived, stored per reader)
    // -----------------------------------------------------------------------

    /**
     * Derives a 16-byte persistent key via ECDH(deviceEphemPrivate, readerEphemPublic)
     * and stores it keyed by readerId for use in future FAST transactions.
     */
    public byte[] deriveAndStorePersistentKey(byte[] readerEphemPubBytes,
                                               byte[] txNonce,
                                               byte[] readerId) throws Exception {
        PublicKey readerEphemPub = decodeUncompressed(readerEphemPubBytes);
        KeyAgreement ka = KeyAgreement.getInstance("ECDH");
        ka.init(ephemeralKeyPair.getPrivate());
        ka.doPhase(readerEphemPub, true);
        byte[] sharedSecret = ka.generateSecret();

        byte[] info = "HomeKey-Persistent-Key".getBytes("UTF-8");
        byte[] prk  = HkdfUtil.extract(txNonce, sharedSecret);
        byte[] key  = HkdfUtil.expand(prk, info, 16);
        storePersistentKey(readerId, key);
        return key;
    }

    // -----------------------------------------------------------------------
    // Key storage helpers
    // -----------------------------------------------------------------------

    public byte[] getPersistentKey(byte[] readerId) {
        String b64 = prefs.getString(PREFIX_PERSIST + toHex(readerId), null);
        return b64 != null ? Base64.decode(b64, Base64.DEFAULT) : null;
    }

    public void storePersistentKey(byte[] readerId, byte[] key) {
        prefs.edit().putString(PREFIX_PERSIST + toHex(readerId),
                Base64.encodeToString(key, Base64.DEFAULT)).apply();
    }

    public byte[] getReaderPublicKey(byte[] readerId) {
        String b64 = prefs.getString(PREFIX_READER + toHex(readerId), null);
        return b64 != null ? Base64.decode(b64, Base64.DEFAULT) : null;
    }

    public void storeReaderPublicKey(byte[] readerId, byte[] pubKey) {
        prefs.edit().putString(PREFIX_READER + toHex(readerId),
                Base64.encodeToString(pubKey, Base64.DEFAULT)).apply();
    }

    // -----------------------------------------------------------------------
    // EC encoding / decoding
    // -----------------------------------------------------------------------

    public static byte[] encodeUncompressed(ECPublicKey key) {
        ECPoint pt = key.getW();
        byte[] x   = to32Bytes(pt.getAffineX());
        byte[] y   = to32Bytes(pt.getAffineY());
        byte[] out = new byte[65];
        out[0] = 0x04;
        System.arraycopy(x, 0, out, 1,  32);
        System.arraycopy(y, 0, out, 33, 32);
        return out;
    }

    public static PublicKey decodeUncompressed(byte[] bytes) throws Exception {
        if (bytes == null || bytes.length != 65 || bytes[0] != 0x04)
            throw new IllegalArgumentException("Expected 65-byte uncompressed EC point");
        BigInteger x = new BigInteger(1, Arrays.copyOfRange(bytes, 1,  33));
        BigInteger y = new BigInteger(1, Arrays.copyOfRange(bytes, 33, 65));
        AlgorithmParameters ap = AlgorithmParameters.getInstance("EC");
        ap.init(new ECGenParameterSpec("secp256r1"));
        ECParameterSpec spec = ap.getParameterSpec(ECParameterSpec.class);
        return KeyFactory.getInstance("EC")
                .generatePublic(new ECPublicKeySpec(new ECPoint(x, y), spec));
    }

    // -----------------------------------------------------------------------
    // DER -> 64-byte point-form signature
    // -----------------------------------------------------------------------

    public static byte[] derToPointForm(byte[] der) {
        int pos = 0;
        if ((der[pos++] & 0xFF) != 0x30) throw new IllegalArgumentException("Bad DER tag");
        int lb = der[pos++] & 0xFF;
        if (lb == 0x81) pos++; else if (lb == 0x82) pos += 2;

        if ((der[pos++] & 0xFF) != 0x02) throw new IllegalArgumentException("Bad r tag");
        int rLen = der[pos++] & 0xFF;
        byte[] r = Arrays.copyOfRange(der, pos, pos + rLen); pos += rLen;

        if ((der[pos++] & 0xFF) != 0x02) throw new IllegalArgumentException("Bad s tag");
        int sLen = der[pos++] & 0xFF;
        byte[] s = Arrays.copyOfRange(der, pos, pos + sLen);

        byte[] result = new byte[64];
        copyNorm(r, result, 0);
        copyNorm(s, result, 32);
        return result;
    }

    /** Strip leading zero and right-align into a 32-byte slot. */
    private static void copyNorm(byte[] src, byte[] dst, int off) {
        int start = 0;
        while (start < src.length - 1 && src[start] == 0) start++;
        int len = src.length - start;
        int pad = 32 - len;
        if (pad < 0) { start -= pad; len = 32; pad = 0; }
        System.arraycopy(src, start, dst, off + pad, len);
    }

    // -----------------------------------------------------------------------
    // Utilities
    // -----------------------------------------------------------------------

    private static byte[] to32Bytes(BigInteger bi) {
        byte[] raw = bi.toByteArray();
        if (raw.length == 32) return raw;
        byte[] out = new byte[32];
        if (raw.length < 32)
            System.arraycopy(raw, 0, out, 32 - raw.length, raw.length);
        else
            System.arraycopy(raw, raw.length - 32, out, 0, 32);
        return out;
    }

    public static String toHex(byte[] b) {
        if (b == null) return "";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02x", x));
        return sb.toString();
    }
}

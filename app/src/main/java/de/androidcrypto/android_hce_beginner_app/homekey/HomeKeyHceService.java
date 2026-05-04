package de.androidcrypto.android_hce_beginner_app.homekey;

import android.content.Intent;
import android.nfc.cardemulation.HostApduService;
import android.os.Bundle;
import android.util.Log;

import java.util.Arrays;

/**
 * HCE service emulating an Apple Home Key endpoint (device side).
 *
 * Registers two AIDs per the Apple Home Key specification:
 *   A0000008580101  Primary     – authentication (FAST / STANDARD)
 *   A0000008580102  Configuration – attestation exchange (ENVELOPE)
 *
 * Protocol command sequence:
 *   1. SELECT PRIMARY    -> supported versions TLV
 *   2. FAST  (AUTH0)     -> device ephemeral key [+ cryptogram when P1=01]
 *   3. STANDARD (AUTH1)  -> ECDSA device signature + device identifier
 *   4. EXCHANGE          -> acknowledge; flag config-applet needed
 *   5. CONTROL FLOW      -> acknowledge; forward UX status to UI
 *   6. SELECT CONFIG     -> acknowledge (only after EXCHANGE)
 *   7. ENVELOPE          -> stub ISO18013 attestation response
 *   8. GET RESPONSE      -> return any buffered data
 */
public class HomeKeyHceService extends HostApduService {

    private static final String TAG = "HomeKeyHCE";

    // ---- Application Identifiers ----
    private static final byte[] AID_PRIMARY = hexToBytes("A0000008580101");
    private static final byte[] AID_CONFIG  = hexToBytes("A0000008580102");

    // Supported versions TLV returned on SELECT: v2.0 and v1.0
    // Format: 5C 04 <major1><minor1><major2><minor2>
    private static final byte[] VERSIONS_TLV = hexToBytes("5c0402000100");
    private static final byte[] VERSION_2_0  = {0x02, 0x00};

    // Transaction flags included in HKDF shared-info for FAST cryptogram
    private static final byte[] TX_FLAGS = {0x01, 0x01};

    // ---- Status words ----
    private static final byte[] SW_OK            = {(byte)0x90, 0x00};
    private static final byte[] SW_ERR_CONDITION = {(byte)0x69, (byte)0x85};
    private static final byte[] SW_ERR_NOT_FOUND = {(byte)0x6A, (byte)0x82};
    private static final byte[] SW_ERR_UNKNOWN   = {0x6F, 0x00};

    // ---- APDU instruction bytes ----
    private static final byte INS_SELECT    = (byte)0xA4;
    private static final byte INS_FAST      = (byte)0x80;
    private static final byte INS_STANDARD  = (byte)0x81;
    private static final byte INS_EXCHANGE  = (byte)0xC9;
    private static final byte INS_CTRL_FLOW = (byte)0x3C;
    private static final byte INS_ENVELOPE  = (byte)0xC3;
    private static final byte INS_GET_RESP  = (byte)0xC0;

    // Context constants used in STANDARD auth-hash input
    // Endpoint context: used when the device signs its own response
    private static final byte[] CTX_ENDPOINT = hexToBytes("4e887b4c");

    private HomeKeySession session;
    private HomeKeyCrypto  crypto;

    @Override
    public void onCreate() {
        super.onCreate();
        crypto  = new HomeKeyCrypto(this);
        session = new HomeKeySession();
        Log.i(TAG, "HomeKeyHceService created");
    }

    @Override
    public void onDeactivated(int reason) {
        Log.i(TAG, "NFC deactivated, reason=" + reason);
        session.reset();
        broadcast("NFC disconnected");
    }

    @Override
    public byte[] processCommandApdu(byte[] apdu, Bundle extras) {
        if (apdu == null || apdu.length < 4) return SW_ERR_UNKNOWN;
        logHex("RX", apdu);

        byte cla  = apdu[0];
        byte ins  = apdu[1];
        byte p1   = apdu[2];
        byte p2   = apdu[3];
        byte[] data = extractData(apdu);

        byte[] resp;

        if      (cla == 0x00      && ins == INS_SELECT    && p1 == 0x04) resp = handleSelect(data);
        else if (cla == (byte)0x80 && ins == INS_FAST)                   resp = handleFast(p1, data);
        else if (cla == (byte)0x80 && ins == INS_STANDARD)               resp = handleStandard(data);
        else if (cla == (byte)0x84 && ins == INS_EXCHANGE)               resp = handleExchange();
        else if (cla == (byte)0x80 && ins == INS_CTRL_FLOW)              resp = handleControlFlow(p1);
        else if (cla == 0x00      && ins == INS_ENVELOPE)                resp = handleEnvelope(p2);
        else if (cla == 0x00      && ins == INS_GET_RESP)                resp = SW_OK;
        else { Log.w(TAG, "Unknown cmd: " + toHex(apdu)); resp = SW_ERR_UNKNOWN; }

        logHex("TX", resp);
        return resp;
    }

    // -------------------------------------------------------------------------

    private byte[] handleSelect(byte[] aid) {
        if (aid == null || aid.length == 0) return SW_ERR_UNKNOWN;

        if (Arrays.equals(aid, AID_PRIMARY)) {
            session.reset();
            session.setState(HomeKeySession.STATE_PRIMARY_SELECTED);
            broadcast("Primary AID selected");
            // Response: supported versions TLV + 9000
            return TlvUtils.concat(VERSIONS_TLV, SW_OK);
        }

        if (Arrays.equals(aid, AID_CONFIG)) {
            if (!session.canSelectConfig()) {
                Log.w(TAG, "Config AID rejected - EXCHANGE not done");
                return SW_ERR_CONDITION;
            }
            session.setState(HomeKeySession.STATE_CONFIG_SELECTED);
            broadcast("Config AID selected");
            return SW_OK;
        }

        Log.w(TAG, "Unknown AID: " + toHex(aid));
        return SW_ERR_NOT_FOUND;
    }

    private byte[] handleFast(byte p1, byte[] data) {
        if (session.getState() != HomeKeySession.STATE_PRIMARY_SELECTED
                && session.getState() != HomeKeySession.STATE_FAST_DONE) {
            return SW_ERR_CONDITION;
        }
        try {
            TlvUtils.TlvMap tlv = TlvUtils.parseTlv(data);
            byte[] selectedVer  = tlv.get(0x5C); // 2 bytes
            byte[] readerEphem  = tlv.get(0x87); // 65 bytes uncompressed
            byte[] txNonce      = tlv.get(0x4C); // 16 bytes
            byte[] readerId     = tlv.get(0x4D); // 16 bytes

            if (readerEphem == null || txNonce == null || readerId == null) {
                Log.e(TAG, "FAST: missing required TLV fields");
                return SW_ERR_UNKNOWN;
            }
            if (selectedVer == null || selectedVer.length < 2) selectedVer = VERSION_2_0;

            session.setReaderEphemPubKey(readerEphem);
            session.setTransactionNonce(txNonce);
            session.setReaderId(readerId);
            session.setSelectedVersion(selectedVer);

            crypto.generateEphemeralKeyPair();
            byte[] deviceEphem = crypto.getEphemeralPublicKeyBytes();
            session.setDeviceEphemPubKey(deviceEphem);
            session.setState(HomeKeySession.STATE_FAST_DONE);

            byte[] tag86 = TlvUtils.encodeTlv(0x86, deviceEphem);

            // P1=01: include FAST cryptogram if we have a stored persistent key
            if (p1 == 0x01) {
                byte[] kPersist = crypto.getPersistentKey(readerId);
                if (kPersist != null) {
                    byte[] readerLongPub = crypto.getReaderPublicKey(readerId);
                    byte[] cryptogram = HomeKeyCrypto.computeFastCryptogram(
                            kPersist, readerLongPub, readerId,
                            readerEphem, txNonce,
                            VERSIONS_TLV, selectedVer, TX_FLAGS, deviceEphem);
                    broadcast("FAST: cryptogram sent (known reader)");
                    return TlvUtils.concat(tag86, TlvUtils.encodeTlv(0x9D, cryptogram), SW_OK);
                }
            }

            broadcast("FAST: ephemeral key sent");
            return TlvUtils.concat(tag86, SW_OK);

        } catch (Exception e) {
            Log.e(TAG, "FAST error", e);
            return SW_ERR_UNKNOWN;
        }
    }

    private byte[] handleStandard(byte[] data) {
        if (session.getState() < HomeKeySession.STATE_FAST_DONE) return SW_ERR_CONDITION;
        try {
            // tag 9E = reader signature (64-byte point form) - received but verification
            // requires reader's long-term public key provisioned via HomeKit.
            // Store it via crypto.storeReaderPublicKey() before tapping to enable verification.

            // Build auth hash input for DEVICE signing with endpoint context constant
            byte[] devEphemX    = Arrays.copyOfRange(session.getDeviceEphemPubKey(),  1, 33);
            byte[] readerEphemX = Arrays.copyOfRange(session.getReaderEphemPubKey(),  1, 33);
            byte[] authInput = buildAuthHashInput(
                    session.getReaderId(), devEphemX, readerEphemX,
                    session.getTransactionNonce(), CTX_ENDPOINT);

            byte[] deviceSig = crypto.signAuthHash(authInput);

            // Derive + persist session key for future FAST authentication
            crypto.deriveAndStorePersistentKey(
                    session.getReaderEphemPubKey(),
                    session.getTransactionNonce(),
                    session.getReaderId());

            session.setState(HomeKeySession.STATE_STANDARD_DONE);
            broadcast("STANDARD: signed + persistent key stored");

            return TlvUtils.concat(
                    TlvUtils.encodeTlv(0x9E, deviceSig),
                    TlvUtils.encodeTlv(0x4E, crypto.getDeviceIdentifier()),
                    SW_OK);

        } catch (Exception e) {
            Log.e(TAG, "STANDARD error", e);
            return SW_ERR_UNKNOWN;
        }
    }

    private byte[] handleExchange() {
        session.markExchangeDone();
        broadcast("EXCHANGE: attestation exchange requested");
        return SW_OK;
    }

    private byte[] handleControlFlow(byte p1) {
        String msg;
        if      (p1 == 0x01) msg = "SUCCESS: reader confirmed access";
        else if (p1 == 0x40) msg = "CONTROL FLOW: switching to config applet";
        else                  msg = "CONTROL FLOW: failed";
        broadcast(msg);
        return SW_OK;
    }

    private byte[] handleEnvelope(byte p2) {
        // p2=01: ISO18013 NDEF NFC-handover (first pair)
        // p2=00: ISO18013 CBOR data (subsequent pairs)
        // Full attestation exchange is reader-specific and beyond basic emulation scope.
        broadcast("ENVELOPE p2=" + String.format("%02X", p2) + " (stub)");
        return SW_OK;
    }

    // -------------------------------------------------------------------------
    // Helpers
    // -------------------------------------------------------------------------

    /**
     * Authentication hash input (105 bytes):
     *   4D || readerId(16) | 86 || devEphemX(32) | 87 || readerEphemX(32)
     *   | 4C || nonce(16) | 9C || contextConst(4)
     */
    private static byte[] buildAuthHashInput(byte[] readerId, byte[] devEphemX,
            byte[] readerEphemX, byte[] nonce, byte[] ctx) {
        return TlvUtils.concat(
                new byte[]{0x4D}, readerId,
                new byte[]{(byte)0x86}, devEphemX,
                new byte[]{(byte)0x87}, readerEphemX,
                new byte[]{0x4C}, nonce,
                new byte[]{(byte)0x9C}, ctx);
    }

    private static byte[] extractData(byte[] apdu) {
        if (apdu.length <= 4) return new byte[0];
        int lc = apdu[4] & 0xFF;
        if (apdu.length < 5 + lc) return new byte[0];
        byte[] d = new byte[lc];
        System.arraycopy(apdu, 5, d, 0, lc);
        return d;
    }

    private void broadcast(String status) {
        Log.i(TAG, status);
        sendBroadcast(new Intent(HomeKeyActivity.ACTION_NFC_STATUS)
                .putExtra(HomeKeyActivity.EXTRA_STATUS, status));
    }

    private static void logHex(String dir, byte[] data) {
        Log.d(TAG, dir + ": " + toHex(data));
    }

    public static byte[] hexToBytes(String hex) {
        byte[] b = new byte[hex.length() / 2];
        for (int i = 0; i < b.length; i++)
            b[i] = (byte)((Character.digit(hex.charAt(i * 2), 16) << 4)
                         | Character.digit(hex.charAt(i * 2 + 1), 16));
        return b;
    }

    public static String toHex(byte[] b) {
        if (b == null) return "null";
        StringBuilder sb = new StringBuilder(b.length * 2);
        for (byte x : b) sb.append(String.format("%02X", x));
        return sb.toString();
    }
}

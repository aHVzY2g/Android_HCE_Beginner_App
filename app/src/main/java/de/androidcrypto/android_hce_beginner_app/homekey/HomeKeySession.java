package de.androidcrypto.android_hce_beginner_app.homekey;

/**
 * Tracks per-transaction NFC session state for the Apple Home Key protocol.
 */
public class HomeKeySession {

    public static final int STATE_IDLE             = 0;
    public static final int STATE_PRIMARY_SELECTED = 1;
    public static final int STATE_FAST_DONE        = 2;
    public static final int STATE_STANDARD_DONE    = 3;
    public static final int STATE_EXCHANGE_DONE    = 4;
    public static final int STATE_CONFIG_SELECTED  = 5;

    private int     state          = STATE_IDLE;
    private boolean configRequired = false;

    private byte[] readerEphemPubKey;
    private byte[] transactionNonce;
    private byte[] readerId;
    private byte[] selectedVersion;
    private byte[] deviceEphemPubKey;

    public void reset() {
        state          = STATE_IDLE;
        configRequired = false;
        readerEphemPubKey = null;
        transactionNonce  = null;
        readerId          = null;
        selectedVersion   = null;
        deviceEphemPubKey = null;
    }

    public int  getState()          { return state; }
    public void setState(int state) { this.state = state; }

    public boolean canSelectConfig() {
        return configRequired && state >= STATE_EXCHANGE_DONE;
    }

    public void markExchangeDone() {
        configRequired = true;
        state = STATE_EXCHANGE_DONE;
    }

    public byte[] getReaderEphemPubKey()         { return readerEphemPubKey; }
    public void   setReaderEphemPubKey(byte[] k) { readerEphemPubKey = k; }

    public byte[] getTransactionNonce()          { return transactionNonce; }
    public void   setTransactionNonce(byte[] n)  { transactionNonce = n; }

    public byte[] getReaderId()                  { return readerId; }
    public void   setReaderId(byte[] id)         { readerId = id; }

    public byte[] getSelectedVersion()           { return selectedVersion; }
    public void   setSelectedVersion(byte[] v)   { selectedVersion = v; }

    public byte[] getDeviceEphemPubKey()         { return deviceEphemPubKey; }
    public void   setDeviceEphemPubKey(byte[] k) { deviceEphemPubKey = k; }
}

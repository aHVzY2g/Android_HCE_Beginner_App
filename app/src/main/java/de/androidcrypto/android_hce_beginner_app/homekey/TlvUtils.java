package de.androidcrypto.android_hce_beginner_app.homekey;

import java.util.HashMap;
import java.util.Map;

/**
 * BER-TLV encoding and decoding utilities for Apple Home Key protocol.
 */
public class TlvUtils {

    public static class TlvMap {
        private final Map<Integer, byte[]> map = new HashMap<>();

        public void put(int tag, byte[] value) { map.put(tag, value); }
        public byte[] get(int tag) { return map.get(tag); }
        public boolean contains(int tag) { return map.containsKey(tag); }
    }

    /**
     * Parse BER-TLV data into a tag->value map.
     * Supports single-byte tags and short/long-form lengths.
     */
    public static TlvMap parseTlv(byte[] data) {
        TlvMap result = new TlvMap();
        if (data == null || data.length == 0) return result;

        int pos = 0;
        while (pos < data.length - 1) {
            int tag = data[pos++] & 0xFF;
            if (tag == 0x00) continue;
            if (pos >= data.length) break;

            int lenByte = data[pos++] & 0xFF;
            int len;
            if (lenByte <= 0x7F) {
                len = lenByte;
            } else if (lenByte == 0x81) {
                if (pos >= data.length) break;
                len = data[pos++] & 0xFF;
            } else if (lenByte == 0x82) {
                if (pos + 1 >= data.length) break;
                len = ((data[pos] & 0xFF) << 8) | (data[pos + 1] & 0xFF);
                pos += 2;
            } else {
                break;
            }

            if (pos + len > data.length) break;

            byte[] value = new byte[len];
            System.arraycopy(data, pos, value, 0, len);
            result.put(tag, value);
            pos += len;
        }
        return result;
    }

    /** Encode a single TLV with a 1-byte tag. */
    public static byte[] encodeTlv(int tag, byte[] value) {
        if (value == null) value = new byte[0];
        byte[] lenBytes = encodeLength(value.length);
        byte[] result = new byte[1 + lenBytes.length + value.length];
        result[0] = (byte) tag;
        System.arraycopy(lenBytes, 0, result, 1, lenBytes.length);
        System.arraycopy(value, 0, result, 1 + lenBytes.length, value.length);
        return result;
    }

    private static byte[] encodeLength(int len) {
        if (len <= 0x7F) return new byte[]{(byte) len};
        if (len <= 0xFF) return new byte[]{(byte) 0x81, (byte) len};
        return new byte[]{(byte) 0x82, (byte) (len >> 8), (byte) (len & 0xFF)};
    }

    /** Concatenate any number of byte arrays. */
    public static byte[] concat(byte[]... arrays) {
        int total = 0;
        for (byte[] a : arrays) if (a != null) total += a.length;
        byte[] result = new byte[total];
        int pos = 0;
        for (byte[] a : arrays) {
            if (a != null) {
                System.arraycopy(a, 0, result, pos, a.length);
                pos += a.length;
            }
        }
        return result;
    }
}

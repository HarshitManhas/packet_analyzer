package com.packetanalyzer.utils;

/**
 * Utility class for byte-level manipulation operations commonly needed
 * when parsing raw network packet data.
 */
public final class ByteUtils {

    private ByteUtils() {
        // Utility class, prevent instantiation
    }

    /**
     * Reads an unsigned 8-bit value from a byte array at the given offset.
     */
    public static int readUint8(byte[] data, int offset) {
        if (offset < 0 || offset >= data.length) {
            throw new ArrayIndexOutOfBoundsException("Offset " + offset + " out of bounds for length " + data.length);
        }
        return data[offset] & 0xFF;
    }

    /**
     * Reads an unsigned 16-bit value (big-endian) from a byte array at the given offset.
     */
    public static int readUint16(byte[] data, int offset) {
        if (offset < 0 || offset + 1 >= data.length) {
            throw new ArrayIndexOutOfBoundsException("Cannot read 2 bytes at offset " + offset);
        }
        return ((data[offset] & 0xFF) << 8) | (data[offset + 1] & 0xFF);
    }

    /**
     * Reads an unsigned 32-bit value (big-endian) from a byte array at the given offset.
     * Returns as a long to avoid sign issues.
     */
    public static long readUint32(byte[] data, int offset) {
        if (offset < 0 || offset + 3 >= data.length) {
            throw new ArrayIndexOutOfBoundsException("Cannot read 4 bytes at offset " + offset);
        }
        return ((long)(data[offset] & 0xFF) << 24) |
               ((long)(data[offset + 1] & 0xFF) << 16) |
               ((long)(data[offset + 2] & 0xFF) << 8) |
               (long)(data[offset + 3] & 0xFF);
    }

    /**
     * Extracts a sub-array from the given byte array.
     */
    public static byte[] extractBytes(byte[] data, int offset, int length) {
        if (offset < 0 || offset + length > data.length) {
            throw new ArrayIndexOutOfBoundsException(
                String.format("Cannot extract %d bytes at offset %d from array of length %d",
                    length, offset, data.length));
        }
        byte[] result = new byte[length];
        System.arraycopy(data, offset, result, 0, length);
        return result;
    }

    /**
     * Converts a byte array to a hexadecimal string.
     */
    public static String toHexString(byte[] data) {
        if (data == null) return "null";
        StringBuilder sb = new StringBuilder();
        for (byte b : data) {
            sb.append(String.format("%02x", b & 0xFF));
        }
        return sb.toString();
    }

    /**
     * Converts a byte array to a MAC address string (colon-separated hex).
     */
    public static String toMacAddress(byte[] data, int offset) {
        if (offset + 5 >= data.length) {
            throw new ArrayIndexOutOfBoundsException("Cannot read 6 bytes for MAC at offset " + offset);
        }
        return String.format("%02x:%02x:%02x:%02x:%02x:%02x",
                data[offset] & 0xFF, data[offset + 1] & 0xFF,
                data[offset + 2] & 0xFF, data[offset + 3] & 0xFF,
                data[offset + 4] & 0xFF, data[offset + 5] & 0xFF);
    }

    /**
     * Checks if there are enough bytes remaining in the array.
     */
    public static boolean hasEnoughBytes(byte[] data, int offset, int required) {
        return data != null && offset >= 0 && (offset + required) <= data.length;
    }

    /**
     * Converts a byte array segment to a printable ASCII string,
     * replacing non-printable characters with dots.
     */
    public static String toAsciiString(byte[] data, int offset, int length) {
        if (data == null) return "";
        int end = Math.min(offset + length, data.length);
        StringBuilder sb = new StringBuilder();
        for (int i = offset; i < end; i++) {
            char c = (char)(data[i] & 0xFF);
            sb.append(c >= 32 && c < 127 ? c : '.');
        }
        return sb.toString();
    }
}

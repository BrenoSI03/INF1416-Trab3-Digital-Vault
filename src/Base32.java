import java.io.ByteArrayOutputStream;

public class Base32 {
    private static final String ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

    public String toString(byte[] data) {
        StringBuilder result = new StringBuilder((data.length * 8 + 4) / 5);
        int buffer = 0;
        int bits = 0;
        for (byte value : data) {
            buffer = (buffer << 8) | (value & 0xff);
            bits += 8;
            while (bits >= 5) {
                result.append(ALPHABET.charAt((buffer >> (bits - 5)) & 31));
                bits -= 5;
            }
        }
        if (bits > 0) {
            result.append(ALPHABET.charAt((buffer << (5 - bits)) & 31));
        }
        return result.toString();
    }

    public byte[] fromString(String text) {
        if (text == null) {
            return null;
        }
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        int buffer = 0;
        int bits = 0;
        int symbols = 0;
        int padding = 0;
        for (int i = 0; i < text.length(); i++) {
            char character = Character.toUpperCase(text.charAt(i));
            if (Character.isWhitespace(character)) {
                continue;
            }
            if (character == '=') {
                padding++;
                continue;
            }
            if (padding > 0) {
                return null;
            }
            int value = ALPHABET.indexOf(character);
            if (value < 0) {
                return null;
            }
            symbols++;
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                output.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        int remainder = symbols % 8;
        int expectedPadding = switch (remainder) {
            case 0 -> 0;
            case 2 -> 6;
            case 4 -> 4;
            case 5 -> 3;
            case 7 -> 1;
            default -> -1;
        };
        if (expectedPadding < 0 || (padding > 0 && padding != expectedPadding)
                || (bits > 0 && (buffer & ((1 << bits) - 1)) != 0)) {
            return null;
        }
        return output.toByteArray();
    }
}

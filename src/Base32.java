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
        for (int i = 0; i < text.length(); i++) {
            char character = Character.toUpperCase(text.charAt(i));
            if (Character.isWhitespace(character) || character == '=') {
                continue;
            }
            int value = ALPHABET.indexOf(character);
            if (value < 0) {
                return null;
            }
            buffer = (buffer << 5) | value;
            bits += 5;
            if (bits >= 8) {
                output.write((buffer >> (bits - 8)) & 0xff);
                bits -= 8;
            }
        }
        return output.toByteArray();
    }
}

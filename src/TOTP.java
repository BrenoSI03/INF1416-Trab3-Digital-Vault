/*
 * Trabalho 3 — INF1416 — Cofre Digital
 *
 * Breno de Andrade Soares — Matrícula: 2320363
 * João Pedro Zaidman dos Santos Gonçalves — Matrícula: 2320464
 */
import java.util.Date;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

public class TOTP {
    private final byte[] key;
    private final long timeStepInSeconds;

    public TOTP(String base32EncodedSecret, long timeStepInSeconds) throws Exception {
        if (timeStepInSeconds <= 0) {
            throw new Exception("Intervalo TOTP inválido.");
        }
        byte[] decoded = new Base32(Base32.Alphabet.BASE32, false, false)
                .fromString(base32EncodedSecret);
        if (decoded == null || decoded.length != 20) {
            throw new Exception("O segredo TOTP deve conter 20 bytes em Base32.");
        }
        this.key = decoded;
        this.timeStepInSeconds = timeStepInSeconds;
    }

    private String getTOTPCodeFromHash(byte[] hash) {
        int offset = hash[hash.length - 1] & 0x0f;
        int binary = ((hash[offset] & 0x7f) << 24)
                | ((hash[offset + 1] & 0xff) << 16)
                | ((hash[offset + 2] & 0xff) << 8)
                | (hash[offset + 3] & 0xff);
        return String.format("%06d", binary % 1_000_000);
    }

    private byte[] HMAC_SHA1(byte[] counter, byte[] keyByteArray) {
        try {
            Mac mac = Mac.getInstance("HmacSHA1");
            mac.init(new SecretKeySpec(keyByteArray, "HmacSHA1"));
            return mac.doFinal(counter);
        } catch (Exception error) {
            throw new IllegalStateException("Não foi possível calcular HMAC-SHA1.", error);
        }
    }

    private String TOTPCode(long timeInterval) {
        byte[] counter = new byte[8];
        for (int i = counter.length - 1; i >= 0; i--) {
            counter[i] = (byte) timeInterval;
            timeInterval >>>= 8;
        }
        return getTOTPCodeFromHash(HMAC_SHA1(counter, key));
    }

    public String generateCode() {
        long interval = new Date().getTime() / 1000L / timeStepInSeconds;
        return TOTPCode(interval);
    }

    public boolean validateCode(String inputTOTP) {
        if (inputTOTP == null || !inputTOTP.matches("\\d{6}")) {
            return false;
        }
        long interval = new Date().getTime() / 1000L / timeStepInSeconds;
        for (long candidate = interval - 1; candidate <= interval + 1; candidate++) {
            if (inputTOTP.equals(TOTPCode(candidate))) {
                return true;
            }
        }
        return false;
    }
}

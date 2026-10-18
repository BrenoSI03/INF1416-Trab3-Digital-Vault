import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.CharBuffer;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import org.bouncycastle.crypto.generators.OpenBSDBCrypt;

public final class CryptoUtils {
    private CryptoUtils() {
    }

    public static SecretKey generateAesKey(char[] secret) throws Exception {
        ByteBuffer encoded = StandardCharsets.UTF_8.encode(CharBuffer.wrap(secret));
        byte[] seed = new byte[encoded.remaining()];
        encoded.get(seed);
        try {
            return generateAesKey(seed);
        } finally {
            Arrays.fill(seed, (byte) 0);
            if (encoded.hasArray()) {
                Arrays.fill(encoded.array(), (byte) 0);
            }
        }
    }

    public static SecretKey generateAesKey(byte[] seed) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(seed);
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        return generator.generateKey();
    }

    public static byte[] encryptAes(byte[] plainText, char[] secret) throws Exception {
        return processAes(Cipher.ENCRYPT_MODE, plainText, generateAesKey(secret));
    }

    public static byte[] decryptAes(byte[] cipherText, char[] secret) throws Exception {
        return processAes(Cipher.DECRYPT_MODE, cipherText, generateAesKey(secret));
    }

    public static byte[] decryptAes(byte[] cipherText, byte[] seed) throws Exception {
        return processAes(Cipher.DECRYPT_MODE, cipherText, generateAesKey(seed));
    }

    private static byte[] processAes(int mode, byte[] data, SecretKey key) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(mode, key);
        return cipher.doFinal(data);
    }

    public static PrivateKey loadPrivateKey(Path file, char[] passphrase) throws Exception {
        byte[] content = decryptAes(Files.readAllBytes(file), passphrase);
        try {
            return restorePrivateKey(content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    public static PrivateKey restorePrivateKey(byte[] decryptedContent) throws Exception {
        String text = new String(decryptedContent, StandardCharsets.US_ASCII).trim();
        String begin = "-----BEGIN PRIVATE KEY-----";
        String end = "-----END PRIVATE KEY-----";
        if (text.startsWith(begin) && text.endsWith(end)) {
            text = text.substring(begin.length(), text.length() - end.length());
        } else if (text.contains("-----")) {
            throw new IllegalArgumentException("Chave privada não contém PKCS#8 em PEM/Base64.");
        }
        String base64 = text.replaceAll("\\s+", "");
        if (base64.isEmpty()) {
            throw new IllegalArgumentException("Chave privada não contém PKCS#8 em PEM/Base64.");
        }
        byte[] der = Base64.getDecoder().decode(base64);
        try {
            return KeyFactory.getInstance("RSA").generatePrivate(new PKCS8EncodedKeySpec(der));
        } finally {
            Arrays.fill(der, (byte) 0);
        }
    }

    public static X509Certificate loadCertificate(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    public static boolean proveKeyPair(PrivateKey privateKey, PublicKey publicKey, int size)
            throws Exception {
        byte[] challenge = new byte[size];
        new SecureRandom().nextBytes(challenge);
        byte[] signature = sign(challenge, privateKey);
        return verify(challenge, signature, publicKey);
    }

    public static byte[] sign(byte[] data, PrivateKey privateKey) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privateKey);
        signature.update(data);
        return signature.sign();
    }

    public static boolean verify(byte[] data, byte[] signatureBytes, PublicKey publicKey)
            throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initVerify(publicKey);
        signature.update(data);
        return signature.verify(signatureBytes);
    }

    public static byte[] openEnvelope(byte[] envelope, PrivateKey privateKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        return cipher.doFinal(envelope);
    }

    public static String generateBcrypt(char[] password) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return OpenBSDBCrypt.generate("2y", password, salt, 8);
    }

    public static boolean verifyBcrypt(String hash, char[] password) {
        try {
            return hash != null && hash.length() == 60 && hash.startsWith("$2y$08$")
                    && OpenBSDBCrypt.checkPassword(hash, password);
        } catch (RuntimeException error) {
            return false;
        }
    }

    public static String extractName(X509Certificate certificate) throws Exception {
        return subjectAttribute(certificate, "CN");
    }

    public static String extractEmail(X509Certificate certificate) throws Exception {
        return subjectAttribute(certificate, "EMAILADDRESS");
    }

    private static String subjectAttribute(X509Certificate certificate, String type)
            throws Exception {
        LdapName name = new LdapName(certificate.getSubjectX500Principal().getName());
        for (Rdn item : name.getRdns()) {
            if (type.equalsIgnoreCase(item.getType())
                    || ("EMAILADDRESS".equals(type) && "1.2.840.113549.1.9.1".equals(item.getType()))) {
                Object value = item.getValue();
                // Sem nome conhecido para o OID, o e-mail vem em DER: 2 bytes de cabeçalho + texto.
                if (value instanceof byte[] bytes && bytes.length > 2) {
                    return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_8);
                }
                return String.valueOf(value);
            }
        }
        return null;
    }

    public static void clear(char[] secret) {
        if (secret != null) {
            Arrays.fill(secret, '\0');
        }
    }
}

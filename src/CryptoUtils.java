import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.nio.CharBuffer;
import java.nio.ByteBuffer;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
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

    public static SecretKey generateAesKey(char[] segredo) throws Exception {
        ByteBuffer codificado = StandardCharsets.UTF_8.encode(CharBuffer.wrap(segredo));
        byte[] semente = new byte[codificado.remaining()];
        codificado.get(semente);
        try {
            return generateAesKey(semente);
        } finally {
            Arrays.fill(semente, (byte) 0);
            if (codificado.hasArray()) {
                Arrays.fill(codificado.array(), (byte) 0);
            }
        }
    }

    public static SecretKey generateAesKey(byte[] semente) throws Exception {
        SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
        random.setSeed(semente);
        KeyGenerator generator = KeyGenerator.getInstance("AES");
        generator.init(256, random);
        return generator.generateKey();
    }

    public static byte[] encryptAes(byte[] texto, char[] segredo) throws Exception {
        return processAes(Cipher.ENCRYPT_MODE, texto, generateAesKey(segredo));
    }

    public static byte[] decryptAes(byte[] cifra, char[] segredo) throws Exception {
        return processAes(Cipher.DECRYPT_MODE, cifra, generateAesKey(segredo));
    }

    public static byte[] encryptAes(byte[] texto, byte[] semente) throws Exception {
        return processAes(Cipher.ENCRYPT_MODE, texto, generateAesKey(semente));
    }

    public static byte[] decryptAes(byte[] cifra, byte[] semente) throws Exception {
        return processAes(Cipher.DECRYPT_MODE, cifra, generateAesKey(semente));
    }

    private static byte[] processAes(int modo, byte[] dados, SecretKey chave) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(modo, chave);
        return cipher.doFinal(dados);
    }

    public static PrivateKey loadPrivateKey(Path arquivo, char[] frase) throws Exception {
        byte[] conteudo = decryptAes(Files.readAllBytes(arquivo), frase);
        try {
            return restorePrivateKey(conteudo);
        } finally {
            Arrays.fill(conteudo, (byte) 0);
        }
    }

    public static PrivateKey restorePrivateKey(byte[] conteudoDecriptado) throws Exception {
        String texto = new String(conteudoDecriptado, StandardCharsets.US_ASCII).trim();
        String inicio = "-----BEGIN PRIVATE KEY-----";
        String fim = "-----END PRIVATE KEY-----";
        if (texto.startsWith(inicio) && texto.endsWith(fim)) {
            texto = texto.substring(inicio.length(), texto.length() - fim.length());
        } else if (texto.contains("-----")) {
            throw new IllegalArgumentException("Chave privada não contém PKCS#8 em PEM/Base64.");
        }
        String base64 = texto.replaceAll("\\s+", "");
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

    public static X509Certificate loadCertificate(Path arquivo) throws Exception {
        try (var input = Files.newInputStream(arquivo)) {
            return (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(input);
        }
    }

    public static X509Certificate loadCertificate(byte[] pem) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(pem));
    }

    public static boolean proveKeyPair(PrivateKey privada, PublicKey publica, int tamanho) throws Exception {
        byte[] desafio = new byte[tamanho];
        new SecureRandom().nextBytes(desafio);
        byte[] assinatura = sign(desafio, privada);
        return verify(desafio, assinatura, publica);
    }

    public static byte[] sign(byte[] dados, PrivateKey privada) throws Exception {
        Signature assinatura = Signature.getInstance("SHA1withRSA");
        assinatura.initSign(privada);
        assinatura.update(dados);
        return assinatura.sign();
    }

    public static boolean verify(byte[] dados, byte[] assinaturaBinaria, PublicKey publica) throws Exception {
        Signature assinatura = Signature.getInstance("SHA1withRSA");
        assinatura.initVerify(publica);
        assinatura.update(dados);
        return assinatura.verify(assinaturaBinaria);
    }

    public static byte[] openEnvelope(byte[] envelope, PrivateKey privada) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privada);
        return cipher.doFinal(envelope);
    }

    public static byte[] createEnvelope(byte[] semente, PublicKey publica) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.ENCRYPT_MODE, publica);
        return cipher.doFinal(semente);
    }

    public static String generateBcrypt(char[] senha) {
        byte[] salt = new byte[16];
        new SecureRandom().nextBytes(salt);
        return OpenBSDBCrypt.generate("2y", senha, salt, 8);
    }

    public static boolean verifyBcrypt(String hash, char[] senha) {
        try {
            return hash != null && hash.length() == 60 && hash.startsWith("$2y$08$")
                    && OpenBSDBCrypt.checkPassword(hash, senha);
        } catch (RuntimeException error) {
            return false;
        }
    }

    public static String extractName(X509Certificate certificado) throws Exception {
        return subjectAttribute(certificado, "CN");
    }

    public static String extractEmail(X509Certificate certificado) throws Exception {
        return subjectAttribute(certificado, "EMAILADDRESS");
    }

    private static String subjectAttribute(X509Certificate certificado, String tipo) throws Exception {
        LdapName nome = new LdapName(certificado.getSubjectX500Principal().getName());
        for (Rdn item : nome.getRdns()) {
            if (tipo.equalsIgnoreCase(item.getType())
                    || ("EMAILADDRESS".equals(tipo) && "1.2.840.113549.1.9.1".equals(item.getType()))) {
                Object valor = item.getValue();
                if (valor instanceof byte[] bytes && bytes.length > 2) {
                    return new String(bytes, 2, bytes.length - 2, StandardCharsets.UTF_8);
                }
                return String.valueOf(valor);
            }
        }
        return null;
    }

    public static KeyPair generateRsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    public static void clear(char[] segredo) {
        if (segredo != null) {
            Arrays.fill(segredo, '\0');
        }
    }
}

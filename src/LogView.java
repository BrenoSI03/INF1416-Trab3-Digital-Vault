import java.io.Console;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;

public class LogView {
    public static void main(String[] args) {
        if (args.length < 1 || args.length > 2) {
            System.err.println("Uso: java LogView <caminho-chave-privada> [arquivo-banco]");
            return;
        }
        Console console = System.console();
        if (console == null) {
            System.err.println("É necessário executar em um terminal com leitura de senha sem eco.");
            return;
        }
        char[] passphrase = console.readPassword("Frase secreta da chave do administrador: ");
        try {
            Path databaseFile = Path.of(args.length == 2 ? args[1] : "cofre.db");
            if (passphrase == null || !Files.isRegularFile(databaseFile)) {
                throw new Exception("Banco de dados ou frase secreta indisponível.");
            }
            try (Database database = new Database(databaseFile)) {
                Database.User admin = database.findAdministrator();
                if (admin == null || !admin.isAdministrator()) {
                    throw new Exception("Administrador não cadastrado.");
                }
                Database.KeyEntry keyEntry = database.findKeyEntry(admin.uid());
                X509Certificate certificate = CryptoUtils.loadCertificate(keyEntry.certificatePem());
                PrivateKey privateKey = CryptoUtils.loadPrivateKey(Path.of(args[0]), passphrase);
                if (!CryptoUtils.proveKeyPair(privateKey, certificate.getPublicKey(), 2_048)) {
                    throw new Exception("Chave privada não autorizada.");
                }
                DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss.SSS")
                        .withZone(ZoneId.systemDefault());
                for (Database.LogEntry entry : database.listLogs()) {
                    String text = entry.message();
                    text = text.replace("<login_name>",
                            entry.login() == null ? "não identificado" : entry.login());
                    text = text.replace("<arq_name>",
                            entry.fileName() == null ? "não informado" : entry.fileName());
                    System.out.printf("%s | %04d | %s%n",
                            formatter.format(Instant.ofEpochMilli(entry.timestamp())),
                            entry.eventCode(), text);
                }
            }
        } catch (Exception error) {
            System.err.println("Acesso negado: " + message(error));
        } finally {
            CryptoUtils.clear(passphrase);
        }
    }

    private static String message(Exception error) {
        return error.getMessage() == null ? "falha de autenticação" : error.getMessage();
    }
}

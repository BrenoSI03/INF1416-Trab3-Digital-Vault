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
        char[] frase = console.readPassword("Frase secreta da chave do administrador: ");
        try {
            Path databaseFile = Path.of(args.length == 2 ? args[1] : "cofre.db");
            if (frase == null || !Files.isRegularFile(databaseFile)) {
                throw new Exception("Banco de dados ou frase secreta indisponível.");
            }
            try (Database banco = new Database(databaseFile)) {
                Database.User administrador = banco.findAdministrator();
                if (administrador == null || !administrador.isAdministrator()) {
                    throw new Exception("Administrador não cadastrado.");
                }
                Database.KeyEntry chaveiro = banco.findKeyEntry(administrador.uid());
                X509Certificate certificado = CryptoUtils.loadCertificate(chaveiro.certificatePem());
                PrivateKey privada = CryptoUtils.loadPrivateKey(Path.of(args[0]), frase);
                if (!CryptoUtils.proveKeyPair(privada, certificado.getPublicKey(), 2_048)) {
                    throw new Exception("Chave privada não autorizada.");
                }
                DateTimeFormatter formato = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss.SSS")
                        .withZone(ZoneId.systemDefault());
                for (Database.LogEntry registro : banco.listLogs()) {
                    String texto = registro.message();
                    texto = texto.replace("<login_name>",
                            registro.login() == null ? "não identificado" : registro.login());
                    texto = texto.replace("<arq_name>",
                            registro.fileName() == null ? "não informado" : registro.fileName());
                    System.out.printf("%s | %04d | %s%n",
                            formato.format(Instant.ofEpochMilli(registro.timestamp())),
                            registro.eventCode(), texto);
                }
            }
        } catch (Exception error) {
            System.err.println("Acesso negado: " + message(error));
        } finally {
            CryptoUtils.clear(frase);
        }
    }

    private static String message(Exception error) {
        return error.getMessage() == null ? "falha de autenticação" : error.getMessage();
    }
}

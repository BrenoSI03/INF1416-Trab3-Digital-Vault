import java.io.ByteArrayOutputStream;
import java.io.Console;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.DriverManager;
import java.util.ArrayList;
import java.util.Base64;
import java.util.Arrays;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class Tests {
    private static final char[] STORE_PASSWORD = "teste123".toCharArray();
    private static int verificacoes;

    private record Identity(String email, PrivateKey privateKey, X509Certificate certificate,
            Path encryptedKeyPath, byte[] certificatePem) {
    }

    public static void main(String[] args) throws Exception {
        if (args.length == 1 && "--package-t3".equals(args[0])) {
            testOriginalPackageWithPassphrases();
            System.out.println("OK - " + verificacoes + " verificações do Pacote-T3 executadas.");
            return;
        }
        Path raiz = Path.of("tests", "additional-data",
                "run-" + System.currentTimeMillis()).toAbsolutePath();
        Path pastaVault = raiz.resolve("independent-vault");
        Path saida = raiz.resolve("output");
        Files.createDirectories(pastaVault);
        Files.createDirectories(saida);
        cleanKnownFiles(raiz, pastaVault, saida);

        testBase32AndTotp();
        testBasicCryptography();
        testVirtualKeyboard();
        testFieldLimits();
        testOfficialMessages();
        testOriginalPackageStructure();
        testDatabaseAndVault(raiz, pastaVault, saida);
        System.out.println("OK - " + verificacoes + " verificações executadas.");
        System.out.println("Dados adicionais: " + raiz);
    }

    private static void testBase32AndTotp() throws Exception {
        Base32 base32 = new Base32(Base32.Alphabet.BASE32, false, false);
        String codificado = base32.toString("foobar".getBytes(StandardCharsets.US_ASCII));
        check("MZXW6YTBOI".equals(codificado), "Base32 RFC 4648");
        check("foobar".equals(new String(base32.fromString(codificado), StandardCharsets.US_ASCII)),
                "decodificação Base32");
        byte[] segredo = new byte[20];
        new SecureRandom().nextBytes(segredo);
        TOTP totp = new TOTP(base32.toString(segredo), 30);
        check(totp.validateCode(totp.generateCode()), "TOTP atual");
        var metodo = TOTP.class.getDeclaredMethod("TOTPCode", long.class);
        metodo.setAccessible(true);
        TOTP exemploRfc = new TOTP(base32.toString(
                "12345678901234567890".getBytes(StandardCharsets.US_ASCII)), 30);
        check("287082".equals(metodo.invoke(exemploRfc, 1L)),
                "TOTP corresponde ao vetor RFC 6238 de 59 segundos");
        long intervalo = System.currentTimeMillis() / 1000L / 30L;
        check(totp.validateCode((String) metodo.invoke(totp, intervalo - 1)), "TOTP de T-1");
        check(totp.validateCode((String) metodo.invoke(totp, intervalo + 1)), "TOTP de T+1");
        check(!totp.validateCode((String) metodo.invoke(totp, intervalo - 2)),
                "TOTP fora da janela recusado");
        check(!totp.validateCode("abc123") && !totp.validateCode("00000"), "TOTP inválido");
        var truncamento = TOTP.class.getDeclaredMethod("getTOTPCodeFromHash", byte[].class);
        truncamento.setAccessible(true);
        check("000000".equals(truncamento.invoke(totp, (Object) new byte[20])),
                "TOTP preserva zeros à esquerda");
        boolean zeroInicialValidado = false;
        SecureRandom random = new SecureRandom();
        for (int i = 0; i < 1_000 && !zeroInicialValidado; i++) {
            byte[] segredoComZero = new byte[20];
            random.nextBytes(segredoComZero);
            TOTP totpComZero = new TOTP(base32.toString(segredoComZero), 30);
            String codigo = totpComZero.generateCode();
            zeroInicialValidado = codigo.startsWith("0") && totpComZero.validateCode(codigo);
        }
        check(zeroInicialValidado, "TOTP iniciado por zero é validado com seis dígitos");
    }

    private static void testBasicCryptography() throws Exception {
        byte[] texto = "conteúdo independente".getBytes(StandardCharsets.UTF_8);
        char[] frase = "frase-áes-teste".toCharArray();
        byte[] cifra = CryptoUtils.encryptAes(texto, frase);
        check(java.util.Arrays.equals(texto, CryptoUtils.decryptAes(cifra, frase)),
                "AES com SHA1PRNG");
        boolean recusou = false;
        try {
            CryptoUtils.decryptAes(cifra, "frase-incorreta".toCharArray());
        } catch (Exception expected) {
            recusou = true;
        }
        check(recusou, "AES recusa frase incorreta");

        var par = generateRsaKeyPair();
        byte[] assinatura = CryptoUtils.sign(texto, par.getPrivate());
        check(CryptoUtils.verify(texto, assinatura, par.getPublic()), "assinatura RSA-SHA1");
        texto[0] ^= 1;
        check(!CryptoUtils.verify(texto, assinatura, par.getPublic()), "assinatura adulterada");
        byte[] semente = new byte[32];
        new SecureRandom().nextBytes(semente);
        check(java.util.Arrays.equals(semente,
                CryptoUtils.openEnvelope(createEnvelope(semente, par.getPublic()),
                        par.getPrivate())), "envelope RSA PKCS1");
        check(CryptoUtils.proveKeyPair(par.getPrivate(), par.getPublic(), 2_048),
                "prova RSA de 2048 bytes do logView");
        check(CryptoUtils.proveKeyPair(par.getPrivate(), par.getPublic(), 10_240),
                "prova RSA de 10240 bytes do cadastro");
        var outroPar = generateRsaKeyPair();
        check(!CryptoUtils.proveKeyPair(par.getPrivate(), outroPar.getPublic(), 10_240),
                "par RSA incorreto recusado no cadastro");
        String base64 = Base64.getMimeEncoder(64, new byte[] {'\n'})
                .encodeToString(par.getPrivate().getEncoded());
        check(Arrays.equals(par.getPrivate().getEncoded(),
                CryptoUtils.restorePrivateKey(base64.getBytes(StandardCharsets.US_ASCII)).getEncoded()),
                "PKCS#8 Base64 com várias linhas");
        boolean pemIncompletoRecusado = false;
        try {
            CryptoUtils.restorePrivateKey(("-----BEGIN PRIVATE KEY-----\n" + base64)
                    .getBytes(StandardCharsets.US_ASCII));
        } catch (Exception expected) {
            pemIncompletoRecusado = true;
        }
        check(pemIncompletoRecusado, "PEM sem rodapé recusado");
        char[] segredoTemporario = "frase-temporaria".toCharArray();
        CryptoUtils.clear(segredoTemporario);
        check(new String(segredoTemporario).chars().allMatch(value -> value == 0),
                "frase mantida em char[] pode ser limpa no encerramento");
    }

    private static void testVirtualKeyboard() throws Exception {
        check(DigitalVault.isPasswordValid("13572468".toCharArray()), "PIN válido");
        check(!DigitalVault.isPasswordValid("11234567".toCharArray()), "PIN repetido recusado");
        check(!DigitalVault.isPasswordValid("1234567".toCharArray()), "PIN curto recusado");
        char[] pin = "13572468".toCharArray();
        String hash = CryptoUtils.generateBcrypt(pin);
        check(hash.startsWith("$2y$08$") && hash.length() == 60, "formato bcrypt 2y custo 8");
        List<char[]> pares = new ArrayList<>();
        for (char digito : pin) {
            pares.add(new char[] {digito, digito == '9' ? '0' : (char) (digito + 1)});
        }
        check(java.util.Arrays.equals(pin, DigitalVault.findPassword(pares, hash)),
                "árvore de candidatas do teclado");
        List<char[]> ultimaCombinacao = new ArrayList<>();
        for (char digito : pin) {
            ultimaCombinacao.add(new char[] {
                    digito == '0' ? '1' : '0', digito
            });
        }
        check(Arrays.equals(pin, DigitalVault.findPassword(ultimaCombinacao, hash)),
                "árvore alcança a última das 2^L combinações");
        checkCandidate("13572468");
        checkCandidate("135724689");
        checkCandidate("1357246890");
        javax.swing.JButton[] teclas = new javax.swing.JButton[5];
        for (int i = 0; i < teclas.length; i++) {
            teclas[i] = new javax.swing.JButton();
        }
        for (int rodada = 0; rodada < 10; rodada++) {
            DigitalVault.distributeDigits(teclas);
            boolean[] vistos = new boolean[10];
            boolean semRepeticao = true;
            for (javax.swing.JButton tecla : teclas) {
                for (String valor : tecla.getText().split(" ")) {
                    int digito = Integer.parseInt(valor);
                    semRepeticao &= !vistos[digito];
                    vistos[digito] = true;
                }
            }
            boolean completo = true;
            for (boolean visto : vistos) {
                completo &= visto;
            }
            check(semRepeticao && completo, "teclado contém 0..9 uma vez na distribuição " + rodada);
        }

        List<char[]> cliques = new ArrayList<>();
        DigitalVault.distributeDigits(teclas);
        String parPressionado = teclas[0].getText();
        check(DigitalVault.recordPressedPair(cliques, parPressionado),
                "clique registra o par apresentado");
        char[] parRegistrado = cliques.get(0).clone();
        DigitalVault.distributeDigits(teclas);
        check(Arrays.equals(parRegistrado, cliques.get(0)),
                "redistribuição não altera o par já pressionado");
        for (int i = 1; i < 10; i++) {
            DigitalVault.recordPressedPair(cliques, teclas[i % teclas.length].getText());
            DigitalVault.distributeDigits(teclas);
        }
        check(cliques.size() == 10
                && !DigitalVault.recordPressedPair(cliques, teclas[0].getText()),
                "teclado limita a senha a 10 cliques");
        cliques.clear();
        check(cliques.isEmpty() && DigitalVault.findPassword(cliques, hash) == null,
                "Limpar remove os pares e OK recusa tamanho inválido");

        byte[] segredo = new byte[20];
        new SecureRandom().nextBytes(segredo);
        String segredoBase32 = new Base32(Base32.Alphabet.BASE32, false, false).toString(segredo);
        byte[] segredoCifrado = CryptoUtils.encryptAes(
                segredoBase32.getBytes(StandardCharsets.US_ASCII), pin);
        String codigoAtual = new TOTP(segredoBase32, 30).generateCode();
        check(!DigitalVault.verifyToken(segredoCifrado, null, codigoAtual),
                "identificação sem PIN não contorna o segundo fator");
        check(DigitalVault.verifyToken(segredoCifrado, pin, codigoAtual),
                "PIN comprovado permite validar o TOTP");
        check(!DigitalVault.verifyToken(segredoCifrado, pin, "00000"),
                "PIN correto sem TOTP válido não autentica");
    }

    private static void checkCandidate(String senha) throws Exception {
        char[] pin = senha.toCharArray();
        String hash = CryptoUtils.generateBcrypt(pin);
        List<char[]> pares = new ArrayList<>();
        for (char digito : pin) {
            pares.add(new char[] {digito, digito == '9' ? '0' : (char) (digito + 1)});
        }
        char[] comprovada = DigitalVault.findPassword(pares, hash);
        check(java.util.Arrays.equals(pin, comprovada),
                "teclado virtual com PIN de " + pin.length + " dígitos");
        byte[] segredo = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP".getBytes(StandardCharsets.US_ASCII);
        byte[] cifra = CryptoUtils.encryptAes(segredo, pin);
        check(Arrays.equals(segredo, CryptoUtils.decryptAes(cifra, comprovada)),
                "PIN comprovado recupera o segredo TOTP de " + pin.length + " dígitos");
        CryptoUtils.clear(comprovada);
    }

    private static void testFieldLimits() throws Exception {
        var metodo = DigitalVault.class.getDeclaredMethod(
                "limitField", javax.swing.JTextField.class, int.class);
        metodo.setAccessible(true);
        javax.swing.JTextField campo = new javax.swing.JTextField();
        metodo.invoke(null, campo, 10);
        campo.setText("1234567890");
        check("1234567890".equals(campo.getText()), "campo aceita o limite exato");
        campo.setText("12345678901");
        check("1234567890".equals(campo.getText()), "campo recusa texto acima do limite");
    }

    private static void testOfficialMessages() {
        Map<Integer, String> messages = expectedOfficialMessages();
        check(messages.size() == 64, "catálogo de auditoria contém os 64 MIDs oficiais");
    }

    private static Map<Integer, String> expectedOfficialMessages() {
        String table = """
                1001|Sistema iniciado.
                1002|Sistema encerrado.
                1003|Sessão iniciada para <login_name>.
                1004|Sessão encerrada para <login_name>.
                1005|Partida do sistema iniciada para cadastro do administrador.
                1006|Partida do sistema iniciada para operação normal pelos usuários.
                2001|Autenticação etapa 1 iniciada.
                2002|Autenticação etapa 1 encerrada.
                2003|Login name <login_name> identificado com acesso liberado.
                2004|Login name <login_name> identificado com acesso bloqueado.
                2005|Login name <login_name> não identificado.
                3001|Autenticação etapa 2 iniciada para <login_name>.
                3002|Autenticação etapa 2 encerrada para <login_name>.
                3003|Senha pessoal verificada positivamente para <login_name>.
                3004|Primeiro erro da senha pessoal contabilizado para <login_name>.
                3005|Segundo erro da senha pessoal contabilizado para <login_name>.
                3006|Terceiro erro da senha pessoal contabilizado para <login_name>.
                3007|Acesso do usuario <login_name> bloqueado pela autenticação etapa 2.
                4001|Autenticação etapa 3 iniciada para <login_name>.
                4002|Autenticação etapa 3 encerrada para <login_name>.
                4003|Token verificado positivamente para <login_name>.
                4004|Primeiro erro de token contabilizado para <login_name>.
                4005|Segundo erro de token contabilizado para <login_name>.
                4006|Terceiro erro de token contabilizado para <login_name>.
                4007|Acesso do usuario <login_name> bloqueado pela autenticação etapa 3.
                5001|Tela principal apresentada para <login_name>.
                5002|Opção 1 do menu principal selecionada por <login_name>.
                5003|Opção 2 do menu principal selecionada por <login_name>.
                5004|Opção 3 do menu principal selecionada por <login_name>.
                6001|Tela de cadastro apresentada para <login_name>.
                6002|Botão cadastrar pressionado por <login_name>.
                6003|Senha pessoal inválida fornecida por <login_name>.
                6004|Caminho do certificado digital inválido fornecido por <login_name>.
                6005|Chave privada verificada negativamente para <login_name> (caminho inválido).
                6006|Chave privada verificada negativamente para <login_name> (frase secreta inválida).
                6007|Chave privada verificada negativamente para <login_name> (assinatura digital inválida).
                6008|Confirmação de dados aceita por <login_name>.
                6009|Confirmação de dados rejeitada por <login_name>.
                6010|Botão voltar de cadastro para o menu principal pressionado por <login_name>.
                7001|Tela de consulta de arquivos secretos apresentada para <login_name>.
                7002|Botão voltar de consulta para o menu principal pressionado por <login_name>.
                7003|Botão Listar de consulta pressionado por <login_name>.
                7004|Caminho de pasta inválido fornecido por <login_name>.
                7005|Arquivo de índice decriptado com sucesso para <login_name>.
                7006|Arquivo de índice verificado (integridade e autenticidade) com sucesso para <login_name>.
                7007|Falha na decriptação do arquivo de índice para <login_name>.
                7008|Falha na verificação (integridade e autenticidade) do arquivo de índice para <login_name>.
                7009|Lista de arquivos presentes no índice apresentada para <login_name>.
                7010|Arquivo de share decriptado com sucesso para <login_name>.
                7011|Arquivo de share verificado (integridade e autenticidade) com sucesso para <login_name>.
                7012|Falha na decriptação do arquivo de share para <login_name>.
                7013|Falha na verificação (integridade e autenticidade) do arquivo de share para <login_name>.
                7014|Lista de arquivos presentes no share apresentada para <login_name>.
                7015|Arquivo <arq_name> selecionado por <login_name> para decriptação.
                7016|Acesso permitido ao arquivo <arq_name> para <login_name>.
                7017|Acesso negado ao arquivo <arq_name> para <login_name>.
                7018|Arquivo <arq_name> decriptado com sucesso para <login_name>.
                7019|Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>.
                7020|Falha na decriptação do arquivo <arq_name> para <login_name>.
                7021|Falha na verificação (integridade e autenticidade) do arquivo <arq_name> para <login_name>.
                8001|Tela de saída apresentada para <login_name>.
                8002|Botão encerrar sessão pressionado por <login_name>.
                8003|Botão encerrar sistema pressionado por <login_name>.
                8004|Botão voltar de sair para o menu principal pressionado por <login_name>.
                """;
        Map<Integer, String> messages = new java.util.TreeMap<>();
        for (String line : table.lines().toList()) {
            int separator = line.indexOf('|');
            messages.put(Integer.parseInt(line.substring(0, separator)),
                    line.substring(separator + 1));
        }
        return messages;
    }

    private static void testOriginalPackageStructure() throws Exception {
        Path chaves = Path.of("Pacote-T3", "Keys");
        Path arquivos = Path.of("Pacote-T3", "Files");
        check("admin@inf1416.puc-rio.br".equals(CryptoUtils.extractEmail(
                loadCertificate(chaves.resolve("admin-x509.crt")))),
                "certificado do administrador do Pacote-T3");
        check(Files.size(chaves.resolve("admin-pkcs8-aes.key")) > 0,
                "chave cifrada do Pacote-T3 disponível");
        check(Files.isRegularFile(arquivos.resolve("XXYYZZ22.1.shr")),
                "contrato codigo.ID.shr no Pacote-T3");
    }

    private static void testOriginalPackageWithPassphrases() throws Exception {
        Console console = System.console();
        if (console == null) {
            throw new IllegalStateException("Execute este teste em um terminal para informar as frases sem eco.");
        }
        Path keys = Path.of("Pacote-T3", "Keys");
        Path files = Path.of("Pacote-T3", "Files");
        Map<String, Identity> identities = new HashMap<>();
        for (String label : List.of("admin", "user01", "user02")) {
            Path keyPath = keys.resolve(label + "-pkcs8-aes.key");
            Path certificatePath = keys.resolve(label + "-x509.crt");
            char[] passphrase = console.readPassword("Frase de %s: ", label);
            if (passphrase == null) {
                throw new IllegalStateException("Leitura da frase cancelada.");
            }
            try {
                PrivateKey privateKey = CryptoUtils.loadPrivateKey(keyPath, passphrase);
                X509Certificate certificate = loadCertificate(certificatePath);
                check(CryptoUtils.proveKeyPair(privateKey, certificate.getPublicKey(), 10_240),
                        "chave e certificado de " + label);
                char[] wrongPassphrase = Arrays.copyOf(passphrase, passphrase.length + 1);
                wrongPassphrase[wrongPassphrase.length - 1] = 'x';
                boolean rejected = false;
                try {
                    CryptoUtils.loadPrivateKey(keyPath, wrongPassphrase);
                } catch (Exception expected) {
                    rejected = true;
                } finally {
                    Arrays.fill(wrongPassphrase, '\0');
                }
                check(rejected, "frase incorreta rejeitada para " + label);
                identities.put(CryptoUtils.extractEmail(certificate),
                        new Identity(CryptoUtils.extractEmail(certificate), privateKey, certificate,
                                keyPath, Files.readAllBytes(certificatePath)));
            } finally {
                Arrays.fill(passphrase, '\0');
            }
        }

        Identity admin = identities.values().stream()
                .filter(identity -> identity.encryptedKeyPath().getFileName().toString()
                        .startsWith("admin-"))
                .findFirst().orElseThrow();
        byte[] index = openPackageFile(files, "index", "index.env",
                admin.privateKey(), admin.certificate().getPublicKey());
        byte[] share = openPackageFile(files, "share", "share.env",
                admin.privateKey(), admin.certificate().getPublicKey());
        check(index.length > 0 && share.length > 0,
                "index e share decriptados e assinaturas verificadas");

        byte[] tamperedSignature = Files.readAllBytes(files.resolve("index.asd"));
        tamperedSignature[0] ^= 1;
        check(!CryptoUtils.verify(index, tamperedSignature, admin.certificate().getPublicKey()),
                "assinatura adulterada do index recusada");

        Map<String, Identity> owners = new HashMap<>();
        Map<String, byte[]> plaintextByCode = new HashMap<>();
        for (String line : new String(index, StandardCharsets.US_ASCII).split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            String[] fields = line.trim().split("\\s+");
            check(fields.length == 4, "linha do index com quatro campos");
            Identity owner = identities.get(fields[2]);
            check(owner != null, "dono do arquivo encontrado no pacote");
            byte[] plaintext = openPackageFile(files, fields[0], fields[0] + ".env",
                    owner.privateKey(), owner.certificate().getPublicKey());
            check(plaintext.length > 0,
                    "arquivo do dono decriptado e assinatura verificada: " + fields[0]);
            owners.put(fields[0], owner);
            plaintextByCode.put(fields[0], plaintext);
        }

        for (String line : new String(share, StandardCharsets.US_ASCII).split("\\R")) {
            if (line.isBlank()) {
                continue;
            }
            String[] fields = line.trim().split("\\s+");
            check(fields.length == 3, "linha do share com três campos");
            Identity recipient = identities.get(fields[2]);
            Identity owner = owners.get(fields[0]);
            check(recipient != null && owner != null, "destinatário e dono do share encontrados");
            byte[] sharedPlaintext = openPackageFile(files, fields[0],
                    fields[0] + "." + fields[1] + ".shr",
                    recipient.privateKey(), owner.certificate().getPublicKey());
            check(Arrays.equals(plaintextByCode.get(fields[0]), sharedPlaintext),
                    "arquivo compartilhado decriptado e assinatura verificada: " + fields[0]);
        }
        testPackageWithVault(files, identities, admin, plaintextByCode);
    }

    private static void testPackageWithVault(Path files, Map<String, Identity> identities,
            Identity admin, Map<String, byte[]> plaintextByCode) throws Exception {
        Path databasePath = Files.createTempFile("t3-package-", ".db");
        Path outputFolder = Files.createTempDirectory("t3-package-output-");
        try (Database database = new Database(databasePath)) {
            char[] pin = "13572468".toCharArray();
            byte[] totpSecret = new byte[20];
            new SecureRandom().nextBytes(totpSecret);
            byte[] encryptedTotp = CryptoUtils.encryptAes(
                    new Base32(Base32.Alphabet.BASE32, false, false).toString(totpSecret).getBytes(StandardCharsets.US_ASCII), pin);
            for (Identity identity : identities.values()) {
                int groupId = identity == admin ? Database.ADMIN_GROUP_ID : Database.USER_GROUP_ID;
                database.insertUser(CryptoUtils.extractName(identity.certificate()), identity.email(),
                        groupId, java.util.UUID.randomUUID().toString(),
                        CryptoUtils.generateBcrypt(pin), encryptedTotp, identity.certificatePem(),
                        Files.readAllBytes(identity.encryptedKeyPath()));
            }
            Arrays.fill(pin, '\0');
            Vault vault = new Vault(database);
            int opened = 0;
            for (Identity identity : identities.values()) {
                Database.User user = database.findUser(identity.email());
                Vault.Catalog catalog = vault.listFiles(files, user, admin.privateKey(),
                        admin.certificate());
                for (Vault.FileEntry entry : catalog.allowedFiles()) {
                    boolean owner = entry.owner().equalsIgnoreCase(identity.email());
                    boolean shared = catalog.shares().stream().anyMatch(item ->
                            item.code().equals(entry.code())
                                    && item.authorizedUser().equalsIgnoreCase(identity.email()));
                    if (!owner && !shared) {
                        continue;
                    }
                    Path output = vault.openFile(catalog, entry, user, identity.privateKey(),
                            outputFolder);
                    check(Arrays.equals(plaintextByCode.get(entry.code()), Files.readAllBytes(output)),
                            "listagem e abertura reais: " + entry.code());
                    Files.delete(output);
                    opened++;
                }
            }
            check(opened > 0, "cofre original aberto pelo fluxo de produção");
        } finally {
            Files.deleteIfExists(outputFolder);
            Files.deleteIfExists(databasePath);
        }
    }

    private static byte[] openPackageFile(Path folder, String code, String envelopeName,
            PrivateKey recipientKey, PublicKey signerKey) throws Exception {
        byte[] seed = CryptoUtils.openEnvelope(Files.readAllBytes(folder.resolve(envelopeName)),
                recipientKey);
        byte[] plaintext = CryptoUtils.decryptAes(Files.readAllBytes(folder.resolve(code + ".enc")),
                seed);
        if (!CryptoUtils.verify(plaintext, Files.readAllBytes(folder.resolve(code + ".asd")),
                signerKey)) {
            throw new AssertionError("Assinatura inválida para " + code);
        }
        return plaintext;
    }

    private static void testDatabaseAndVault(Path raiz, Path pastaVault, Path saida) throws Exception {
        Identity admin = createIdentity(raiz, "admin-test", "Administrador Teste",
                "admin@teste.local", "frase-admin-teste".toCharArray());
        Identity owner = createIdentity(raiz, "owner-test", "Dono Teste",
                "owner@teste.local", "frase-owner-teste".toCharArray());
        Identity recipient = createIdentity(raiz, "recipient-test", "Destinatário Teste",
                "recipient@teste.local", "frase-recipient-teste".toCharArray());
        Path databaseFile = raiz.resolve("test.db");
        try (Database banco = new Database(databaseFile)) {
            check(readMessages(databaseFile).equals(expectedOfficialMessages()),
                    "textos dos 64 MIDs correspondem à tabela oficial");
            check(!banco.hasUsers() && banco.findAdministrator() == null,
                    "banco novo não cria usuário padrão");
            banco.logEvent(1001, null, null);
            banco.logEvent(1005, null, null);
            check(hasLogSuffix(banco, 1001, 1005),
                    "primeira execução registra partida para cadastro do administrador");
            char[] adminPin = "13572468".toCharArray();
            char[] ownerPin = "135724689".toCharArray();
            char[] recipientPin = "1357246890".toCharArray();
            long adminUid = insertTestUser(banco, admin, Database.ADMIN_GROUP_ID,
                    "frase-admin-teste".toCharArray(), adminPin);
            long ownerUid = insertTestUser(banco, owner, Database.USER_GROUP_ID,
                    "frase-owner-teste".toCharArray(), ownerPin);
            long recipientUid = insertTestUser(banco, recipient, Database.USER_GROUP_ID,
                    "frase-recipient-teste".toCharArray(), recipientPin);
            check(banco.countUsers() == 3 && banco.findAdministrator().uid() == adminUid,
                    "cadastro transacional e administrador");
            verifyDatabasePasswordAndTotp(banco.findUser(adminUid), adminPin);
            verifyDatabasePasswordAndTotp(banco.findUser(ownerUid), ownerPin);
            verifyDatabasePasswordAndTotp(banco.findUser(recipientUid), recipientPin);
            Database.User administradorCadastrado = banco.findUser(adminUid);
            Database.User destinatarioCadastrado = banco.findUser(recipientUid);
            check(DigitalVault.canRegisterUser(administradorCadastrado)
                    && !DigitalVault.canRegisterUser(destinatarioCadastrado),
                    "somente o grupo Administrador pode cadastrar usuários");
            String detalhesCertificado = DigitalVault.certificateDetails(
                    recipient.certificate(), CryptoUtils.extractName(recipient.certificate()),
                    CryptoUtils.extractEmail(recipient.certificate()));
            check(detalhesCertificado.contains("Versão:")
                    && detalhesCertificado.contains("Série:")
                    && detalhesCertificado.contains("Validade:")
                    && detalhesCertificado.contains("Tipo de assinatura:")
                    && detalhesCertificado.contains("Emissor:")
                    && detalhesCertificado.contains("Sujeito:")
                    && detalhesCertificado.contains("E-mail: " + recipient.email()),
                    "confirmação apresenta os campos exigidos do certificado");
            DigitalVault.RegistrationMaterial material = DigitalVault.loadRegistrationMaterial(
                    banco, adminUid, raiz.resolve("recipient-test-x509.crt").toString(),
                    recipient.encryptedKeyPath().toString(),
                    "frase-recipient-teste".toCharArray());
            check(material.encryptedPrivateKey().length > 0
                    && material.certificate() != null,
                    "cadastro valida o par com desafio aleatório de 10240 bytes");
            check(registrationFailsWith(banco, adminUid,
                    raiz.resolve("certificado-ausente.crt").toString(),
                    recipient.encryptedKeyPath().toString(),
                    "frase-recipient-teste".toCharArray(), 6004),
                    "certificado ausente registra MID 6004");
            check(registrationFailsWith(banco, adminUid,
                    raiz.resolve("recipient-test-x509.crt").toString(),
                    raiz.resolve("chave-ausente.key").toString(),
                    "frase-recipient-teste".toCharArray(), 6005),
                    "chave ausente registra MID 6005");
            check(registrationFailsWith(banco, adminUid,
                    raiz.resolve("recipient-test-x509.crt").toString(),
                    recipient.encryptedKeyPath().toString(),
                    "frase-incorreta".toCharArray(), 6006),
                    "frase incorreta registra MID 6006");
            check(registrationFailsWith(banco, adminUid,
                    raiz.resolve("recipient-test-x509.crt").toString(),
                    owner.encryptedKeyPath().toString(),
                    "frase-owner-teste".toCharArray(), 6007),
                    "par chave/certificado incompatível registra MID 6007");

            banco.logEvent(1001, null, null);
            banco.logEvent(1006, null, null);
            check(hasLogSuffix(banco, 1001, 1006),
                    "execução com usuários registra partida normal");
            check(CryptoUtils.proveKeyPair(DigitalVault.verifyStoredKey(
                    banco, adminUid, banco.findKeyEntry(adminUid), "frase-admin-teste".toCharArray()),
                    admin.certificate().getPublicKey(), 10_240),
                    "segunda execução valida a chave do administrador");
            boolean adminInvalidoRecusado = false;
            try {
                DigitalVault.verifyStoredKey(banco, adminUid, banco.findKeyEntry(adminUid),
                        "frase-incorreta".toCharArray());
            } catch (Exception expected) {
                adminInvalidoRecusado = banco.countUsers() == 3 && hasLogSuffix(banco, 6006)
                        && "Frase secreta inválida.".equals(expected.getMessage());
            }
            check(adminInvalidoRecusado,
                    "frase inválida do administrador encerra a prova sem reinicializar usuários");

            DigitalVault.LoginResult loginInexistente = DigitalVault.identifyUser(
                    banco, "ausente@teste.local");
            DigitalVault.LoginResult loginValido = DigitalVault.identifyUser(
                    banco, recipient.email());
            check(loginInexistente.eventCode() == 2005 && loginInexistente.user() == null
                    && loginValido.eventCode() == 2003
                    && loginValido.user().uid() == recipientUid
                    && hasLogSuffix(banco, 2005, 2003, 2002),
                    "etapa 1 distingue login inexistente e acesso liberado com MIDs oficiais");

            Database.KeyEntry chaveDestinatario = banco.findKeyEntry(recipientUid);
            PrivateKey chaveComprovada = DigitalVault.verifyStoredKey(banco, recipientUid,
                    chaveDestinatario, "frase-recipient-teste".toCharArray());
            check(CryptoUtils.proveKeyPair(chaveComprovada,
                    recipient.certificate().getPublicKey(), 10_240),
                    "Listar comprova novamente a chave do usuário corrente");
            boolean fraseErradaRecusada = false;
            try {
                DigitalVault.verifyStoredKey(banco, recipientUid, chaveDestinatario,
                        "frase-incorreta".toCharArray());
            } catch (Exception expected) {
                fraseErradaRecusada = hasLogSuffix(banco, 6006)
                        && "Frase secreta inválida.".equals(expected.getMessage());
            }
            check(fraseErradaRecusada, "Listar recusa frase incorreta do usuário");
            boolean fraseAdminRecusada = false;
            try {
                DigitalVault.verifyStoredKey(banco, recipientUid, chaveDestinatario,
                        "frase-admin-teste".toCharArray());
            } catch (Exception expected) {
                fraseAdminRecusada = true;
            }
            check(fraseAdminRecusada,
                    "frase retida do administrador não substitui a prova do usuário");
            check(DigitalVault.EXIT_MESSAGE.equals("Pressione o botão Encerrar Sessão ou o botão "
                    + "Encerrar Sistema para confirmar."),
                    "tela de saída usa a frase exata do enunciado");

            createVault(pastaVault, admin, owner, recipient);
            banco.incrementAccessCount(recipientUid);
            banco.incrementQueryCount(recipientUid);
            Database.User usuario = banco.findUser(recipientUid);
            check(usuario.accessCount() == 1 && usuario.queryCount() == 1,
                    "totais de acesso e consulta persistidos por usuário");
            Vault cofre = new Vault(banco);
            Vault.Catalog catalogo = cofre.listFiles(pastaVault, usuario,
                    admin.privateKey(), admin.certificate());
            check(catalogo.allowedFiles().size() == 2, "união de grupo e share");
            Vault.FileEntry compartilhado = catalogo.allowedFiles().stream()
                    .filter(item -> item.code().equals("TST900")).findFirst().orElseThrow();
            Path aberto = cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saida);
            check("arquivo compartilhado independente".equals(Files.readString(aberto)),
                    "abertura por codigo.ID.shr e assinatura do dono");

            Vault.FileEntry somenteGrupo = catalogo.allowedFiles().stream()
                    .filter(item -> item.code().equals("GRP701")).findFirst().orElseThrow();
            boolean grupoFalhouSeguro = false;
            try {
                cofre.openFile(catalogo, somenteGrupo, usuario, recipient.privateKey(), saida);
            } catch (Exception expected) {
                List<Database.LogEntry> logs = banco.listLogs();
                grupoFalhouSeguro = !Files.exists(saida.resolve(somenteGrupo.name()))
                        && logs.get(logs.size() - 1).eventCode() == 7017;
            }
            check(grupoFalhouSeguro, "grupo sem share recebe acesso negado e não gera saída");

            boolean sobrescritaRecusada = false;
            try {
                cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saida);
            } catch (Exception expected) {
                sobrescritaRecusada = "arquivo compartilhado independente".equals(
                        Files.readString(aberto));
            }
            check(sobrescritaRecusada, "arquivo de saída existente não é sobrescrito");
            check(!hasTemporaryOutput(saida),
                    "recusa de sobrescrita não deixa arquivo parcial");

            Path destinoInvalido = raiz.resolve("destination-is-a-file");
            Files.writeString(destinoInvalido, "manter");
            boolean destinoInvalidoRecusado = false;
            try {
                cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(),
                        destinoInvalido);
            } catch (Exception expected) {
                destinoInvalidoRecusado = "manter".equals(Files.readString(destinoInvalido));
            }
            check(destinoInvalidoRecusado,
                    "destino que não é diretório é recusado sem alteração");

            Path cifra = pastaVault.resolve("TST900.enc");
            Path cifraReal = pastaVault.resolve("TST900.enc.real");
            Files.move(cifra, cifraReal);
            boolean linksSimbolicosDisponiveis = true;
            boolean origemSimbolicaRecusada = false;
            try {
                try {
                    Files.createSymbolicLink(cifra, cifraReal.getFileName());
                } catch (java.io.IOException | UnsupportedOperationException | SecurityException error) {
                    linksSimbolicosDisponiveis = false;
                }
                if (linksSimbolicosDisponiveis) {
                    try {
                        cofre.openFile(catalogo, compartilhado, usuario,
                                recipient.privateKey(), raiz.resolve("symbolic-source-output"));
                    } catch (Exception expected) {
                        origemSimbolicaRecusada = true;
                    }
                }
            } finally {
                Files.deleteIfExists(cifra);
                Files.move(cifraReal, cifra);
            }
            if (linksSimbolicosDisponiveis) {
                check(origemSimbolicaRecusada,
                        "link simbólico usado como arquivo do cofre é recusado");

                Path destinoReal = raiz.resolve("real-symbolic-output");
                Path destinoSimbolico = raiz.resolve("symbolic-output");
                Files.createDirectories(destinoReal);
                Files.createSymbolicLink(destinoSimbolico, destinoReal);
                boolean destinoSimbolicoRecusado = false;
                try {
                    cofre.openFile(catalogo, compartilhado, usuario,
                            recipient.privateKey(), destinoSimbolico);
                } catch (Exception expected) {
                    destinoSimbolicoRecusado = !Files.exists(destinoReal.resolve("shared.txt"));
                }
                check(destinoSimbolicoRecusado, "link simbólico usado como destino é recusado");
            } else {
                System.out.println("IGNORADO - Windows não permitiu criar links simbólicos");
            }

            String mensagemSegura = DigitalVault.message(
                    new java.nio.file.NoSuchFileException("C:\\dados-privados\\admin.key"));
            check(!mensagemSegura.contains("dados-privados")
                    && !mensagemSegura.contains("NoSuchFileException")
                    && !mensagemSegura.contains("\n"),
                    "interface não exibe caminho privado nem stack trace");

            Path saidaOwner = raiz.resolve("owner-output");
            Files.createDirectories(saidaOwner);
            Database.User dono = banco.findUser(owner.email());
            Vault.Catalog catalogoDono = cofre.listFiles(pastaVault, dono,
                    admin.privateKey(), admin.certificate());
            Path arquivoDono = cofre.openFile(catalogoDono,
                    catalogoDono.files().get("GRP701"), dono, owner.privateKey(), saidaOwner);
            check("arquivo somente do grupo".equals(Files.readString(arquivoDono)),
                    "abertura pelo dono com .env");

            Database.User administrador = banco.findUser(adminUid);
            Vault.Catalog catalogoAdmin = cofre.listFiles(pastaVault, administrador,
                    admin.privateKey(), admin.certificate());
            boolean negouSemPermissao = false;
            try {
                cofre.openFile(catalogoAdmin, catalogoAdmin.files().get("TST900"),
                        administrador, admin.privateKey(), raiz.resolve("denied-output"));
            } catch (Exception expected) {
                negouSemPermissao = true;
            }
            check(negouSemPermissao, "arquivo sem dono, grupo ou share negado");

            testCorruption(pastaVault.resolve("index.env"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "index.env adulterado recusado");
            testCorruption(pastaVault.resolve("index.enc"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "index.enc adulterado recusado");
            testCorruption(pastaVault.resolve("index.asd"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "index.asd adulterado recusado");
            testCorruption(pastaVault.resolve("share.env"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "share.env adulterado recusado");
            testCorruption(pastaVault.resolve("share.enc"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "share.enc adulterado recusado");
            testCorruption(pastaVault.resolve("share.asd"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "share.asd adulterado recusado");

            Path saidaErros = raiz.resolve("error-output");
            Files.createDirectories(saidaErros);
            testCorruption(pastaVault.resolve("GRP701.env"), () ->
                    cofre.openFile(catalogoDono, catalogoDono.files().get("GRP701"), dono,
                            owner.privateKey(), saidaErros),
                    "envelope .env do dono adulterado recusado");
            testCorruption(pastaVault.resolve("TST900.7.shr"), () ->
                    cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saidaErros),
                    "share de documento adulterado recusado");
            testCorruption(pastaVault.resolve("TST900.enc"), () ->
                    cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saidaErros),
                    "criptograma de documento adulterado recusado");
            testCorruption(pastaVault.resolve("TST900.asd"), () ->
                    cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saidaErros),
                    "assinatura de documento adulterada recusada");
            check(!Files.exists(saidaErros.resolve("shared.txt")),
                    "adulteração não produz texto plano");
            check(!hasTemporaryOutput(saidaErros),
                    "erro de integridade não deixa arquivo temporário");

            byte[] assinaturaOriginal = Files.readAllBytes(pastaVault.resolve("TST900.asd"));
            Files.write(pastaVault.resolve("TST900.asd"), CryptoUtils.sign(
                    "arquivo compartilhado independente".getBytes(StandardCharsets.UTF_8),
                    recipient.privateKey()));
            boolean certificadoErradoRecusado = false;
            try {
                cofre.openFile(catalogo, compartilhado, usuario, recipient.privateKey(), saidaErros);
            } catch (Exception expected) {
                certificadoErradoRecusado = true;
            } finally {
                Files.write(pastaVault.resolve("TST900.asd"), assinaturaOriginal);
            }
            check(certificadoErradoRecusado, "assinatura de não dono recusada");

            Path shareAssinatura = pastaVault.resolve("share.asd");
            Path shareReserva = pastaVault.resolve("share.asd.bak");
            Files.move(shareAssinatura, shareReserva);
            boolean ausenteRecusado;
            try {
                cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate());
                ausenteRecusado = false;
            } catch (Exception expected) {
                List<Database.LogEntry> logs = banco.listLogs();
                ausenteRecusado = logs.get(logs.size() - 1).eventCode() == 7013;
            } finally {
                Files.move(shareReserva, shareAssinatura);
            }
            check(ausenteRecusado, "assinatura share ausente registra MID 7013");

            testMissingFile(pastaVault.resolve("index.enc"), () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    "arquivo exigido do index ausente é recusado");
            testMissingFile(pastaVault.resolve("TST900.7.shr"), () ->
                    cofre.openFile(catalogo, compartilhado, usuario,
                            recipient.privateKey(), saidaErros),
                    "envelope exigido do documento ausente é recusado");

            boolean pastaAusenteRecusada = false;
            try {
                cofre.listFiles(raiz.resolve("pasta-inexistente"), usuario,
                        admin.privateKey(), admin.certificate());
            } catch (Exception expected) {
                List<Database.LogEntry> logs = banco.listLogs();
                pastaAusenteRecusada = logs.get(logs.size() - 1).eventCode() == 7004;
            }
            check(pastaAusenteRecusada, "pasta ausente registra MID 7004");
            boolean pastaVaziaRecusada = false;
            try {
                cofre.listFiles(Path.of(""), usuario, admin.privateKey(), admin.certificate());
            } catch (Exception expected) {
                List<Database.LogEntry> logs = banco.listLogs();
                pastaVaziaRecusada = logs.get(logs.size() - 1).eventCode() == 7004;
            }
            check(pastaVaziaRecusada, "caminho vazio registra MID 7004");

            writeProtectedFile(pastaVault, "index",
                    "LINHA campos-insuficientes\n".getBytes(StandardCharsets.US_ASCII),
                    admin.privateKey(), admin.certificate());
            boolean indiceMalformado = false;
            try {
                cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate());
            } catch (Exception expected) {
                indiceMalformado = true;
            }
            check(indiceMalformado, "índice autenticado malformado recusado");
            createVault(pastaVault, admin, owner, recipient);

            writeProtectedFile(pastaVault, "index", new byte[0], admin.privateKey(),
                    admin.certificate());
            writeProtectedFile(pastaVault, "share", new byte[0], admin.privateKey(),
                    admin.certificate());
            check(cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate())
                    .allowedFiles().isEmpty(), "index e share vazios aceitos");
            createVault(pastaVault, admin, owner, recipient);

            testMetadata(pastaVault, "index", "TST900 shared.txt owner@teste.local OutroGrupo\n\n"
                    .getBytes(StandardCharsets.US_ASCII), admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    true, "linha vazia no index é ignorada");
            testMetadata(pastaVault, "index", ("TST900 shared.txt owner@teste.local OutroGrupo\r\n"
                    + "GRP701 group-only.txt owner@teste.local Usuario\r\n")
                    .getBytes(StandardCharsets.US_ASCII), admin, () -> {
                        Vault.Catalog comCrlf = cofre.listFiles(pastaVault, usuario,
                                admin.privateKey(), admin.certificate());
                        check(comCrlf.allowedFiles().size() == 2
                                && comCrlf.files().get("TST900").group().equals("OutroGrupo"),
                                "index com CRLF produz os mesmos campos");
                    }, true, "index com quebra de linha CRLF é aceito");
            testMetadata(pastaVault, "index", "TST900 a.doc owner@teste.local OutroGrupo\n"
                    .concat("TST900 b.doc owner@teste.local OutroGrupo\n")
                    .getBytes(StandardCharsets.US_ASCII), admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    false, "código duplicado no index recusado");
            testMetadata(pastaVault, "index", "TST900 ../fora.txt owner@teste.local OutroGrupo\n"
                    .getBytes(StandardCharsets.US_ASCII), admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    false, "nome com travessia de diretório recusado");
            testMetadata(pastaVault, "share", "TST900 0 recipient@teste.local\n"
                    .getBytes(StandardCharsets.US_ASCII), admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    false, "ID de share não positivo recusado");
            testMetadata(pastaVault, "share", "INEXISTENTE 2 recipient@teste.local\n"
                    .getBytes(StandardCharsets.US_ASCII), admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    false, "share sem referência no index é recusado");
            testMetadata(pastaVault, "share", ("TST900 7 recipient@teste.local\n"
                    + "INEXISTENTE 2 recipient@teste.local\n").getBytes(StandardCharsets.US_ASCII),
                    admin, () ->
                    cofre.listFiles(pastaVault, usuario, admin.privateKey(), admin.certificate()),
                    false, "share inteiro é recusado quando uma referência não existe");
            testMetadata(pastaVault, "share", ("TST900 2 recipient@teste.local\n"
                    + "TST900 2 owner@teste.local\n").getBytes(StandardCharsets.US_ASCII),
                    admin, () -> cofre.listFiles(pastaVault, usuario,
                            admin.privateKey(), admin.certificate()),
                    false, "ID de share duplicado recusado");
            testMetadata(pastaVault, "index", ("TST900   shared.txt  owner@teste.local OutroGrupo\n"
                    + "GRP701 group-only.txt owner@teste.local Usuario\n")
                    .getBytes(StandardCharsets.US_ASCII), admin, () -> {
                        Vault.Catalog comEspacos = cofre.listFiles(pastaVault, usuario,
                                admin.privateKey(), admin.certificate());
                        check(comEspacos.allowedFiles().size() == 2,
                                "index com espaços e múltiplas linhas produz catálogo");
                    }, true, "index com espaços é aceito");
            Path envelopeDois = pastaVault.resolve("TST900.2.shr");
            Files.copy(pastaVault.resolve("TST900.7.shr"), envelopeDois);
            try {
                testMetadata(pastaVault, "share", "TST900 2 recipient@teste.local\n"
                        .getBytes(StandardCharsets.US_ASCII), admin, () -> {
                            Vault.Catalog segundoShare = cofre.listFiles(pastaVault, usuario,
                                    admin.privateKey(), admin.certificate());
                            Path arquivo = cofre.openFile(segundoShare, compartilhado, usuario,
                                    recipient.privateKey(), raiz.resolve("share-2-output"));
                            check("arquivo compartilhado independente".equals(Files.readString(arquivo)),
                                    "share com ID 2 abre arquivo");
                        }, true, "share com ID 2 é aceito");
            } finally {
                Files.deleteIfExists(envelopeDois);
            }

            banco.logEvent(3001, recipientUid, null);
            check(DigitalVault.recordPasswordFailure(banco, recipientUid) == 1
                    && DigitalVault.recordPasswordFailure(banco, recipientUid) == 2,
                    "primeiro e segundo erros de PIN são consecutivos");
            DigitalVault.recordPasswordSuccess(banco, recipientUid);
            check(banco.findUser(recipientUid).passwordFailures() == 0
                    && hasLogSuffix(banco, 3004, 3005, 3003, 3002),
                    "PIN correto reinicia o contador e encerra a etapa 2");
            banco.logEvent(3001, recipientUid, null);
            check(DigitalVault.recordPasswordFailure(banco, recipientUid) == 1
                    && DigitalVault.recordPasswordFailure(banco, recipientUid) == 2
                    && DigitalVault.recordPasswordFailure(banco, recipientUid) == 3
                    && banco.findUser(recipientUid).lockedUntil() > System.currentTimeMillis()
                    && hasLogSuffix(banco, 3004, 3005, 3006, 3007, 3002),
                    "terceiro erro de PIN bloqueia e registra os MIDs da etapa 2");
            long bloqueio = banco.findUser(recipientUid).lockedUntil()
                    - System.currentTimeMillis();
            check(bloqueio > 115_000L && bloqueio <= 120_000L, "bloqueio de 120 segundos");
            try (Database reaberto = new Database(databaseFile)) {
                check(reaberto.findUser(recipientUid).lockedUntil() == banco.findUser(recipientUid).lockedUntil(),
                        "bloqueio persiste após reabrir o banco");
            }
            DigitalVault.LoginResult loginBloqueado = DigitalVault.identifyUser(
                    banco, recipient.email());
            DigitalVault.LoginResult outroUsuario = DigitalVault.identifyUser(
                    banco, admin.email());
            check(loginBloqueado.eventCode() == 2004
                    && outroUsuario.eventCode() == 2003
                    && hasLogSuffix(banco, 2004, 2003, 2002),
                    "conta bloqueada volta à etapa 1 sem impedir outro usuário");
            try (var conexao = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
                    var statement = conexao.prepareStatement(
                            "UPDATE Usuarios SET bloqueado_ate=? WHERE uid=?")) {
                statement.setLong(1, System.currentTimeMillis() - 1);
                statement.setLong(2, recipientUid);
                statement.executeUpdate();
            }
            DigitalVault.LoginResult loginLiberado = DigitalVault.identifyUser(
                    banco, recipient.email());
            check(loginLiberado.eventCode() == 2003
                    && banco.findUser(recipientUid).lockedUntil() == 0,
                    "bloqueio vencido é liberado pela etapa 1");
            boolean duplicadoRecusado = false;
            try {
                insertTestUser(banco, recipient, Database.USER_GROUP_ID,
                        "frase-recipient-teste".toCharArray());
            } catch (Exception expected) {
                duplicadoRecusado = banco.countUsers() == 3;
            }
            check(duplicadoRecusado, "e-mail duplicado não cria cadastro parcial");
            boolean grupoInvalidoRecusado = false;
            try {
                banco.insertUser("Teste", "novo@teste.local", 999,
                        java.util.UUID.randomUUID().toString(), usuario.passwordHash(),
                        usuario.encryptedTotpSecret(), recipient.certificatePem(),
                        Files.readAllBytes(recipient.encryptedKeyPath()));
            } catch (Exception expected) {
                grupoInvalidoRecusado = banco.countUsers() == 3;
            }
            check(grupoInvalidoRecusado, "grupo inválido desfaz cadastro por transação");
            try (var conexao = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
                    var statement = conexao.createStatement()) {
                statement.executeUpdate("""
                        CREATE TRIGGER fail_keyring BEFORE INSERT ON Chaveiro
                        BEGIN SELECT RAISE(ABORT, 'falha de teste'); END
                        """);
            }
            boolean falhaIntermediariaDesfeita = false;
            try {
                banco.insertUser("Cadastro interrompido", "rollback@teste.local",
                        Database.USER_GROUP_ID, java.util.UUID.randomUUID().toString(),
                        usuario.passwordHash(), usuario.encryptedTotpSecret(),
                        recipient.certificatePem(), Files.readAllBytes(recipient.encryptedKeyPath()));
            } catch (Exception expected) {
                falhaIntermediariaDesfeita = banco.countUsers() == 3
                        && banco.findUser("rollback@teste.local") == null;
            } finally {
                try (var conexao = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
                        var statement = conexao.createStatement()) {
                    statement.executeUpdate("DROP TRIGGER fail_keyring");
                }
            }
            check(falhaIntermediariaDesfeita,
                    "falha no Chaveiro desfaz a inserção anterior em Usuarios");
            banco.logEvent(4001, ownerUid, null);
            check(DigitalVault.recordTokenFailure(banco, ownerUid) == 1
                    && DigitalVault.recordTokenFailure(banco, ownerUid) == 2,
                    "primeiro e segundo erros de TOTP são consecutivos");
            DigitalVault.recordAuthenticationSuccess(banco, ownerUid);
            check(banco.findUser(ownerUid).tokenFailures() == 0
                    && banco.findUser(ownerUid).accessCount() == 1
                    && hasLogSuffix(banco, 4004, 4005, 4003, 4002, 1003),
                    "TOTP correto reinicia contador e inicia a sessão após os dois fatores");
            banco.logEvent(4001, ownerUid, null);
            check(DigitalVault.recordTokenFailure(banco, ownerUid) == 1
                    && DigitalVault.recordTokenFailure(banco, ownerUid) == 2
                    && DigitalVault.recordTokenFailure(banco, ownerUid) == 3
                    && banco.findUser(ownerUid).lockedUntil() > System.currentTimeMillis()
                    && banco.findUser(recipientUid).lockedUntil() == 0
                    && hasLogSuffix(banco, 4004, 4005, 4006, 4007, 4002),
                    "terceiro erro de TOTP bloqueia só a conta e registra os MIDs da etapa 3");

            long horarioFixo = 1_800_000_000_000L;
            banco.clearPasswordFailures(adminUid);
            banco.recordPasswordFailure(adminUid, horarioFixo);
            banco.recordPasswordFailure(adminUid, horarioFixo);
            banco.recordPasswordFailure(adminUid, horarioFixo);
            long expiracaoEsperada = horarioFixo + 120_000L;
            check(banco.findUser(adminUid).lockedUntil() == expiracaoEsperada,
                    "bloqueio usa exatamente 120 segundos do relógio informado");
            try (Database reaberto = new Database(databaseFile)) {
                check(reaberto.findUser(adminUid).lockedUntil() == expiracaoEsperada,
                        "data de expiração permanece após reinicialização");
                reaberto.clearExpiredLock(adminUid, expiracaoEsperada - 1);
                check(reaberto.findUser(adminUid).lockedUntil() == expiracaoEsperada,
                        "bloqueio permanece antes do instante de expiração");
                reaberto.clearExpiredLock(adminUid, expiracaoEsperada);
                check(reaberto.findUser(adminUid).lockedUntil() == 0,
                        "bloqueio termina no instante de expiração");
            }
            banco.logEvent(8002, ownerUid, null);
            DigitalVault.recordSessionEnd(banco, banco.findUser(ownerUid));
            check(hasLogSuffix(banco, 8002, 1004),
                    "encerramento de sessão registra MIDs 8002 e 1004");
            banco.logEvent(8003, ownerUid, null);
            DigitalVault.recordSessionEnd(banco, banco.findUser(ownerUid));
            banco.logEvent(1002, null, null);
            check(hasLogSuffix(banco, 8003, 1004, 1002),
                    "encerramento do sistema registra sessão antes do MID 1002");
            banco.logEvent(7015, recipientUid, "shared.txt");
            List<Database.LogEntry> logs = banco.listLogs();
            Database.LogEntry ultimo = logs.get(logs.size() - 1);
            check(ultimo.eventCode() == 7015 && "shared.txt".equals(ultimo.fileName())
                    && recipient.email().equals(ultimo.login())
                    && ultimo.message().contains("<arq_name>"),
                    "registro guarda MID, usuário e arquivo; texto vem de Mensagens");
        }

        Database conexaoPerdida = new Database(raiz.resolve("lost-connection.db"));
        conexaoPerdida.close();
        boolean logRecusado = false;
        boolean autenticacaoRecusada = false;
        try {
            conexaoPerdida.logEvent(1001, null, null);
        } catch (Exception expected) {
            logRecusado = true;
        }
        try {
            DigitalVault.identifyUser(conexaoPerdida, recipient.email());
        } catch (Exception expected) {
            autenticacaoRecusada = true;
        }
        check(logRecusado && autenticacaoRecusada,
                "conexão perdida impede registro e não autoriza autenticação");

        Path orderDatabase = raiz.resolve("order-test.db");
        try (Database banco = new Database(orderDatabase)) {
            banco.logEvent(1001, null, null);
            banco.logEvent(1002, null, null);
            banco.logEvent(1006, null, null);
        }
        try (var conexao = DriverManager.getConnection("jdbc:sqlite:" + orderDatabase);
                var statement = conexao.prepareStatement(
                        "UPDATE Registros SET data_hora=? WHERE mid=?")) {
            statement.setLong(1, 2_000L);
            statement.setInt(2, 1001);
            statement.executeUpdate();
            statement.setLong(1, 1_000L);
            statement.setInt(2, 1002);
            statement.executeUpdate();
            statement.setLong(1, 1_000L);
            statement.setInt(2, 1006);
            statement.executeUpdate();
        }
        try (Database banco = new Database(orderDatabase)) {
            List<Database.LogEntry> registros = banco.listLogs();
            check(registros.get(0).eventCode() == 1002
                    && registros.get(1).eventCode() == 1006
                    && registros.get(2).eventCode() == 1001,
                    "logs ordenados por data e RID em caso de empate");
        }
    }

    @FunctionalInterface
    private interface Operation {
        void run() throws Exception;
    }

    private static void testCorruption(Path arquivo, Operation operacao, String descricao)
            throws Exception {
        byte[] original = Files.readAllBytes(arquivo);
        byte[] alterado;
        if (arquivo.getFileName().toString().endsWith(".asd")) {
            alterado = original.clone();
            alterado[0] ^= 1;
        } else {
            alterado = java.util.Arrays.copyOf(original, original.length - 1);
        }
        Files.write(arquivo, alterado);
        boolean recusou = false;
        try {
            operacao.run();
        } catch (Exception expected) {
            recusou = true;
        } finally {
            Files.write(arquivo, original);
        }
        check(recusou, descricao);
    }

    private static void testMissingFile(Path arquivo, Operation operacao, String descricao)
            throws Exception {
        Path reserva = arquivo.resolveSibling(arquivo.getFileName() + ".missing");
        Files.move(arquivo, reserva);
        boolean recusou = false;
        try {
            operacao.run();
        } catch (Exception expected) {
            recusou = true;
        } finally {
            Files.move(reserva, arquivo);
        }
        check(recusou, descricao);
    }

    private static void testMetadata(Path pasta, String nome, byte[] texto,
            Identity admin, Operation operacao, boolean deveAceitar, String descricao)
            throws Exception {
        Path cifra = pasta.resolve(nome + ".enc");
        Path envelope = pasta.resolve(nome + ".env");
        Path assinatura = pasta.resolve(nome + ".asd");
        byte[] cifraOriginal = Files.readAllBytes(cifra);
        byte[] envelopeOriginal = Files.readAllBytes(envelope);
        byte[] assinaturaOriginal = Files.readAllBytes(assinatura);
        boolean aceitou;
        try {
            writeProtectedFile(pasta, nome, texto, admin.privateKey(), admin.certificate());
            try {
                operacao.run();
                aceitou = true;
            } catch (Exception expected) {
                aceitou = false;
            }
        } finally {
            Files.write(cifra, cifraOriginal);
            Files.write(envelope, envelopeOriginal);
            Files.write(assinatura, assinaturaOriginal);
        }
        check(aceitou == deveAceitar, descricao);
    }

    private static Map<Integer, String> readMessages(Path databaseFile) throws Exception {
        Map<Integer, String> messages = new java.util.TreeMap<>();
        try (var connection = DriverManager.getConnection("jdbc:sqlite:" + databaseFile);
                var statement = connection.createStatement();
                var result = statement.executeQuery(
                        "SELECT mid,texto FROM Mensagens ORDER BY mid")) {
            while (result.next()) {
                messages.put(result.getInt(1), result.getString(2));
            }
        }
        return messages;
    }

    private static boolean hasLogSuffix(Database database, int... eventCodes) throws Exception {
        List<Database.LogEntry> logs = database.listLogs();
        if (logs.size() < eventCodes.length) {
            return false;
        }
        int offset = logs.size() - eventCodes.length;
        for (int i = 0; i < eventCodes.length; i++) {
            if (logs.get(offset + i).eventCode() != eventCodes[i]) {
                return false;
            }
        }
        return true;
    }

    private static boolean registrationFailsWith(Database database, long actorUid,
            String certificatePath, String privateKeyPath, char[] passphrase, int expectedMid)
            throws Exception {
        try {
            DigitalVault.loadRegistrationMaterial(database, actorUid,
                    certificatePath, privateKeyPath, passphrase);
            return false;
        } catch (Exception expected) {
            return hasLogSuffix(database, expectedMid);
        } finally {
            CryptoUtils.clear(passphrase);
        }
    }

    private static long insertTestUser(Database banco, Identity identidade, int grupo,
            char[] frase) throws Exception {
        return insertTestUser(banco, identidade, grupo, frase, "13572468".toCharArray());
    }

    private static long insertTestUser(Database banco, Identity identidade, int grupo,
            char[] frase, char[] pin) throws Exception {
        byte[] segredo = new byte[20];
        new SecureRandom().nextBytes(segredo);
        String base32 = new Base32(Base32.Alphabet.BASE32, false, false).toString(segredo);
        return banco.insertUser(identidade.certificate().getSubjectX500Principal().getName(),
                identidade.email(), grupo, java.util.UUID.randomUUID().toString(),
                CryptoUtils.generateBcrypt(pin),
                CryptoUtils.encryptAes(base32.getBytes(StandardCharsets.US_ASCII), pin),
                identidade.certificatePem(), Files.readAllBytes(identidade.encryptedKeyPath()));
    }

    private static void verifyDatabasePasswordAndTotp(Database.User user, char[] pin)
            throws Exception {
        javax.swing.JButton[] buttons = new javax.swing.JButton[5];
        for (int i = 0; i < buttons.length; i++) {
            buttons[i] = new javax.swing.JButton();
        }
        List<char[]> pressedPairs = new ArrayList<>();
        for (char digit : pin) {
            boolean recorded = false;
            while (!recorded) {
                DigitalVault.distributeDigits(buttons);
                for (javax.swing.JButton button : buttons) {
                    if (button.getText().charAt(0) == digit) {
                        DigitalVault.recordPressedPair(pressedPairs, button.getText());
                        recorded = true;
                        break;
                    }
                }
            }
        }
        char[] verifiedPin = DigitalVault.findPassword(pressedPairs, user.passwordHash());
        check(Arrays.equals(pin, verifiedPin),
                "PIN de " + pin.length + " dígitos do banco é encontrado com pares regenerados");
        byte[] encodedSecret = CryptoUtils.decryptAes(user.encryptedTotpSecret(), verifiedPin);
        String secret = new String(encodedSecret, StandardCharsets.US_ASCII);
        String code = new TOTP(secret, 30).generateCode();
        check(DigitalVault.verifyToken(user.encryptedTotpSecret(), verifiedPin, code),
                "PIN de " + pin.length + " dígitos abre e valida o TOTP armazenado");
        CryptoUtils.clear(verifiedPin);
        Arrays.fill(encodedSecret, (byte) 0);
    }

    private static Identity createIdentity(Path raiz, String alias, String nome,
            String email, char[] frase) throws Exception {
        Path store = raiz.resolve(alias + ".p12");
        String executavel = System.getProperty("os.name").toLowerCase().contains("win")
                ? "keytool.exe" : "keytool";
        Path keytool = Path.of(System.getProperty("java.home"), "bin", executavel);
        Process processo = new ProcessBuilder(keytool.toString(), "-genkeypair", "-noprompt",
                "-alias", alias, "-keystore", store.toString(), "-storetype", "PKCS12",
                "-storepass", new String(STORE_PASSWORD), "-keypass", new String(STORE_PASSWORD),
                "-keyalg", "RSA", "-keysize", "2048", "-validity", "3650",
                "-dname", "CN=" + nome + ",EMAILADDRESS=" + email + ",O=Teste,C=BR")
                .redirectErrorStream(true).start();
        ByteArrayOutputStream output = new ByteArrayOutputStream();
        processo.getInputStream().transferTo(output);
        if (processo.waitFor() != 0) {
            throw new Exception("keytool falhou: " + output.toString(StandardCharsets.UTF_8));
        }
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        try (var input = Files.newInputStream(store)) {
            keyStore.load(input, STORE_PASSWORD);
        }
        PrivateKey privada = (PrivateKey) keyStore.getKey(alias, STORE_PASSWORD);
        X509Certificate certificado = (X509Certificate) keyStore.getCertificate(alias);
        String pemCert = "-----BEGIN CERTIFICATE-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(certificado.getEncoded())
                + "\n-----END CERTIFICATE-----\n";
        String pemKey = "-----BEGIN PRIVATE KEY-----\n"
                + Base64.getMimeEncoder(64, new byte[] {'\n'}).encodeToString(privada.getEncoded())
                + "\n-----END PRIVATE KEY-----\n";
        Path chave = raiz.resolve(alias + "-pkcs8-aes.key");
        Files.write(chave, CryptoUtils.encryptAes(
                pemKey.getBytes(StandardCharsets.US_ASCII), frase));
        Files.writeString(raiz.resolve(alias + "-x509.crt"), pemCert, StandardCharsets.US_ASCII);
        check(CryptoUtils.proveKeyPair(
                CryptoUtils.loadPrivateKey(chave, frase), certificado.getPublicKey(), 10_240),
                "prova PKCS#8 PEM de " + alias);
        return new Identity(email, privada, certificado, chave,
                pemCert.getBytes(StandardCharsets.US_ASCII));
    }

    private static void createVault(Path pasta, Identity admin, Identity owner,
            Identity recipient) throws Exception {
        byte[] index = ("TST900 shared.txt owner@teste.local OutroGrupo\n"
                + "GRP701 group-only.txt owner@teste.local Usuario\n")
                .getBytes(StandardCharsets.US_ASCII);
        byte[] share = "TST900 7 recipient@teste.local\n".getBytes(StandardCharsets.US_ASCII);
        writeProtectedFile(pasta, "index", index, admin.privateKey(), admin.certificate());
        writeProtectedFile(pasta, "share", share, admin.privateKey(), admin.certificate());
        byte[] seedShared = writeProtectedFile(pasta, "TST900",
                "arquivo compartilhado independente".getBytes(StandardCharsets.UTF_8),
                owner.privateKey(), owner.certificate());
        Files.write(pasta.resolve("TST900.7.shr"),
                createEnvelope(seedShared, recipient.certificate().getPublicKey()));
        writeProtectedFile(pasta, "GRP701", "arquivo somente do grupo".getBytes(StandardCharsets.UTF_8),
                owner.privateKey(), owner.certificate());
    }

    private static byte[] writeProtectedFile(Path pasta, String codigo, byte[] texto,
            PrivateKey assinante, X509Certificate destinatario) throws Exception {
        byte[] semente = new byte[32];
        new SecureRandom().nextBytes(semente);
        Files.write(pasta.resolve(codigo + ".enc"), encryptWithSeed(texto, semente));
        Files.write(pasta.resolve(codigo + ".env"),
                createEnvelope(semente, destinatario.getPublicKey()));
        Files.write(pasta.resolve(codigo + ".asd"), CryptoUtils.sign(texto, assinante));
        return semente;
    }

    private static java.security.KeyPair generateRsaKeyPair() throws Exception {
        java.security.KeyPairGenerator generator = java.security.KeyPairGenerator.getInstance("RSA");
        generator.initialize(2048);
        return generator.generateKeyPair();
    }

    private static byte[] createEnvelope(byte[] seed, PublicKey publicKey) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, publicKey);
        return cipher.doFinal(seed);
    }

    private static byte[] encryptWithSeed(byte[] text, byte[] seed) throws Exception {
        javax.crypto.Cipher cipher = javax.crypto.Cipher.getInstance("AES/ECB/PKCS5Padding");
        cipher.init(javax.crypto.Cipher.ENCRYPT_MODE, CryptoUtils.generateAesKey(seed));
        return cipher.doFinal(text);
    }

    private static X509Certificate loadCertificate(Path file) throws Exception {
        return CryptoUtils.loadCertificate(Files.readAllBytes(file));
    }

    private static void cleanKnownFiles(Path raiz, Path cofre, Path saida) throws Exception {
        for (String nome : List.of("admin-test.p12", "owner-test.p12", "recipient-test.p12",
                "admin-test-pkcs8-aes.key", "owner-test-pkcs8-aes.key",
                "recipient-test-pkcs8-aes.key", "admin-test-x509.crt",
                "owner-test-x509.crt", "recipient-test-x509.crt", "test.db")) {
            Files.deleteIfExists(raiz.resolve(nome));
        }
        for (String nome : List.of("index.enc", "index.env", "index.asd", "share.enc",
                "share.env", "share.asd", "TST900.enc", "TST900.env", "TST900.asd",
                "TST900.7.shr", "GRP701.enc", "GRP701.env", "GRP701.asd")) {
            Files.deleteIfExists(cofre.resolve(nome));
        }
        Files.deleteIfExists(saida.resolve("shared.txt"));
        Files.deleteIfExists(saida.resolve("group-only.txt"));
    }

    private static boolean hasTemporaryOutput(Path folder) throws Exception {
        try (var files = Files.list(folder)) {
            return files.anyMatch(path -> path.getFileName().toString().startsWith(".cofre-"));
        }
    }

    private static void check(boolean condicao, String descricao) {
        verificacoes++;
        if (!condicao) {
            throw new AssertionError("Falha: " + descricao);
        }
        System.out.println("OK - " + descricao);
    }
}

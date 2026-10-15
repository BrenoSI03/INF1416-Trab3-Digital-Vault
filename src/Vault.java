import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.LinkOption;
import java.nio.file.Path;
import java.nio.file.StandardOpenOption;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;
import java.text.Normalizer;
import java.util.ArrayList;
import java.util.HashSet;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;
import java.util.Set;

public class Vault {
    public record FileEntry(String code, String name, String owner, String group) {
    }

    public record ShareEntry(String code, int id, String authorizedUser) {
    }

    public record Catalog(Path folder, List<FileEntry> allowedFiles,
            Map<String, FileEntry> files, List<ShareEntry> shares) {
    }

    private final Database banco;

    public Vault(Database banco) {
        this.banco = banco;
    }

    public Catalog listFiles(Path pastaInformada, Database.User usuario,
            PrivateKey privadaAdmin, X509Certificate certificadoAdmin) throws Exception {
        Path pasta;
        try {
            if (pastaInformada == null || pastaInformada.toString().isBlank()) {
                throw new Exception();
            }
            pasta = pastaInformada.toAbsolutePath().normalize();
            if (!Files.isDirectory(pasta, LinkOption.NOFOLLOW_LINKS)) {
                throw new Exception();
            }
        } catch (Exception error) {
            banco.logEvent(7004, usuario.uid(), null);
            throw new Exception("A pasta segura é inválida.");
        }

        byte[] index = openMetadata(pasta, "index", privadaAdmin,
                certificadoAdmin.getPublicKey(), usuario.uid(), 7005, 7006, 7007, 7008);
        Map<String, FileEntry> arquivos = parseIndex(index);

        byte[] share = openMetadata(pasta, "share", privadaAdmin,
                certificadoAdmin.getPublicKey(), usuario.uid(), 7010, 7011, 7012, 7013);
        List<ShareEntry> compartilhamentos = parseShare(share, arquivos);

        List<FileEntry> permitidos = new ArrayList<>();
        for (FileEntry arquivo : arquivos.values()) {
            boolean compartilhado = compartilhamentos.stream().anyMatch(item ->
                    item.code().equals(arquivo.code())
                            && item.authorizedUser().equalsIgnoreCase(usuario.email()));
            if (arquivo.owner().equalsIgnoreCase(usuario.email())
                    || sameGroup(arquivo.group(), usuario.group()) || compartilhado) {
                permitidos.add(arquivo);
            }
        }
        return new Catalog(pasta, List.copyOf(permitidos), Map.copyOf(arquivos),
                List.copyOf(compartilhamentos));
    }

    private byte[] openMetadata(Path pasta, String nome, PrivateKey privada,
            PublicKey publica, long uid, int midDecriptado, int midVerificado,
            int midErroDecriptacao, int midErroAssinatura) throws Exception {
        byte[] texto;
        try {
            byte[] envelope = Files.readAllBytes(safeFile(pasta, nome + ".env"));
            byte[] semente = CryptoUtils.openEnvelope(envelope, privada);
            texto = CryptoUtils.decryptAes(
                    Files.readAllBytes(safeFile(pasta, nome + ".enc")), semente);
            banco.logEvent(midDecriptado, uid, null);
        } catch (Exception error) {
            banco.logEvent(midErroDecriptacao, uid, null);
            throw new Exception("Falha ao decriptar o arquivo " + nome + ".");
        }
        try {
            byte[] assinatura = Files.readAllBytes(safeFile(pasta, nome + ".asd"));
            if (!CryptoUtils.verify(texto, assinatura, publica)) {
                throw new Exception();
            }
            banco.logEvent(midVerificado, uid, null);
            return texto;
        } catch (Exception error) {
            banco.logEvent(midErroAssinatura, uid, null);
            throw new Exception("Assinatura inválida no arquivo " + nome + ".");
        }
    }

    private Map<String, FileEntry> parseIndex(byte[] dados) throws Exception {
        Map<String, FileEntry> resultado = new LinkedHashMap<>();
        for (String linha : asciiLines(dados)) {
            String[] campos = linha.split(" +", -1);
            if (campos.length != 4 || !campos[0].matches("[A-Za-z0-9]+")
                    || !isSafeName(campos[1]) || campos[2].isBlank() || campos[3].isBlank()
                    || resultado.containsKey(campos[0])) {
                throw new Exception("Linha inválida no arquivo index.");
            }
            resultado.put(campos[0], new FileEntry(campos[0], campos[1], campos[2], campos[3]));
        }
        return resultado;
    }

    private List<ShareEntry> parseShare(byte[] dados,
            Map<String, FileEntry> arquivos) throws Exception {
        List<ShareEntry> resultado = new ArrayList<>();
        Set<String> identificadores = new HashSet<>();
        for (String linha : asciiLines(dados)) {
            String[] campos = linha.split(" +", -1);
            int id;
            try {
                id = Integer.parseInt(campos.length > 1 ? campos[1] : "");
            } catch (NumberFormatException error) {
                throw new Exception("ID inválido no arquivo share.");
            }
            String chave = campos[0] + ":" + id;
            if (campos.length != 3 || !campos[0].matches("[A-Za-z0-9]+") || id <= 0
                    || campos[2].isBlank() || !arquivos.containsKey(campos[0])
                    || !identificadores.add(chave)) {
                throw new Exception("Linha inválida no arquivo share.");
            }
            resultado.add(new ShareEntry(campos[0], id, campos[2]));
        }
        return resultado;
    }

    private List<String> asciiLines(byte[] dados) throws Exception {
        for (byte dado : dados) {
            if ((dado & 0x80) != 0 || dado == '\r') {
                throw new Exception("O índice deve usar texto ASCII e linhas separadas por \\n.");
            }
        }
        String texto = new String(dados, StandardCharsets.US_ASCII);
        List<String> linhas = new ArrayList<>();
        if (texto.isEmpty()) {
            return linhas;
        }
        String[] partes = texto.split("\\n", -1);
        for (int i = 0; i < partes.length; i++) {
            if (i == partes.length - 1 && partes[i].isEmpty()) {
                break;
            }
            if (partes[i].isEmpty()) {
                throw new Exception("Linha vazia no índice.");
            }
            linhas.add(partes[i]);
        }
        return linhas;
    }

    public Path openFile(Catalog catalogo, FileEntry selecionado, Database.User usuario,
            PrivateKey privadaUser, Path destino) throws Exception {
        banco.logEvent(7015, usuario.uid(), selecionado.name());
        FileEntry autentico = catalogo.files().get(selecionado.code());
        ShareEntry compartilhamento = autentico == null ? null : catalogo.shares().stream()
                .filter(item -> item.code().equals(autentico.code())
                        && item.authorizedUser().equalsIgnoreCase(usuario.email()))
                .findFirst().orElse(null);
        boolean ehDono = autentico != null && autentico.owner().equalsIgnoreCase(usuario.email());
        boolean permitido = autentico != null && autentico.equals(selecionado)
                && catalogo.allowedFiles().contains(autentico)
                && (ehDono || compartilhamento != null);
        if (!permitido) {
            banco.logEvent(7017, usuario.uid(), selecionado.name());
            throw new Exception("Acesso negado ao arquivo selecionado.");
        }
        banco.logEvent(7016, usuario.uid(), selecionado.name());

        Path envelope;
        if (ehDono) {
            envelope = catalogo.folder().resolve(autentico.code() + ".env");
        } else {
            envelope = catalogo.folder().resolve(
                    autentico.code() + "." + compartilhamento.id() + ".shr");
        }

        byte[] texto;
        try {
            byte[] semente = CryptoUtils.openEnvelope(
                    Files.readAllBytes(safeFile(catalogo.folder(), envelope.getFileName().toString())),
                    privadaUser);
            texto = CryptoUtils.decryptAes(
                    Files.readAllBytes(safeFile(catalogo.folder(), autentico.code() + ".enc")),
                    semente);
            banco.logEvent(7018, usuario.uid(), autentico.name());
        } catch (Exception error) {
            banco.logEvent(7020, usuario.uid(), autentico.name());
            throw new Exception("Falha ao decriptar o arquivo selecionado.");
        }

        try {
            Database.User dono = banco.findUser(autentico.owner());
            Database.KeyEntry chaveDono = dono == null ? null : banco.findKeyEntry(dono.uid());
            if (chaveDono == null) {
                throw new Exception();
            }
            X509Certificate certificadoDono = CryptoUtils.loadCertificate(chaveDono.certificatePem());
            byte[] assinatura = Files.readAllBytes(
                    safeFile(catalogo.folder(), autentico.code() + ".asd"));
            if (!CryptoUtils.verify(texto, assinatura, certificadoDono.getPublicKey())) {
                throw new Exception();
            }
            banco.logEvent(7019, usuario.uid(), autentico.name());
        } catch (Exception error) {
            banco.logEvent(7021, usuario.uid(), autentico.name());
            throw new Exception("Assinatura inválida no arquivo selecionado.");
        }

        if (!isSafeName(autentico.name())) {
            throw new Exception("Nome de saída inseguro.");
        }
        Path pastaDestino = destino.toAbsolutePath().normalize();
        if (Files.exists(pastaDestino) && Files.isSymbolicLink(pastaDestino)) {
            throw new Exception("A pasta de destino não pode ser um link simbólico.");
        }
        Files.createDirectories(pastaDestino);
        Path saida = pastaDestino.resolve(autentico.name()).normalize();
        if (!saida.getParent().equals(pastaDestino) || Files.exists(saida)) {
            throw new Exception("O arquivo de saída já existe ou possui nome inválido.");
        }
        Path temporario = Files.createTempFile(pastaDestino, ".cofre-", ".tmp");
        try {
            Files.write(temporario, texto, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(temporario, saida);
        } finally {
            Files.deleteIfExists(temporario);
        }
        return saida;
    }

    private Path safeFile(Path pasta, String nome) throws Exception {
        Path caminho = pasta.resolve(nome).normalize();
        if (!caminho.getParent().equals(pasta) || Files.isSymbolicLink(caminho)
                || !Files.isRegularFile(caminho, LinkOption.NOFOLLOW_LINKS)) {
            throw new Exception("Arquivo ausente ou inseguro: " + nome);
        }
        return caminho;
    }

    private boolean isSafeName(String nome) {
        if (nome == null || nome.isBlank() || nome.equals(".") || nome.equals("..")) {
            return false;
        }
        Path path = Path.of(nome);
        return path.getNameCount() == 1 && path.getFileName().toString().equals(nome)
                && !nome.contains("/") && !nome.contains("\\");
    }

    private boolean sameGroup(String primeiro, String segundo) {
        String a = Normalizer.normalize(primeiro, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        String b = Normalizer.normalize(segundo, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        return a.equalsIgnoreCase(b);
    }
}

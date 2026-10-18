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

    private final Database database;

    public Vault(Database database) {
        this.database = database;
    }

    public Catalog listFiles(Path informedFolder, Database.User user,
            PrivateKey adminPrivateKey, X509Certificate adminCertificate) throws Exception {
        Path folder;
        try {
            if (informedFolder == null || informedFolder.toString().isBlank()) {
                throw new Exception();
            }
            folder = informedFolder.toAbsolutePath().normalize();
            if (!Files.isDirectory(folder, LinkOption.NOFOLLOW_LINKS)) {
                throw new Exception();
            }
        } catch (Exception error) {
            database.logEvent(7004, user.uid(), null);
            throw new Exception("A pasta segura é inválida.");
        }

        byte[] index = openMetadata(folder, "index", adminPrivateKey,
                adminCertificate.getPublicKey(), user.uid(), 7005, 7006, 7007, 7008);
        Map<String, FileEntry> files = parseIndex(index);

        byte[] share = openMetadata(folder, "share", adminPrivateKey,
                adminCertificate.getPublicKey(), user.uid(), 7010, 7011, 7012, 7013);
        List<ShareEntry> shares = parseShare(share, files);

        List<FileEntry> allowed = new ArrayList<>();
        for (FileEntry file : files.values()) {
            boolean shared = shares.stream().anyMatch(item ->
                    item.code().equals(file.code())
                            && item.authorizedUser().equalsIgnoreCase(user.email()));
            if (file.owner().equalsIgnoreCase(user.email())
                    || sameGroup(file.group(), user.group()) || shared) {
                allowed.add(file);
            }
        }
        return new Catalog(folder, List.copyOf(allowed), Map.copyOf(files),
                List.copyOf(shares));
    }

    private byte[] openMetadata(Path folder, String name, PrivateKey privateKey,
            PublicKey publicKey, long uid, int decryptedEvent, int verifiedEvent,
            int decryptErrorEvent, int signatureErrorEvent) throws Exception {
        byte[] text;
        try {
            byte[] envelope = Files.readAllBytes(safeFile(folder, name + ".env"));
            byte[] seed = CryptoUtils.openEnvelope(envelope, privateKey);
            text = CryptoUtils.decryptAes(
                    Files.readAllBytes(safeFile(folder, name + ".enc")), seed);
            database.logEvent(decryptedEvent, uid, null);
        } catch (Exception error) {
            database.logEvent(decryptErrorEvent, uid, null);
            throw new Exception("Falha ao decriptar o arquivo " + name + ".");
        }
        try {
            byte[] signature = Files.readAllBytes(safeFile(folder, name + ".asd"));
            if (!CryptoUtils.verify(text, signature, publicKey)) {
                throw new Exception();
            }
            database.logEvent(verifiedEvent, uid, null);
            return text;
        } catch (Exception error) {
            database.logEvent(signatureErrorEvent, uid, null);
            throw new Exception("Assinatura inválida no arquivo " + name + ".");
        }
    }

    private Map<String, FileEntry> parseIndex(byte[] data) throws Exception {
        Map<String, FileEntry> result = new LinkedHashMap<>();
        for (String line : asciiLines(data)) {
            String[] fields = line.split(" +", -1);
            if (fields.length != 4 || !fields[0].matches("[A-Za-z0-9]+")
                    || !isSafeName(fields[1]) || fields[2].isBlank() || fields[3].isBlank()
                    || result.containsKey(fields[0])) {
                throw new Exception("Linha inválida no arquivo index.");
            }
            result.put(fields[0], new FileEntry(fields[0], fields[1], fields[2], fields[3]));
        }
        return result;
    }

    private List<ShareEntry> parseShare(byte[] data,
            Map<String, FileEntry> files) throws Exception {
        List<ShareEntry> result = new ArrayList<>();
        Set<String> identifiers = new HashSet<>();
        for (String line : asciiLines(data)) {
            String[] fields = line.split(" +", -1);
            int id;
            try {
                id = Integer.parseInt(fields.length > 1 ? fields[1] : "");
            } catch (NumberFormatException error) {
                throw new Exception("ID inválido no arquivo share.");
            }
            String key = fields[0] + ":" + id;
            if (fields.length != 3 || !fields[0].matches("[A-Za-z0-9]+") || id <= 0
                    || fields[2].isBlank() || !identifiers.add(key)) {
                throw new Exception("Linha inválida no arquivo share.");
            }
            if (files.containsKey(fields[0])) {
                result.add(new ShareEntry(fields[0], id, fields[2]));
            }
        }
        return result;
    }

    private List<String> asciiLines(byte[] data) throws Exception {
        for (byte value : data) {
            if ((value & 0x80) != 0) {
                throw new Exception("O índice deve usar texto ASCII.");
            }
        }
        String text = new String(data, StandardCharsets.US_ASCII);
        List<String> lines = new ArrayList<>();
        for (String line : text.split("\n")) {
            line = line.strip();
            if (!line.isEmpty()) {
                lines.add(line);
            }
        }
        return lines;
    }

    public Path openFile(Catalog catalog, FileEntry selected, Database.User user,
            PrivateKey userPrivateKey, Path destination) throws Exception {
        database.logEvent(7015, user.uid(), selected.name());
        FileEntry file = catalog.files().get(selected.code());
        ShareEntry share = file == null ? null : catalog.shares().stream()
                .filter(item -> item.code().equals(file.code())
                        && item.authorizedUser().equalsIgnoreCase(user.email()))
                .findFirst().orElse(null);
        boolean isOwner = file != null && file.owner().equalsIgnoreCase(user.email());
        // O mesmo grupo permite listar, mas só o dono (.env) e o destinatário (.shr) têm envelope.
        boolean allowed = isOwner || share != null;
        if (!allowed) {
            database.logEvent(7017, user.uid(), selected.name());
            throw new Exception("Acesso negado ao arquivo selecionado.");
        }
        database.logEvent(7016, user.uid(), selected.name());

        Path envelope;
        if (isOwner) {
            envelope = catalog.folder().resolve(file.code() + ".env");
        } else {
            envelope = catalog.folder().resolve(file.code() + "." + share.id() + ".shr");
        }

        byte[] text;
        try {
            byte[] seed = CryptoUtils.openEnvelope(
                    Files.readAllBytes(safeFile(catalog.folder(), envelope.getFileName().toString())),
                    userPrivateKey);
            text = CryptoUtils.decryptAes(
                    Files.readAllBytes(safeFile(catalog.folder(), file.code() + ".enc")),
                    seed);
            database.logEvent(7018, user.uid(), file.name());
        } catch (Exception error) {
            database.logEvent(7020, user.uid(), file.name());
            throw new Exception("Falha ao decriptar o arquivo selecionado.");
        }

        try {
            Database.User owner = database.findUser(file.owner());
            Database.KeyEntry ownerKey = owner == null ? null : database.findKeyEntry(owner.uid());
            if (ownerKey == null) {
                throw new Exception();
            }
            X509Certificate ownerCertificate = CryptoUtils.loadCertificate(ownerKey.certificatePem());
            byte[] signature = Files.readAllBytes(
                    safeFile(catalog.folder(), file.code() + ".asd"));
            if (!CryptoUtils.verify(text, signature, ownerCertificate.getPublicKey())) {
                throw new Exception();
            }
            database.logEvent(7019, user.uid(), file.name());
        } catch (Exception error) {
            database.logEvent(7021, user.uid(), file.name());
            throw new Exception("Assinatura inválida no arquivo selecionado.");
        }

        Path outputFolder = destination.toAbsolutePath().normalize();
        if (Files.exists(outputFolder) && Files.isSymbolicLink(outputFolder)) {
            throw new Exception("A pasta de destino não pode ser um link simbólico.");
        }
        Files.createDirectories(outputFolder);
        Path output = outputFolder.resolve(file.name()).normalize();
        if (!output.getParent().equals(outputFolder) || Files.exists(output)) {
            throw new Exception("O arquivo de saída já existe ou possui nome inválido.");
        }
        Path temporary = Files.createTempFile(outputFolder, ".cofre-", ".tmp");
        try {
            Files.write(temporary, text, StandardOpenOption.TRUNCATE_EXISTING);
            Files.move(temporary, output);
        } finally {
            Files.deleteIfExists(temporary);
        }
        return output;
    }

    private Path safeFile(Path folder, String name) throws Exception {
        Path path = folder.resolve(name).normalize();
        if (!path.getParent().equals(folder) || Files.isSymbolicLink(path)
                || !Files.isRegularFile(path, LinkOption.NOFOLLOW_LINKS)) {
            throw new Exception("Arquivo ausente ou inseguro: " + name);
        }
        return path;
    }

    private boolean isSafeName(String name) {
        if (name == null || name.isBlank() || name.equals(".") || name.equals("..")) {
            return false;
        }
        Path path = Path.of(name);
        return path.getNameCount() == 1 && path.getFileName().toString().equals(name)
                && !name.contains("/") && !name.contains("\\");
    }

    // O index é ASCII: o grupo "Usuário" do banco aparece como "usuario" no arquivo.
    private boolean sameGroup(String first, String second) {
        String a = Normalizer.normalize(first, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        String b = Normalizer.normalize(second, Normalizer.Form.NFD)
                .replaceAll("\\p{M}", "");
        return a.equalsIgnoreCase(b);
    }
}

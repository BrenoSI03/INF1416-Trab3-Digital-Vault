import java.nio.file.Path;
import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.sql.Statement;
import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

public class Database implements AutoCloseable {
    public static final int ADMIN_GROUP_ID = 1;
    public static final int USER_GROUP_ID = 2;

    public record User(long uid, String name, String email, int gid, String group,
            String passwordHash, byte[] encryptedTotpSecret, long lockedUntil,
            int passwordFailures, int tokenFailures, int accessCount, int queryCount,
            String keyId) {
        public boolean isAdministrator() {
            return gid == ADMIN_GROUP_ID;
        }
    }

    public record KeyEntry(String keyId, long uid, byte[] certificatePem,
            byte[] encryptedPrivateKey) {
    }

    public record LogEntry(long recordId, long timestamp, int eventCode, String message,
            String login, String fileName) {
    }

    private final Connection conexao;

    public Database(Path arquivo) throws Exception {
        Class.forName("org.sqlite.JDBC");
        conexao = DriverManager.getConnection("jdbc:sqlite:" + arquivo.toAbsolutePath());
        try (Statement statement = conexao.createStatement()) {
            statement.execute("PRAGMA foreign_keys = ON");
            statement.execute("PRAGMA busy_timeout = 5000");
        }
        createSchema();
    }

    private void createSchema() throws SQLException {
        try (Statement statement = conexao.createStatement()) {
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS Grupos (
                        gid INTEGER PRIMARY KEY,
                        nome TEXT NOT NULL UNIQUE
                    )""");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS Usuarios (
                        uid INTEGER PRIMARY KEY AUTOINCREMENT,
                        nome TEXT NOT NULL,
                        email TEXT NOT NULL UNIQUE COLLATE NOCASE,
                        gid INTEGER NOT NULL REFERENCES Grupos(gid),
                        kid TEXT NOT NULL UNIQUE,
                        hash_senha TEXT NOT NULL CHECK(length(hash_senha) = 60),
                        segredo_totp BLOB NOT NULL,
                        bloqueado_ate INTEGER NOT NULL DEFAULT 0,
                        erros_senha INTEGER NOT NULL DEFAULT 0,
                        erros_token INTEGER NOT NULL DEFAULT 0,
                        acessos INTEGER NOT NULL DEFAULT 0,
                        consultas INTEGER NOT NULL DEFAULT 0,
                        FOREIGN KEY(kid) REFERENCES Chaveiro(kid) DEFERRABLE INITIALLY DEFERRED
                    )""");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS Chaveiro (
                        kid TEXT PRIMARY KEY,
                        uid INTEGER NOT NULL UNIQUE REFERENCES Usuarios(uid),
                        certificado_pem BLOB NOT NULL,
                        chave_privada_cifrada BLOB NOT NULL
                    )""");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS Mensagens (
                        mid INTEGER PRIMARY KEY,
                        texto TEXT NOT NULL
                    )""");
            statement.executeUpdate("""
                    CREATE TABLE IF NOT EXISTS Registros (
                        rid INTEGER PRIMARY KEY AUTOINCREMENT,
                        data_hora INTEGER NOT NULL,
                        mid INTEGER NOT NULL REFERENCES Mensagens(mid),
                        uid INTEGER REFERENCES Usuarios(uid),
                        arquivo TEXT
                    )""");
        }
        insertSeedData();
    }

    private void insertSeedData() throws SQLException {
        try (PreparedStatement grupo = conexao.prepareStatement(
                "INSERT OR IGNORE INTO Grupos(gid, nome) VALUES(?, ?)")) {
            grupo.setInt(1, ADMIN_GROUP_ID);
            grupo.setString(2, "Administrador");
            grupo.executeUpdate();
            grupo.setInt(1, USER_GROUP_ID);
            grupo.setString(2, "Usuário");
            grupo.executeUpdate();
        }
        try (PreparedStatement mensagem = conexao.prepareStatement(
                "INSERT INTO Mensagens(mid, texto) VALUES(?, ?) "
                        + "ON CONFLICT(mid) DO UPDATE SET texto=excluded.texto")) {
            for (Map.Entry<Integer, String> item : officialMessages().entrySet()) {
                mensagem.setInt(1, item.getKey());
                mensagem.setString(2, item.getValue());
                mensagem.addBatch();
            }
            mensagem.executeBatch();
        }
    }

    private static Map<Integer, String> officialMessages() {
        Map<Integer, String> mensagens = new LinkedHashMap<>();
        mensagens.put(1001, "Sistema iniciado.");
        mensagens.put(1002, "Sistema encerrado.");
        mensagens.put(1003, "Sessão iniciada para <login_name>.");
        mensagens.put(1004, "Sessão encerrada para <login_name>.");
        mensagens.put(1005, "Partida do sistema iniciada para cadastro do administrador.");
        mensagens.put(1006, "Partida do sistema iniciada para operação normal pelos usuários.");
        mensagens.put(2001, "Autenticação etapa 1 iniciada.");
        mensagens.put(2002, "Autenticação etapa 1 encerrada.");
        mensagens.put(2003, "Login name <login_name> identificado com acesso liberado.");
        mensagens.put(2004, "Login name <login_name> identificado com acesso bloqueado.");
        mensagens.put(2005, "Login name <login_name> não identificado.");
        mensagens.put(3001, "Autenticação etapa 2 iniciada para <login_name>.");
        mensagens.put(3002, "Autenticação etapa 2 encerrada para <login_name>.");
        mensagens.put(3003, "Senha pessoal verificada positivamente para <login_name>.");
        mensagens.put(3004, "Primeiro erro da senha pessoal contabilizado para <login_name>.");
        mensagens.put(3005, "Segundo erro da senha pessoal contabilizado para <login_name>.");
        mensagens.put(3006, "Terceiro erro da senha pessoal contabilizado para <login_name>.");
        mensagens.put(3007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 2.");
        mensagens.put(4001, "Autenticação etapa 3 iniciada para <login_name>.");
        mensagens.put(4002, "Autenticação etapa 3 encerrada para <login_name>.");
        mensagens.put(4003, "Token verificado positivamente para <login_name>.");
        mensagens.put(4004, "Primeiro erro de token contabilizado para <login_name>.");
        mensagens.put(4005, "Segundo erro de token contabilizado para <login_name>.");
        mensagens.put(4006, "Terceiro erro de token contabilizado para <login_name>.");
        mensagens.put(4007, "Acesso do usuario <login_name> bloqueado pela autenticação etapa 3.");
        mensagens.put(5001, "Tela principal apresentada para <login_name>.");
        mensagens.put(5002, "Opção 1 do menu principal selecionada por <login_name>.");
        mensagens.put(5003, "Opção 2 do menu principal selecionada por <login_name>.");
        mensagens.put(5004, "Opção 3 do menu principal selecionada por <login_name>.");
        mensagens.put(6001, "Tela de cadastro apresentada para <login_name>.");
        mensagens.put(6002, "Botão cadastrar pressionado por <login_name>.");
        mensagens.put(6003, "Senha pessoal inválida fornecida por <login_name>.");
        mensagens.put(6004, "Caminho do certificado digital inválido fornecido por <login_name>.");
        mensagens.put(6005, "Chave privada verificada negativamente para <login_name> (caminho inválido).");
        mensagens.put(6006, "Chave privada verificada negativamente para <login_name> (frase secreta inválida).");
        mensagens.put(6007, "Chave privada verificada negativamente para <login_name> (assinatura digital inválida).");
        mensagens.put(6008, "Confirmação de dados aceita por <login_name>.");
        mensagens.put(6009, "Confirmação de dados rejeitada por <login_name>.");
        mensagens.put(6010, "Botão voltar de cadastro para o menu principal pressionado por <login_name>.");
        mensagens.put(7001, "Tela de consulta de arquivos secretos apresentada para <login_name>.");
        mensagens.put(7002, "Botão voltar de consulta para o menu principal pressionado por <login_name>.");
        mensagens.put(7003, "Botão Listar de consulta pressionado por <login_name>.");
        mensagens.put(7004, "Caminho de pasta inválido fornecido por <login_name>.");
        mensagens.put(7005, "Arquivo de índice decriptado com sucesso para <login_name>.");
        mensagens.put(7006, "Arquivo de índice verificado (integridade e autenticidade) com sucesso para <login_name>.");
        mensagens.put(7007, "Falha na decriptação do arquivo de índice para <login_name>.");
        mensagens.put(7008, "Falha na verificação (integridade e autenticidade) do arquivo de índice para <login_name>.");
        mensagens.put(7009, "Lista de arquivos presentes no índice apresentada para <login_name>.");
        mensagens.put(7010, "Arquivo de share decriptado com sucesso para <login_name>.");
        mensagens.put(7011, "Arquivo de share verificado (integridade e autenticidade) com sucesso para <login_name>.");
        mensagens.put(7012, "Falha na decriptação do arquivo de share para <login_name>.");
        mensagens.put(7013, "Falha na verificação (integridade e autenticidade) do arquivo de share para <login_name>.");
        mensagens.put(7014, "Lista de arquivos presentes no share apresentada para <login_name>.");
        mensagens.put(7015, "Arquivo <arq_name> selecionado por <login_name> para decriptação.");
        mensagens.put(7016, "Acesso permitido ao arquivo <arq_name> para <login_name>.");
        mensagens.put(7017, "Acesso negado ao arquivo <arq_name> para <login_name>.");
        mensagens.put(7018, "Arquivo <arq_name> decriptado com sucesso para <login_name>.");
        mensagens.put(7019, "Arquivo <arq_name> verificado (integridade e autenticidade) com sucesso para <login_name>.");
        mensagens.put(7020, "Falha na decriptação do arquivo <arq_name> para <login_name>.");
        mensagens.put(7021, "Falha na verificação (integridade e autenticidade) do arquivo <arq_name> para <login_name>.");
        mensagens.put(8001, "Tela de saída apresentada para <login_name>.");
        mensagens.put(8002, "Botão encerrar sessão pressionado por <login_name>.");
        mensagens.put(8003, "Botão encerrar sistema pressionado por <login_name>.");
        mensagens.put(8004, "Botão voltar de sair para o menu principal pressionado por <login_name>.");
        return mensagens;
    }

    public int countMessages() throws SQLException {
        try (Statement statement = conexao.createStatement();
                ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM Mensagens")) {
            return result.getInt(1);
        }
    }

    public boolean hasUsers() throws SQLException {
        return countUsers() > 0;
    }

    public int countUsers() throws SQLException {
        try (Statement statement = conexao.createStatement();
                ResultSet result = statement.executeQuery("SELECT COUNT(*) FROM Usuarios")) {
            return result.getInt(1);
        }
    }

    public User findAdministrator() throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "SELECT u.*, g.nome grupo FROM Usuarios u JOIN Grupos g ON g.gid=u.gid "
                        + "WHERE u.gid=? ORDER BY u.uid LIMIT 1")) {
            statement.setInt(1, ADMIN_GROUP_ID);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? readUser(result) : null;
            }
        }
    }

    public User findUser(String email) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "SELECT u.*, g.nome grupo FROM Usuarios u JOIN Grupos g ON g.gid=u.gid WHERE u.email=?")) {
            statement.setString(1, email);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? readUser(result) : null;
            }
        }
    }

    public User findUser(long uid) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "SELECT u.*, g.nome grupo FROM Usuarios u JOIN Grupos g ON g.gid=u.gid WHERE u.uid=?")) {
            statement.setLong(1, uid);
            try (ResultSet result = statement.executeQuery()) {
                return result.next() ? readUser(result) : null;
            }
        }
    }

    private User readUser(ResultSet result) throws SQLException {
        return new User(result.getLong("uid"), result.getString("nome"),
                result.getString("email"), result.getInt("gid"), result.getString("grupo"),
                result.getString("hash_senha"), result.getBytes("segredo_totp"),
                result.getLong("bloqueado_ate"), result.getInt("erros_senha"),
                result.getInt("erros_token"), result.getInt("acessos"),
                result.getInt("consultas"), result.getString("kid"));
    }

    public KeyEntry findKeyEntry(long uid) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "SELECT * FROM Chaveiro WHERE uid=?")) {
            statement.setLong(1, uid);
            try (ResultSet result = statement.executeQuery()) {
                if (!result.next()) {
                    return null;
                }
                return new KeyEntry(result.getString("kid"), result.getLong("uid"),
                        result.getBytes("certificado_pem"), result.getBytes("chave_privada_cifrada"));
            }
        }
    }

    public long insertUser(String nome, String email, int gid, String kid,
            String hashSenha, byte[] segredoTotp, byte[] certificadoPem,
            byte[] chavePrivadaCifrada) throws SQLException {
        boolean autoCommit = conexao.getAutoCommit();
        conexao.setAutoCommit(false);
        try {
            long uid;
            try (PreparedStatement usuario = conexao.prepareStatement("""
                    INSERT INTO Usuarios(nome,email,gid,kid,hash_senha,segredo_totp)
                    VALUES(?,?,?,?,?,?)""", Statement.RETURN_GENERATED_KEYS)) {
                usuario.setString(1, nome);
                usuario.setString(2, email);
                usuario.setInt(3, gid);
                usuario.setString(4, kid);
                usuario.setString(5, hashSenha);
                usuario.setBytes(6, segredoTotp);
                usuario.executeUpdate();
                try (ResultSet keys = usuario.getGeneratedKeys()) {
                    if (!keys.next()) {
                        throw new SQLException("UID não foi gerado.");
                    }
                    uid = keys.getLong(1);
                }
            }
            try (PreparedStatement chaveiro = conexao.prepareStatement(
                    "INSERT INTO Chaveiro(kid,uid,certificado_pem,chave_privada_cifrada) VALUES(?,?,?,?)")) {
                chaveiro.setString(1, kid);
                chaveiro.setLong(2, uid);
                chaveiro.setBytes(3, certificadoPem);
                chaveiro.setBytes(4, chavePrivadaCifrada);
                chaveiro.executeUpdate();
            }
            conexao.commit();
            return uid;
        } catch (SQLException error) {
            conexao.rollback();
            throw error;
        } finally {
            conexao.setAutoCommit(autoCommit);
        }
    }

    public int recordPasswordFailure(long uid) throws SQLException {
        return recordPasswordFailure(uid, System.currentTimeMillis());
    }

    int recordPasswordFailure(long uid, long currentTimeMillis) throws SQLException {
        int erros = findUser(uid).passwordFailures() + 1;
        boolean bloquear = erros >= 3;
        try (PreparedStatement statement = conexao.prepareStatement(
                "UPDATE Usuarios SET erros_senha=?, bloqueado_ate=? WHERE uid=?")) {
            statement.setInt(1, bloquear ? 0 : erros);
            statement.setLong(2, bloquear ? currentTimeMillis + 120_000L : 0);
            statement.setLong(3, uid);
            statement.executeUpdate();
        }
        return erros;
    }

    public int recordTokenFailure(long uid) throws SQLException {
        return recordTokenFailure(uid, System.currentTimeMillis());
    }

    int recordTokenFailure(long uid, long currentTimeMillis) throws SQLException {
        int erros = findUser(uid).tokenFailures() + 1;
        boolean bloquear = erros >= 3;
        try (PreparedStatement statement = conexao.prepareStatement(
                "UPDATE Usuarios SET erros_token=?, bloqueado_ate=? WHERE uid=?")) {
            statement.setInt(1, bloquear ? 0 : erros);
            statement.setLong(2, bloquear ? currentTimeMillis + 120_000L : 0);
            statement.setLong(3, uid);
            statement.executeUpdate();
        }
        return erros;
    }

    public void clearPasswordFailures(long uid) throws SQLException {
        updateUser("UPDATE Usuarios SET erros_senha=0 WHERE uid=?", uid);
    }

    public void clearTokenFailures(long uid) throws SQLException {
        updateUser("UPDATE Usuarios SET erros_token=0 WHERE uid=?", uid);
    }

    public void clearExpiredLock(long uid) throws SQLException {
        clearExpiredLock(uid, System.currentTimeMillis());
    }

    void clearExpiredLock(long uid, long currentTimeMillis) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "UPDATE Usuarios SET bloqueado_ate=0 WHERE uid=? AND bloqueado_ate<=?")) {
            statement.setLong(1, uid);
            statement.setLong(2, currentTimeMillis);
            statement.executeUpdate();
        }
    }

    public void incrementAccessCount(long uid) throws SQLException {
        updateUser("UPDATE Usuarios SET acessos=acessos+1 WHERE uid=?", uid);
    }

    public void incrementQueryCount(long uid) throws SQLException {
        updateUser("UPDATE Usuarios SET consultas=consultas+1 WHERE uid=?", uid);
    }

    private void updateUser(String sql, long uid) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(sql)) {
            statement.setLong(1, uid);
            statement.executeUpdate();
        }
    }

    public void logEvent(int mid, Long uid, String arquivo) throws SQLException {
        try (PreparedStatement statement = conexao.prepareStatement(
                "INSERT INTO Registros(data_hora,mid,uid,arquivo) VALUES(?,?,?,?)")) {
            statement.setLong(1, System.currentTimeMillis());
            statement.setInt(2, mid);
            if (uid == null) {
                statement.setNull(3, java.sql.Types.INTEGER);
            } else {
                statement.setLong(3, uid);
            }
            statement.setString(4, arquivo);
            statement.executeUpdate();
        }
    }

    public List<LogEntry> listLogs() throws SQLException {
        List<LogEntry> registros = new ArrayList<>();
        String sql = """
                SELECT r.rid,r.data_hora,r.mid,m.texto,u.email,r.arquivo
                FROM Registros r
                JOIN Mensagens m ON m.mid=r.mid
                LEFT JOIN Usuarios u ON u.uid=r.uid
                ORDER BY r.data_hora ASC,r.rid ASC""";
        try (Statement statement = conexao.createStatement(); ResultSet result = statement.executeQuery(sql)) {
            while (result.next()) {
                registros.add(new LogEntry(result.getLong(1), result.getLong(2), result.getInt(3),
                        result.getString(4), result.getString(5), result.getString(6)));
            }
        }
        return registros;
    }

    @Override
    public void close() throws SQLException {
        conexao.close();
    }
}

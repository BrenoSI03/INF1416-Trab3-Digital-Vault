import java.awt.BorderLayout;
import java.awt.Cursor;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.awt.event.WindowAdapter;
import java.awt.event.WindowEvent;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.sql.SQLException;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;
import java.util.UUID;
import javax.swing.BorderFactory;
import javax.swing.JButton;
import javax.swing.JComboBox;
import javax.swing.JFileChooser;
import javax.swing.JFrame;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JPasswordField;
import javax.swing.JScrollPane;
import javax.swing.JTable;
import javax.swing.JTextField;
import javax.swing.ListSelectionModel;
import javax.swing.SwingUtilities;
import javax.swing.table.DefaultTableModel;
import javax.swing.text.AbstractDocument;
import javax.swing.text.AttributeSet;
import javax.swing.text.BadLocationException;
import javax.swing.text.DocumentFilter;

public class DigitalVault {
    static final String EXIT_MESSAGE = "Pressione o botão Encerrar Sessão ou o botão "
            + "Encerrar Sistema para confirmar.";

    record LoginResult(Database.User user, int eventCode) {
    }

    record RegistrationMaterial(X509Certificate certificate, byte[] certificatePem,
            byte[] encryptedPrivateKey) {
    }

    private final Database database;
    private final Vault vault;
    private final JFrame window = new JFrame("Cofre Digital");
    private char[] adminPassphrase;
    private Database.User currentUser;
    private char[] verifiedPassword;
    private boolean sessionStarted;
    private boolean closed;
    private Vault.Catalog currentCatalog;
    private PrivateKey queryPrivateKey;

    public DigitalVault(Path databaseFile) throws Exception {
        database = new Database(databaseFile);
        vault = new Vault(database);
        window.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        window.setMinimumSize(new Dimension(720, 520));
        window.setLocationRelativeTo(null);
        window.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                shutDown();
            }
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                Path databaseFile = Path.of(args.length == 0 ? "cofre.db" : args[0]);
                new DigitalVault(databaseFile).start();
            } catch (Exception error) {
                JOptionPane.showMessageDialog(null,
                        "Não foi possível iniciar o Cofre Digital: " + message(error),
                        "Erro", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void start() throws Exception {
        database.logEvent(1001, null, null);
        window.setVisible(true);
        if (!database.hasUsers()) {
            database.logEvent(1005, null, null);
            showRegistration(true);
            return;
        }
        database.logEvent(1006, null, null);
        if (!validateInitialAdministrator()) {
            JOptionPane.showMessageDialog(window,
                    "A chave privada do administrador não foi validada. O sistema será encerrado.");
            shutDown();
            return;
        }
        showLogin();
    }

    private boolean validateInitialAdministrator() throws Exception {
        Database.User admin = database.findAdministrator();
        if (admin == null) {
            return false;
        }
        JPasswordField field = new JPasswordField(30);
        int answer = JOptionPane.showConfirmDialog(window, field,
                "Frase secreta da chave do administrador", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (answer != JOptionPane.OK_OPTION) {
            return false;
        }
        char[] passphrase = field.getPassword();
        try {
            verifyStoredKey(database, admin.uid(), database.findKeyEntry(admin.uid()), passphrase);
            adminPassphrase = passphrase.clone();
            return true;
        } catch (Exception error) {
            return false;
        } finally {
            CryptoUtils.clear(passphrase);
        }
    }

    private void showPanel(JPanel panel) {
        window.setContentPane(panel);
        window.pack();
        window.setLocationRelativeTo(null);
        window.revalidate();
    }

    private JPanel createBasePanel(String title) {
        JPanel panel = new JPanel(new BorderLayout(10, 10));
        panel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        JLabel header = new JLabel("<html><h2>" + title + "</h2>"
                + (currentUser == null ? "" : "Login: " + html(currentUser.email())
                        + "<br>Grupo: " + html(currentUser.group())
                        + "<br>Nome: " + html(currentUser.name())) + "</html>");
        panel.add(header, BorderLayout.NORTH);
        return panel;
    }

    private void showLogin() {
        clearVerifiedPassword();
        currentUser = null;
        sessionStarted = false;
        currentCatalog = null;
        queryPrivateKey = null;
        try {
            database.logEvent(2001, null, null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel("Autenticação — etapa 1");
        JPanel center = new JPanel(new GridLayout(0, 1, 8, 8));
        JTextField emailField = new JTextField(35);
        center.add(new JLabel("Login name (e-mail):"));
        center.add(emailField);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton okButton = new JButton("OK");
        JButton clearButton = new JButton("Limpar");
        buttons.add(okButton);
        buttons.add(clearButton);
        center.add(buttons);
        panel.add(center, BorderLayout.CENTER);
        okButton.addActionListener(event -> {
            try {
                LoginResult result = identifyUser(database, emailField.getText().trim());
                if (result.eventCode() == 2005) {
                    showMessage("Login name não identificado.");
                    return;
                }
                if (result.eventCode() == 2004) {
                    showMessage("Acesso bloqueado temporariamente.");
                    return;
                }
                currentUser = result.user();
                showVirtualKeyboard();
            } catch (Exception error) {
                showError(error);
            }
        });
        clearButton.addActionListener(event -> emailField.setText(""));
        showPanel(panel);
        emailField.requestFocusInWindow();
    }

    static LoginResult identifyUser(Database database, String email) throws Exception {
        Database.User user = database.findUser(email);
        if (user == null) {
            database.logEvent(2005, null, null);
            return new LoginResult(null, 2005);
        }
        database.clearExpiredLock(user.uid());
        user = database.findUser(user.uid());
        if (user.lockedUntil() > System.currentTimeMillis()) {
            database.logEvent(2004, user.uid(), null);
            return new LoginResult(user, 2004);
        }
        database.logEvent(2003, user.uid(), null);
        database.logEvent(2002, user.uid(), null);
        return new LoginResult(user, 2003);
    }

    private void showVirtualKeyboard() {
        showVirtualKeyboard(true);
    }

    private void showVirtualKeyboard(boolean logStart) {
        try {
            if (logStart) {
                database.logEvent(3001, currentUser.uid(), null);
            }
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel("Autenticação — etapa 2");
        JPanel center = new JPanel(new BorderLayout(8, 8));
        JLabel counter = new JLabel("Senha pessoal: 0 dígitos informados");
        JPanel keyboard = new JPanel(new GridLayout(1, 5, 8, 8));
        List<char[]> pairs = new ArrayList<>();
        JButton[] keys = new JButton[5];
        for (int i = 0; i < keys.length; i++) {
            JButton key = new JButton();
            keys[i] = key;
            key.addActionListener(event -> {
                if (!recordPressedPair(pairs, key.getText())) {
                    return;
                }
                counter.setText("Senha pessoal: " + pairs.size() + " dígitos informados");
                distributeDigits(keys);
            });
            keyboard.add(key);
        }
        distributeDigits(keys);
        center.add(counter, BorderLayout.NORTH);
        center.add(keyboard, BorderLayout.CENTER);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton okButton = new JButton("OK");
        JButton clearButton = new JButton("Limpar");
        buttons.add(okButton);
        buttons.add(clearButton);
        center.add(buttons, BorderLayout.SOUTH);
        panel.add(center, BorderLayout.CENTER);

        clearButton.addActionListener(event -> {
            pairs.clear();
            counter.setText("Senha pessoal: 0 dígitos informados");
            distributeDigits(keys);
        });
        okButton.addActionListener(event -> {
            okButton.setEnabled(false);
            // Uma senha de 10 dígitos gera até 1024 candidatas no bcrypt, o que pode levar alguns segundos.
            window.setCursor(Cursor.getPredefinedCursor(Cursor.WAIT_CURSOR));
            try {
                char[] password = findPassword(pairs, currentUser.passwordHash());
                if (password == null) {
                    handlePasswordFailure();
                    if (currentUser != null) {
                        okButton.setEnabled(true);
                    }
                    return;
                }
                recordPasswordSuccess(database, currentUser.uid());
                verifiedPassword = password;
                showToken();
            } catch (Exception error) {
                showError(error);
                okButton.setEnabled(true);
            } finally {
                window.setCursor(Cursor.getDefaultCursor());
            }
        });
        showPanel(panel);
    }

    static void distributeDigits(JButton[] keys) {
        List<Integer> digits = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            digits.add(i);
        }
        Collections.shuffle(digits, new SecureRandom());
        for (int i = 0; i < 5; i++) {
            keys[i].setText(digits.get(i * 2) + " " + digits.get(i * 2 + 1));
        }
    }

    static boolean recordPressedPair(List<char[]> pairs, String buttonText) {
        if (pairs.size() >= 10) {
            return false;
        }
        if (buttonText == null || !buttonText.matches("[0-9] [0-9]")) {
            throw new IllegalArgumentException("Par de dígitos inválido.");
        }
        pairs.add(new char[] {buttonText.charAt(0), buttonText.charAt(2)});
        return true;
    }

    static char[] findPassword(List<char[]> pairs, String hash) {
        if (pairs.size() < 8 || pairs.size() > 10) {
            return null;
        }
        char[] candidate = new char[pairs.size()];
        return findPassword(pairs, hash, candidate, 0);
    }

    private static char[] findPassword(List<char[]> pairs, String hash,
            char[] candidate, int position) {
        if (position == pairs.size()) {
            return CryptoUtils.verifyBcrypt(hash, candidate) ? candidate.clone() : null;
        }
        for (char digit : pairs.get(position)) {
            candidate[position] = digit;
            char[] found = findPassword(pairs, hash, candidate, position + 1);
            if (found != null) {
                CryptoUtils.clear(candidate);
                return found;
            }
        }
        candidate[position] = '\0';
        return null;
    }

    private void handlePasswordFailure() throws Exception {
        int failures = recordPasswordFailure(database, currentUser.uid());
        if (failures >= 3) {
            showMessage("Terceiro erro. O acesso foi bloqueado por 2 minutos.");
            showLogin();
        } else {
            showMessage("Senha pessoal inválida. Erro " + failures + " de 3.");
            showVirtualKeyboard(false);
        }
    }

    static void recordPasswordSuccess(Database database, long uid) throws Exception {
        database.clearPasswordFailures(uid);
        database.logEvent(3003, uid, null);
        database.logEvent(3002, uid, null);
    }

    static int recordPasswordFailure(Database database, long uid) throws Exception {
        int failures = database.recordPasswordFailure(uid);
        database.logEvent(3003 + failures, uid, null);
        if (failures >= 3) {
            database.logEvent(3007, uid, null);
            database.logEvent(3002, uid, null);
        }
        return failures;
    }

    private void showToken() {
        showToken(true);
    }

    private void showToken(boolean logStart) {
        try {
            if (logStart) {
                database.logEvent(4001, currentUser.uid(), null);
            }
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel("Autenticação — etapa 3");
        JPanel center = new JPanel(new GridLayout(0, 1, 8, 8));
        JTextField tokenField = new JTextField(6);
        limitField(tokenField, 6);
        center.add(new JLabel("TOTP de 6 dígitos:"));
        center.add(tokenField);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton okButton = new JButton("OK");
        JButton clearButton = new JButton("Limpar");
        buttons.add(okButton);
        buttons.add(clearButton);
        center.add(buttons);
        panel.add(center, BorderLayout.CENTER);
        okButton.addActionListener(event -> {
            try {
                if (!verifyToken(currentUser.encryptedTotpSecret(), verifiedPassword,
                        tokenField.getText().trim())) {
                    handleTokenFailure();
                    return;
                }
                recordAuthenticationSuccess(database, currentUser.uid());
                sessionStarted = true;
                clearVerifiedPassword();
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        clearButton.addActionListener(event -> tokenField.setText(""));
        showPanel(panel);
    }

    static boolean verifyToken(byte[] encryptedSecret, char[] verifiedPassword,
            String code) throws Exception {
        if (verifiedPassword == null) {
            return false;
        }
        byte[] base32Bytes = CryptoUtils.decryptAes(encryptedSecret, verifiedPassword);
        try {
            TOTP totp = new TOTP(new String(base32Bytes, StandardCharsets.US_ASCII), 30);
            return totp.validateCode(code);
        } finally {
            Arrays.fill(base32Bytes, (byte) 0);
        }
    }

    private void handleTokenFailure() throws Exception {
        int failures = recordTokenFailure(database, currentUser.uid());
        if (failures >= 3) {
            showMessage("Terceiro erro. O acesso foi bloqueado por 2 minutos.");
            showLogin();
        } else {
            showMessage("Token inválido. Erro " + failures + " de 3.");
            showToken(false);
        }
    }

    static void recordAuthenticationSuccess(Database database, long uid) throws Exception {
        database.clearTokenFailures(uid);
        database.logEvent(4003, uid, null);
        database.logEvent(4002, uid, null);
        database.logEvent(1003, uid, null);
        database.incrementAccessCount(uid);
    }

    static int recordTokenFailure(Database database, long uid) throws Exception {
        int failures = database.recordTokenFailure(uid);
        database.logEvent(4003 + failures, uid, null);
        if (failures >= 3) {
            database.logEvent(4007, uid, null);
            database.logEvent(4002, uid, null);
        }
        return failures;
    }

    private void showMainMenu() {
        try {
            currentUser = database.findUser(currentUser.uid());
            database.logEvent(5001, currentUser.uid(), null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel("Tela Principal");
        JPanel center = new JPanel(new GridLayout(0, 1, 8, 8));
        center.add(new JLabel("Total de acessos do usuário: " + currentUser.accessCount()));
        // O grupo Usuário não vê a opção 1; as demais mantêm o número usado nos MIDs 5003 e 5004.
        if (canRegisterUser(currentUser)) {
            JButton registerButton = new JButton("1 — Cadastrar um novo usuário");
            registerButton.addActionListener(event -> {
                try {
                    database.logEvent(5002, currentUser.uid(), null);
                    showRegistration(false);
                } catch (Exception error) {
                    showError(error);
                }
            });
            center.add(registerButton);
        }
        JButton queryButton = new JButton("2 — Consultar pasta de arquivos secretos do usuário");
        JButton exitButton = new JButton("3 — Sair do Sistema");
        queryButton.addActionListener(event -> {
            try {
                database.logEvent(5003, currentUser.uid(), null);
                showFileQuery();
            } catch (Exception error) {
                showError(error);
            }
        });
        exitButton.addActionListener(event -> {
            try {
                database.logEvent(5004, currentUser.uid(), null);
                showExit();
            } catch (Exception error) {
                showError(error);
            }
        });
        center.add(queryButton);
        center.add(exitButton);
        panel.add(center, BorderLayout.CENTER);
        showPanel(panel);
    }

    private void showRegistration(boolean initial) {
        if (!initial && !canRegisterUser(currentUser)) {
            showMessage("Somente administradores podem cadastrar usuários.");
            return;
        }
        Long actorUid = initial ? null : currentUser.uid();
        try {
            database.logEvent(6001, actorUid, null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel(initial ? "Cadastro inicial do administrador" : "Cadastro de usuário");
        JPanel form = new JPanel(new GridLayout(0, 2, 7, 7));
        JTextField certificateField = new JTextField(35);
        JTextField keyField = new JTextField(35);
        JPasswordField passphraseField = new JPasswordField(35);
        JComboBox<String> groupBox = new JComboBox<>(new String[] {"Administrador", "Usuário"});
        groupBox.setEnabled(!initial);
        JPasswordField passwordField = new JPasswordField(10);
        JPasswordField confirmationField = new JPasswordField(10);
        limitField(certificateField, 255);
        limitField(keyField, 255);
        limitField(passphraseField, 255);
        limitField(passwordField, 10);
        limitField(confirmationField, 10);
        form.add(new JLabel("Total de usuários do sistema:"));
        try {
            form.add(new JLabel(String.valueOf(database.countUsers())));
        } catch (Exception error) {
            form.add(new JLabel("indisponível"));
        }
        addField(form, "Caminho do certificado digital:", certificateField);
        addField(form, "Caminho da chave privada:", keyField);
        addField(form, "Frase secreta:", passphraseField);
        addField(form, "Grupo:", groupBox);
        addField(form, "Senha pessoal:", passwordField);
        addField(form, "Confirmação da senha:", confirmationField);
        JPanel buttons = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton registerButton = new JButton("Cadastrar");
        JButton backButton = new JButton("Voltar de Cadastrar para o Menu Principal");
        backButton.setVisible(!initial);
        buttons.add(registerButton);
        buttons.add(backButton);
        JPanel center = new JPanel(new BorderLayout(8, 8));
        center.add(form, BorderLayout.CENTER);
        center.add(buttons, BorderLayout.SOUTH);
        panel.add(center, BorderLayout.CENTER);

        registerButton.addActionListener(event -> {
            char[] passphrase = passphraseField.getPassword();
            char[] password = passwordField.getPassword();
            char[] confirmation = confirmationField.getPassword();
            try {
                database.logEvent(6002, actorUid, null);
                if (!isPasswordValid(password) || !Arrays.equals(password, confirmation)) {
                    database.logEvent(6003, actorUid, null);
                    throw new Exception("A senha deve ter de 8 a 10 dígitos, sem dígitos iguais consecutivos, e coincidir com a confirmação.");
                }
                RegistrationMaterial material = loadRegistrationMaterial(database, actorUid,
                        certificateField.getText().trim(), keyField.getText().trim(), passphrase);
                X509Certificate certificate = material.certificate();
                String email = CryptoUtils.extractEmail(certificate);
                String name = CryptoUtils.extractName(certificate);
                if (email == null || name == null || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")
                        || database.findUser(email) != null) {
                    throw new Exception("O certificado não contém nome/e-mail válido e único.");
                }
                String details = certificateDetails(certificate, name, email);
                int answer = JOptionPane.showConfirmDialog(window, new JLabel(details),
                        "Confirmação dos dados", JOptionPane.YES_NO_OPTION);
                if (answer != JOptionPane.YES_OPTION) {
                    database.logEvent(6009, actorUid, null);
                    return;
                }
                database.logEvent(6008, actorUid, null);
                byte[] secret = new byte[20];
                new SecureRandom().nextBytes(secret);
                String base32 = new Base32(Base32.Alphabet.BASE32, false, false).toString(secret);
                byte[] encryptedSecret = CryptoUtils.encryptAes(
                        base32.getBytes(StandardCharsets.US_ASCII), password);
                String hash = CryptoUtils.generateBcrypt(password);
                int gid = initial || groupBox.getSelectedIndex() == 0
                        ? Database.ADMIN_GROUP_ID : Database.USER_GROUP_ID;
                database.insertUser(name, email, gid, UUID.randomUUID().toString(), hash,
                        encryptedSecret, material.certificatePem(), material.encryptedPrivateKey());
                JOptionPane.showMessageDialog(window,
                        "Usuário cadastrado. Segredo Base32 para o Google Authenticator:\n" + base32,
                        "Cadastro concluído", JOptionPane.INFORMATION_MESSAGE);
                clearFields(certificateField, keyField, passphraseField, passwordField,
                        confirmationField);
                if (initial) {
                    adminPassphrase = passphrase.clone();
                    showLogin();
                } else {
                    showRegistration(false);
                }
            } catch (Exception error) {
                showMessage(message(error));
            } finally {
                CryptoUtils.clear(passphrase);
                CryptoUtils.clear(password);
                CryptoUtils.clear(confirmation);
            }
        });
        backButton.addActionListener(event -> {
            try {
                database.logEvent(6010, currentUser.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(panel);
    }

    static boolean canRegisterUser(Database.User user) {
        return user != null && user.isAdministrator();
    }

    static boolean isPasswordValid(char[] password) {
        if (password == null || password.length < 8 || password.length > 10) {
            return false;
        }
        for (int i = 0; i < password.length; i++) {
            if (password[i] < '0' || password[i] > '9'
                    || (i > 0 && password[i] == password[i - 1])) {
                return false;
            }
        }
        return true;
    }

    private void showFileQuery() {
        try {
            database.logEvent(7001, currentUser.uid(), null);
            currentUser = database.findUser(currentUser.uid());
        } catch (Exception error) {
            showError(error);
            return;
        }
        currentCatalog = null;
        queryPrivateKey = null;
        JPanel panel = createBasePanel("Consulta de arquivos secretos");
        JPanel top = new JPanel(new GridLayout(0, 2, 7, 7));
        JTextField folderField = new JTextField(35);
        JPasswordField passphraseField = new JPasswordField(35);
        limitField(folderField, 255);
        limitField(passphraseField, 255);
        top.add(new JLabel("Total de consultas do usuário:"));
        JLabel queryCountLabel = new JLabel(String.valueOf(currentUser.queryCount()));
        top.add(queryCountLabel);
        addField(top, "Caminho da pasta:", folderField);
        addField(top, "Frase secreta:", passphraseField);
        JButton listButton = new JButton("Listar");
        JButton backButton = new JButton("Voltar de Consultar para o Menu Principal");
        top.add(listButton);
        top.add(backButton);
        DefaultTableModel model = new DefaultTableModel(
                new Object[] {"Nome secreto", "Dono", "Grupo"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable table = new JTable(model);
        table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        panel.add(top, BorderLayout.NORTH);
        panel.add(new JScrollPane(table), BorderLayout.CENTER);

        listButton.addActionListener(event -> {
            char[] passphrase = passphraseField.getPassword();
            try {
                database.logEvent(7003, currentUser.uid(), null);
                currentCatalog = null;
                queryPrivateKey = null;
                model.setRowCount(0);
                PrivateKey userPrivateKey = verifyStoredKey(database, currentUser.uid(),
                        database.findKeyEntry(currentUser.uid()), passphrase);
                Database.User admin = database.findAdministrator();
                Database.KeyEntry adminKey = database.findKeyEntry(admin.uid());
                PrivateKey adminPrivateKey = restoreKey(adminKey, adminPassphrase);
                X509Certificate adminCertificate = CryptoUtils.loadCertificate(
                        adminKey.certificatePem());
                Vault.Catalog catalog = vault.listFiles(Path.of(folderField.getText().trim()),
                        currentUser, adminPrivateKey, adminCertificate);
                for (Vault.FileEntry file : catalog.allowedFiles()) {
                    model.addRow(new Object[] {file.name(), file.owner(), file.group()});
                }
                database.logEvent(7009, currentUser.uid(), null);
                database.logEvent(7014, currentUser.uid(), null);
                currentCatalog = catalog;
                queryPrivateKey = userPrivateKey;
                database.incrementQueryCount(currentUser.uid());
                currentUser = database.findUser(currentUser.uid());
                queryCountLabel.setText(String.valueOf(currentUser.queryCount()));
                passphraseField.setText("");
            } catch (Exception error) {
                showMessage(message(error));
            } finally {
                CryptoUtils.clear(passphrase);
            }
        });
        table.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent event) {
                if (event.getClickCount() != 2 || table.getSelectedRow() < 0
                        || currentCatalog == null || queryPrivateKey == null) {
                    return;
                }
                JFileChooser chooser = new JFileChooser();
                chooser.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                chooser.setDialogTitle("Escolha a pasta de destino");
                if (chooser.showSaveDialog(window) != JFileChooser.APPROVE_OPTION) {
                    return;
                }
                try {
                    Vault.FileEntry file = currentCatalog.allowedFiles().get(table.getSelectedRow());
                    Path output = vault.openFile(currentCatalog, file, currentUser,
                            queryPrivateKey, chooser.getSelectedFile().toPath());
                    showMessage("Arquivo gravado em " + output);
                } catch (Exception error) {
                    showMessage(message(error));
                }
            }
        });
        backButton.addActionListener(event -> {
            try {
                currentCatalog = null;
                queryPrivateKey = null;
                database.logEvent(7002, currentUser.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(panel);
    }

    private void showExit() {
        try {
            database.logEvent(8001, currentUser.uid(), null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel panel = createBasePanel("Saída do sistema");
        JPanel center = new JPanel(new GridLayout(0, 1, 8, 8));
        center.add(new JLabel("Total de acessos do usuário: " + currentUser.accessCount()));
        center.add(new JLabel(EXIT_MESSAGE));
        JButton sessionButton = new JButton("Encerrar Sessão");
        JButton systemButton = new JButton("Encerrar Sistema");
        JButton backButton = new JButton("Voltar de Sair para o Menu Principal");
        center.add(sessionButton);
        center.add(systemButton);
        center.add(backButton);
        panel.add(center, BorderLayout.CENTER);
        sessionButton.addActionListener(event -> {
            try {
                database.logEvent(8002, currentUser.uid(), null);
                recordSessionEnd(database, currentUser);
                showLogin();
            } catch (Exception error) {
                showError(error);
            }
        });
        systemButton.addActionListener(event -> {
            try {
                database.logEvent(8003, currentUser.uid(), null);
            } catch (Exception error) {
                showError(error);
            }
            shutDown();
        });
        backButton.addActionListener(event -> {
            try {
                database.logEvent(8004, currentUser.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(panel);
    }

    private void shutDown() {
        if (closed) {
            return;
        }
        closed = true;
        try {
            recordSessionEnd(database, sessionStarted ? currentUser : null);
            database.logEvent(1002, null, null);
        } catch (Exception ignored) {
            // Não há interface disponível para recuperar uma falha durante o encerramento.
        } finally {
            try {
                database.close();
            } catch (Exception ignored) {
                // O encerramento continua para que os segredos sejam limpos da memória.
            }
            clearVerifiedPassword();
            CryptoUtils.clear(adminPassphrase);
            adminPassphrase = null;
            queryPrivateKey = null;
            window.dispose();
        }
    }

    static void recordSessionEnd(Database database, Database.User user) throws Exception {
        if (user != null) {
            database.logEvent(1004, user.uid(), null);
        }
    }

    static PrivateKey verifyStoredKey(Database database, long uid, Database.KeyEntry keyEntry,
            char[] passphrase) throws Exception {
        PrivateKey privateKey;
        try {
            privateKey = restoreKey(keyEntry, passphrase);
        } catch (Exception error) {
            database.logEvent(6006, uid, null);
            throw new Exception("Frase secreta inválida.");
        }
        boolean validPair;
        try {
            X509Certificate certificate = CryptoUtils.loadCertificate(keyEntry.certificatePem());
            validPair = CryptoUtils.proveKeyPair(privateKey, certificate.getPublicKey(), 10_240);
        } catch (Exception error) {
            validPair = false;
        }
        if (!validPair) {
            database.logEvent(6007, uid, null);
            throw new Exception("A chave privada não corresponde ao certificado.");
        }
        return privateKey;
    }

    static RegistrationMaterial loadRegistrationMaterial(Database database, Long actorUid,
            String certificatePath, String privateKeyPath, char[] passphrase) throws Exception {
        byte[] certificatePem;
        X509Certificate certificate;
        try {
            certificatePem = Files.readAllBytes(Path.of(certificatePath));
            String pemText = new String(certificatePem, StandardCharsets.US_ASCII);
            if (!pemText.contains("-----BEGIN CERTIFICATE-----")) {
                throw new Exception();
            }
            certificate = CryptoUtils.loadCertificate(certificatePem);
            certificate.checkValidity();
        } catch (Exception error) {
            database.logEvent(6004, actorUid, null);
            throw new Exception("Caminho ou certificado digital inválido.");
        }

        byte[] encryptedPrivateKey;
        try {
            encryptedPrivateKey = Files.readAllBytes(Path.of(privateKeyPath));
        } catch (Exception error) {
            database.logEvent(6005, actorUid, null);
            throw new Exception("Caminho da chave privada inválido.");
        }

        PrivateKey privateKey;
        try {
            byte[] openPrivateKey = CryptoUtils.decryptAes(encryptedPrivateKey, passphrase);
            try {
                privateKey = CryptoUtils.restorePrivateKey(openPrivateKey);
            } finally {
                Arrays.fill(openPrivateKey, (byte) 0);
            }
        } catch (Exception error) {
            database.logEvent(6006, actorUid, null);
            throw new Exception("Frase secreta inválida.");
        }

        boolean validPair;
        try {
            validPair = CryptoUtils.proveKeyPair(privateKey, certificate.getPublicKey(), 10_240);
        } catch (Exception error) {
            validPair = false;
        }
        if (!validPair) {
            database.logEvent(6007, actorUid, null);
            throw new Exception("A chave privada não corresponde ao certificado.");
        }
        return new RegistrationMaterial(certificate, certificatePem, encryptedPrivateKey);
    }

    private static PrivateKey restoreKey(Database.KeyEntry keyEntry, char[] passphrase)
            throws Exception {
        if (keyEntry == null) {
            throw new Exception("Chave do usuário não encontrada.");
        }
        byte[] content = CryptoUtils.decryptAes(keyEntry.encryptedPrivateKey(), passphrase);
        try {
            return CryptoUtils.restorePrivateKey(content);
        } finally {
            Arrays.fill(content, (byte) 0);
        }
    }

    private void clearVerifiedPassword() {
        CryptoUtils.clear(verifiedPassword);
        verifiedPassword = null;
    }

    private static void addField(JPanel panel, String label, java.awt.Component field) {
        panel.add(new JLabel(label));
        panel.add(field);
    }

    private static void limitField(JTextField field, int limit) {
        ((AbstractDocument) field.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass bypass, int offset, String text,
                    AttributeSet attributes) throws BadLocationException {
                if (text != null && bypass.getDocument().getLength() + text.length() <= limit) {
                    super.insertString(bypass, offset, text, attributes);
                }
            }

            @Override
            public void replace(FilterBypass bypass, int offset, int length, String text,
                    AttributeSet attributes) throws BadLocationException {
                if (text != null && bypass.getDocument().getLength() - length + text.length() <= limit) {
                    super.replace(bypass, offset, length, text, attributes);
                }
            }
        });
    }

    private static void clearFields(JTextField... fields) {
        for (JTextField field : fields) {
            field.setText("");
        }
    }

    static String certificateDetails(X509Certificate certificate, String name, String email) {
        DateTimeFormatter formatter = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
                .withZone(ZoneId.systemDefault());
        return "<html>Versão: " + certificate.getVersion()
                + "<br>Série: " + certificate.getSerialNumber()
                + "<br>Validade: " + formatter.format(certificate.getNotBefore().toInstant())
                + " até " + formatter.format(certificate.getNotAfter().toInstant())
                + "<br>Tipo de assinatura: " + html(certificate.getSigAlgName())
                + "<br>Emissor: " + html(certificate.getIssuerX500Principal().getName())
                + "<br>Sujeito: " + html(certificate.getSubjectX500Principal().getName())
                + "<br>Nome: " + html(name) + "<br>E-mail: " + html(email) + "</html>";
    }

    private static String html(String text) {
        return text == null ? "" : text.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;");
    }

    private void showMessage(String text) {
        JOptionPane.showMessageDialog(window, text, "Cofre Digital", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(Exception error) {
        JOptionPane.showMessageDialog(window, message(error), "Erro", JOptionPane.ERROR_MESSAGE);
    }

    static String message(Throwable error) {
        if (error instanceof SQLException) {
            return "Falha ao acessar o banco de dados.";
        }
        if (error instanceof java.nio.file.FileSystemException
                || error instanceof java.nio.file.InvalidPathException
                || error instanceof SecurityException) {
            return "Falha ao acessar arquivo ou diretório.";
        }
        String text = error.getMessage();
        return text == null || text.isBlank() ? "Operação não concluída." : text;
    }
}

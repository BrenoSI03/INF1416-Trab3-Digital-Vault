import java.awt.BorderLayout;
import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
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
    private final Database banco;
    private final Vault cofre;
    private final JFrame janela = new JFrame("Cofre Digital");
    private char[] fraseAdministrador;
    private Database.User usuarioAtual;
    private char[] senhaComprovada;
    private boolean encerrado;

    public DigitalVault(Path databaseFile) throws Exception {
        banco = new Database(databaseFile);
        cofre = new Vault(banco);
        janela.setDefaultCloseOperation(JFrame.DO_NOTHING_ON_CLOSE);
        janela.setMinimumSize(new Dimension(720, 520));
        janela.setLocationRelativeTo(null);
        janela.addWindowListener(new WindowAdapter() {
            @Override
            public void windowClosing(WindowEvent event) {
                shutDown();
            }
        });
    }

    public static void main(String[] args) {
        SwingUtilities.invokeLater(() -> {
            try {
                Path banco = Path.of(args.length == 0 ? "cofre.db" : args[0]);
                new DigitalVault(banco).start();
            } catch (Exception error) {
                JOptionPane.showMessageDialog(null,
                        "Não foi possível iniciar o Cofre Digital: " + message(error),
                        "Erro", JOptionPane.ERROR_MESSAGE);
            }
        });
    }

    private void start() throws Exception {
        banco.logEvent(1001, null, null);
        janela.setVisible(true);
        if (!banco.hasUsers()) {
            banco.logEvent(1005, null, null);
            showRegistration(true);
            return;
        }
        banco.logEvent(1006, null, null);
        if (!validateInitialAdministrator()) {
            JOptionPane.showMessageDialog(janela,
                    "A chave privada do administrador não foi validada. O sistema será encerrado.");
            shutDown();
            return;
        }
        showLogin();
    }

    private boolean validateInitialAdministrator() throws Exception {
        Database.User administrador = banco.findAdministrator();
        if (administrador == null) {
            return false;
        }
        JPasswordField campo = new JPasswordField(30);
        int resposta = JOptionPane.showConfirmDialog(janela, campo,
                "Frase secreta da chave do administrador", JOptionPane.OK_CANCEL_OPTION,
                JOptionPane.PLAIN_MESSAGE);
        if (resposta != JOptionPane.OK_OPTION) {
            return false;
        }
        char[] frase = campo.getPassword();
        try {
            Database.KeyEntry chaveiro = banco.findKeyEntry(administrador.uid());
            PrivateKey privada = restoreKey(chaveiro, frase);
            X509Certificate certificado = CryptoUtils.loadCertificate(chaveiro.certificatePem());
            boolean parValido;
            try {
                parValido = CryptoUtils.proveKeyPair(privada, certificado.getPublicKey(), 10_240);
            } catch (Exception error) {
                parValido = false;
            }
            if (!parValido) {
                banco.logEvent(6007, administrador.uid(), null);
                return false;
            }
            fraseAdministrador = frase.clone();
            return true;
        } catch (Exception error) {
            banco.logEvent(6006, administrador.uid(), null);
            return false;
        } finally {
            CryptoUtils.clear(frase);
        }
    }

    private void showPanel(JPanel painel) {
        janela.setContentPane(painel);
        janela.pack();
        janela.setLocationRelativeTo(null);
        janela.revalidate();
    }

    private JPanel createBasePanel(String titulo) {
        JPanel painel = new JPanel(new BorderLayout(10, 10));
        painel.setBorder(BorderFactory.createEmptyBorder(14, 14, 14, 14));
        JLabel cabecalho = new JLabel("<html><h2>" + titulo + "</h2>"
                + (usuarioAtual == null ? "" : "Login: " + html(usuarioAtual.email())
                        + "<br>Grupo: " + html(usuarioAtual.group())
                        + "<br>Nome: " + html(usuarioAtual.name())) + "</html>");
        painel.add(cabecalho, BorderLayout.NORTH);
        return painel;
    }

    private void showLogin() {
        clearVerifiedPassword();
        usuarioAtual = null;
        try {
            banco.logEvent(2001, null, null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Autenticação — etapa 1");
        JPanel centro = new JPanel(new GridLayout(0, 1, 8, 8));
        JTextField email = new JTextField(35);
        centro.add(new JLabel("Login name (e-mail):"));
        centro.add(email);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton confirmar = new JButton("OK");
        JButton limpar = new JButton("Limpar");
        botoes.add(confirmar);
        botoes.add(limpar);
        centro.add(botoes);
        painel.add(centro, BorderLayout.CENTER);
        confirmar.addActionListener(event -> {
            try {
                String login = email.getText().trim();
                Database.User usuario = banco.findUser(login);
                if (usuario == null) {
                    banco.logEvent(2005, null, null);
                    showMessage("Login name não identificado.");
                    return;
                }
                banco.clearExpiredLock(usuario.uid());
                usuario = banco.findUser(usuario.uid());
                if (usuario.lockedUntil() > System.currentTimeMillis()) {
                    banco.logEvent(2004, usuario.uid(), null);
                    showMessage("Acesso bloqueado temporariamente.");
                    return;
                }
                banco.logEvent(2003, usuario.uid(), null);
                banco.logEvent(2002, usuario.uid(), null);
                usuarioAtual = usuario;
                showVirtualKeyboard();
            } catch (Exception error) {
                showError(error);
            }
        });
        limpar.addActionListener(event -> email.setText(""));
        showPanel(painel);
        email.requestFocusInWindow();
    }

    private void showVirtualKeyboard() {
        showVirtualKeyboard(true);
    }

    private void showVirtualKeyboard(boolean registrarInicio) {
        try {
            if (registrarInicio) {
                banco.logEvent(3001, usuarioAtual.uid(), null);
            }
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Autenticação — etapa 2");
        JPanel centro = new JPanel(new BorderLayout(8, 8));
        JLabel quantidade = new JLabel("Senha pessoal: 0 dígitos informados");
        JPanel teclado = new JPanel(new GridLayout(1, 5, 8, 8));
        List<char[]> pares = new ArrayList<>();
        JButton[] teclas = new JButton[5];
        Runnable redistribuir = () -> distributeDigits(teclas);
        for (int i = 0; i < teclas.length; i++) {
            teclas[i] = new JButton();
            JButton tecla = teclas[i];
            tecla.addActionListener(event -> {
                if (!recordPressedPair(pares, tecla.getText())) {
                    return;
                }
                quantidade.setText("Senha pessoal: " + pares.size() + " dígitos informados");
                redistribuir.run();
            });
            teclado.add(tecla);
        }
        redistribuir.run();
        centro.add(quantidade, BorderLayout.NORTH);
        centro.add(teclado, BorderLayout.CENTER);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton confirmar = new JButton("OK");
        JButton limpar = new JButton("Limpar");
        botoes.add(confirmar);
        botoes.add(limpar);
        centro.add(botoes, BorderLayout.SOUTH);
        painel.add(centro, BorderLayout.CENTER);

        limpar.addActionListener(event -> {
            pares.clear();
            quantidade.setText("Senha pessoal: 0 dígitos informados");
            redistribuir.run();
        });
        confirmar.addActionListener(event -> {
            confirmar.setEnabled(false);
            try {
                char[] senha = findPassword(pares, usuarioAtual.passwordHash());
                if (senha == null) {
                    handlePasswordFailure();
                    if (usuarioAtual != null) {
                        confirmar.setEnabled(true);
                    }
                    return;
                }
                banco.clearPasswordFailures(usuarioAtual.uid());
                banco.logEvent(3003, usuarioAtual.uid(), null);
                banco.logEvent(3002, usuarioAtual.uid(), null);
                senhaComprovada = senha;
                showToken();
            } catch (Exception error) {
                showError(error);
                confirmar.setEnabled(true);
            }
        });
        showPanel(painel);
    }

    static void distributeDigits(JButton[] teclas) {
        List<Integer> digitos = new ArrayList<>();
        for (int i = 0; i < 10; i++) {
            digitos.add(i);
        }
        Collections.shuffle(digitos, new SecureRandom());
        for (int i = 0; i < 5; i++) {
            teclas[i].setText(digitos.get(i * 2) + " " + digitos.get(i * 2 + 1));
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

    static char[] findPassword(List<char[]> pares, String hash) {
        if (pares.size() < 8 || pares.size() > 10) {
            return null;
        }
        char[] candidata = new char[pares.size()];
        return findPassword(pares, hash, candidata, 0);
    }

    private static char[] findPassword(List<char[]> pares, String hash,
            char[] candidata, int posicao) {
        if (posicao == pares.size()) {
            return CryptoUtils.verifyBcrypt(hash, candidata) ? candidata.clone() : null;
        }
        for (char digito : pares.get(posicao)) {
            candidata[posicao] = digito;
            char[] encontrada = findPassword(pares, hash, candidata, posicao + 1);
            if (encontrada != null) {
                CryptoUtils.clear(candidata);
                return encontrada;
            }
        }
        candidata[posicao] = '\0';
        return null;
    }

    private void handlePasswordFailure() throws Exception {
        int erros = banco.recordPasswordFailure(usuarioAtual.uid());
        banco.logEvent(3003 + erros, usuarioAtual.uid(), null);
        if (erros >= 3) {
            banco.logEvent(3007, usuarioAtual.uid(), null);
            banco.logEvent(3002, usuarioAtual.uid(), null);
            showMessage("Terceiro erro. O acesso foi bloqueado por 2 minutos.");
            showLogin();
        } else {
            showMessage("Senha pessoal inválida. Erro " + erros + " de 3.");
            showVirtualKeyboard(false);
        }
    }

    private void showToken() {
        showToken(true);
    }

    private void showToken(boolean registrarInicio) {
        try {
            if (registrarInicio) {
                banco.logEvent(4001, usuarioAtual.uid(), null);
            }
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Autenticação — etapa 3");
        JPanel centro = new JPanel(new GridLayout(0, 1, 8, 8));
        JTextField token = new JTextField(6);
        limitField(token, 6);
        centro.add(new JLabel("TOTP de 6 dígitos:"));
        centro.add(token);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton confirmar = new JButton("OK");
        JButton limpar = new JButton("Limpar");
        botoes.add(confirmar);
        botoes.add(limpar);
        centro.add(botoes);
        painel.add(centro, BorderLayout.CENTER);
        confirmar.addActionListener(event -> {
            try {
                if (!verifyToken(usuarioAtual.encryptedTotpSecret(), senhaComprovada,
                        token.getText().trim())) {
                    handleTokenFailure();
                    return;
                }
                banco.clearTokenFailures(usuarioAtual.uid());
                banco.logEvent(4003, usuarioAtual.uid(), null);
                banco.logEvent(4002, usuarioAtual.uid(), null);
                banco.logEvent(1003, usuarioAtual.uid(), null);
                banco.incrementAccessCount(usuarioAtual.uid());
                clearVerifiedPassword();
                usuarioAtual = banco.findUser(usuarioAtual.uid());
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        limpar.addActionListener(event -> token.setText(""));
        showPanel(painel);
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
            java.util.Arrays.fill(base32Bytes, (byte) 0);
        }
    }

    private void handleTokenFailure() throws Exception {
        int erros = banco.recordTokenFailure(usuarioAtual.uid());
        banco.logEvent(4003 + erros, usuarioAtual.uid(), null);
        if (erros >= 3) {
            banco.logEvent(4007, usuarioAtual.uid(), null);
            banco.logEvent(4002, usuarioAtual.uid(), null);
            showMessage("Terceiro erro. O acesso foi bloqueado por 2 minutos.");
            showLogin();
        } else {
            showMessage("Token inválido. Erro " + erros + " de 3.");
            showToken(false);
        }
    }

    private void showMainMenu() {
        try {
            usuarioAtual = banco.findUser(usuarioAtual.uid());
            banco.logEvent(5001, usuarioAtual.uid(), null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Tela Principal");
        JPanel centro = new JPanel(new GridLayout(0, 1, 8, 8));
        centro.add(new JLabel("Total de acessos do usuário: " + usuarioAtual.accessCount()));
        if (usuarioAtual.isAdministrator()) {
            JButton cadastrar = new JButton("1 — Cadastrar um novo usuário");
            cadastrar.addActionListener(event -> {
                try {
                    banco.logEvent(5002, usuarioAtual.uid(), null);
                    showRegistration(false);
                } catch (Exception error) {
                    showError(error);
                }
            });
            centro.add(cadastrar);
        }
        JButton consultar = new JButton(usuarioAtual.isAdministrator()
                ? "2 — Consultar pasta de arquivos secretos do usuário"
                : "1 — Consultar pasta de arquivos secretos do usuário");
        JButton sair = new JButton(usuarioAtual.isAdministrator()
                ? "3 — Sair do Sistema" : "2 — Sair do Sistema");
        consultar.addActionListener(event -> {
            try {
                banco.logEvent(5003, usuarioAtual.uid(), null);
                showFileQuery();
            } catch (Exception error) {
                showError(error);
            }
        });
        sair.addActionListener(event -> {
            try {
                banco.logEvent(5004, usuarioAtual.uid(), null);
                showExit();
            } catch (Exception error) {
                showError(error);
            }
        });
        centro.add(consultar);
        centro.add(sair);
        painel.add(centro, BorderLayout.CENTER);
        showPanel(painel);
    }

    private void showRegistration(boolean inicial) {
        if (!inicial && (usuarioAtual == null || !usuarioAtual.isAdministrator())) {
            showMessage("Somente administradores podem cadastrar usuários.");
            return;
        }
        try {
            banco.logEvent(6001, inicial ? null : usuarioAtual.uid(), null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel(inicial ? "Cadastro inicial do administrador" : "Cadastro de usuário");
        JPanel formulario = new JPanel(new GridLayout(0, 2, 7, 7));
        JTextField certificado = new JTextField(35);
        JTextField chave = new JTextField(35);
        JPasswordField frase = new JPasswordField(35);
        JComboBox<String> grupo = new JComboBox<>(new String[] {"Administrador", "Usuário"});
        grupo.setEnabled(!inicial);
        JPasswordField senha = new JPasswordField(10);
        JPasswordField confirmacao = new JPasswordField(10);
        limitField(certificado, 255);
        limitField(chave, 255);
        limitField(frase, 255);
        limitField(senha, 10);
        limitField(confirmacao, 10);
        formulario.add(new JLabel("Total de usuários do sistema:"));
        try {
            formulario.add(new JLabel(String.valueOf(banco.countUsers())));
        } catch (Exception error) {
            formulario.add(new JLabel("indisponível"));
        }
        addField(formulario, "Caminho do certificado digital:", certificado);
        addField(formulario, "Caminho da chave privada:", chave);
        addField(formulario, "Frase secreta:", frase);
        addField(formulario, "Grupo:", grupo);
        addField(formulario, "Senha pessoal:", senha);
        addField(formulario, "Confirmação da senha:", confirmacao);
        JPanel botoes = new JPanel(new FlowLayout(FlowLayout.LEFT));
        JButton cadastrar = new JButton("Cadastrar");
        JButton voltar = new JButton("Voltar de Cadastrar para o Menu Principal");
        voltar.setVisible(!inicial);
        botoes.add(cadastrar);
        botoes.add(voltar);
        JPanel centro = new JPanel(new BorderLayout(8, 8));
        centro.add(formulario, BorderLayout.CENTER);
        centro.add(botoes, BorderLayout.SOUTH);
        painel.add(centro, BorderLayout.CENTER);

        cadastrar.addActionListener(event -> {
            char[] fraseInformada = frase.getPassword();
            char[] senhaInformada = senha.getPassword();
            char[] confirmacaoInformada = confirmacao.getPassword();
            try {
                banco.logEvent(6002, inicial ? null : usuarioAtual.uid(), null);
                if (certificado.getText().length() > 255 || chave.getText().length() > 255
                        || fraseInformada.length > 255 || !isPasswordValid(senhaInformada)
                        || !java.util.Arrays.equals(senhaInformada, confirmacaoInformada)) {
                    banco.logEvent(6003, inicial ? null : usuarioAtual.uid(), null);
                    throw new Exception("A senha deve ter de 8 a 10 dígitos, sem dígitos iguais consecutivos, e coincidir com a confirmação.");
                }
                Path caminhoCertificado = Path.of(certificado.getText().trim());
                X509Certificate certificadoLido;
                byte[] certificadoPem;
                try {
                    certificadoPem = Files.readAllBytes(caminhoCertificado);
                    String inicioPem = new String(certificadoPem, StandardCharsets.US_ASCII);
                    if (!inicioPem.contains("-----BEGIN CERTIFICATE-----")) {
                        throw new Exception();
                    }
                    certificadoLido = CryptoUtils.loadCertificate(certificadoPem);
                    certificadoLido.checkValidity();
                } catch (Exception error) {
                    banco.logEvent(6004, inicial ? null : usuarioAtual.uid(), null);
                    throw new Exception("Caminho ou certificado digital inválido.");
                }
                byte[] chaveCifrada;
                try {
                    chaveCifrada = Files.readAllBytes(Path.of(chave.getText().trim()));
                } catch (Exception error) {
                    banco.logEvent(6005, inicial ? null : usuarioAtual.uid(), null);
                    throw new Exception("Caminho da chave privada inválido.");
                }
                PrivateKey privada;
                try {
                    byte[] chaveAberta = CryptoUtils.decryptAes(chaveCifrada, fraseInformada);
                    try {
                        privada = CryptoUtils.restorePrivateKey(chaveAberta);
                    } finally {
                        java.util.Arrays.fill(chaveAberta, (byte) 0);
                    }
                } catch (Exception error) {
                    banco.logEvent(6006, inicial ? null : usuarioAtual.uid(), null);
                    throw new Exception("Frase secreta inválida.");
                }
                boolean parValido;
                try {
                    parValido = CryptoUtils.proveKeyPair(
                            privada, certificadoLido.getPublicKey(), 10_240);
                } catch (Exception error) {
                    parValido = false;
                }
                if (!parValido) {
                    banco.logEvent(6007, inicial ? null : usuarioAtual.uid(), null);
                    throw new Exception("A chave privada não corresponde ao certificado.");
                }
                String email = CryptoUtils.extractEmail(certificadoLido);
                String nome = CryptoUtils.extractName(certificadoLido);
                if (email == null || nome == null || !email.matches("^[^@\\s]+@[^@\\s]+\\.[^@\\s]+$")
                        || banco.findUser(email) != null) {
                    throw new Exception("O certificado não contém nome/e-mail válido e único.");
                }
                String detalhes = certificateDetails(certificadoLido, nome, email);
                int resposta = JOptionPane.showConfirmDialog(janela, new JLabel(detalhes),
                        "Confirmação dos dados", JOptionPane.YES_NO_OPTION);
                if (resposta != JOptionPane.YES_OPTION) {
                    banco.logEvent(6009, inicial ? null : usuarioAtual.uid(), null);
                    return;
                }
                banco.logEvent(6008, inicial ? null : usuarioAtual.uid(), null);
                byte[] segredo = new byte[20];
                new SecureRandom().nextBytes(segredo);
                String base32 = new Base32().toString(segredo);
                byte[] segredoCifrado = CryptoUtils.encryptAes(
                        base32.getBytes(StandardCharsets.US_ASCII), senhaInformada);
                String hash = CryptoUtils.generateBcrypt(senhaInformada);
                int gid = inicial || grupo.getSelectedIndex() == 0
                        ? Database.ADMIN_GROUP_ID : Database.USER_GROUP_ID;
                banco.insertUser(nome, email, gid, UUID.randomUUID().toString(), hash,
                        segredoCifrado, certificadoPem, chaveCifrada);
                JOptionPane.showMessageDialog(janela,
                        "Usuário cadastrado. Segredo Base32 para o Google Authenticator:\n" + base32,
                        "Cadastro concluído", JOptionPane.INFORMATION_MESSAGE);
                if (inicial) {
                    fraseAdministrador = fraseInformada.clone();
                    clearFields(certificado, chave, frase, senha, confirmacao);
                    showLogin();
                } else {
                    clearFields(certificado, chave, frase, senha, confirmacao);
                    showRegistration(false);
                }
            } catch (Exception error) {
                showMessage(message(error));
            } finally {
                CryptoUtils.clear(fraseInformada);
                CryptoUtils.clear(senhaInformada);
                CryptoUtils.clear(confirmacaoInformada);
            }
        });
        voltar.addActionListener(event -> {
            try {
                banco.logEvent(6010, usuarioAtual.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(painel);
    }

    static boolean isPasswordValid(char[] senha) {
        if (senha == null || senha.length < 8 || senha.length > 10) {
            return false;
        }
        for (int i = 0; i < senha.length; i++) {
            if (senha[i] < '0' || senha[i] > '9' || (i > 0 && senha[i] == senha[i - 1])) {
                return false;
            }
        }
        return true;
    }

    private void showFileQuery() {
        try {
            banco.logEvent(7001, usuarioAtual.uid(), null);
            usuarioAtual = banco.findUser(usuarioAtual.uid());
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Consulta de arquivos secretos");
        JPanel topo = new JPanel(new GridLayout(0, 2, 7, 7));
        JTextField pasta = new JTextField(35);
        JPasswordField frase = new JPasswordField(35);
        limitField(pasta, 255);
        limitField(frase, 255);
        topo.add(new JLabel("Total de consultas do usuário:"));
        JLabel totalConsultas = new JLabel(String.valueOf(usuarioAtual.queryCount()));
        topo.add(totalConsultas);
        addField(topo, "Caminho da pasta:", pasta);
        addField(topo, "Frase secreta:", frase);
        JButton listar = new JButton("Listar");
        JButton voltar = new JButton("Voltar de Consultar para o Menu Principal");
        topo.add(listar);
        topo.add(voltar);
        DefaultTableModel modelo = new DefaultTableModel(
                new Object[] {"Nome secreto", "Dono", "Grupo"}, 0) {
            @Override
            public boolean isCellEditable(int row, int column) {
                return false;
            }
        };
        JTable tabela = new JTable(modelo);
        tabela.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);
        painel.add(topo, BorderLayout.NORTH);
        painel.add(new JScrollPane(tabela), BorderLayout.CENTER);
        final Vault.Catalog[] catalogoAtual = new Vault.Catalog[1];
        final PrivateKey[] privadaAtual = new PrivateKey[1];

        listar.addActionListener(event -> {
            char[] fraseInformada = frase.getPassword();
            try {
                banco.logEvent(7003, usuarioAtual.uid(), null);
                catalogoAtual[0] = null;
                privadaAtual[0] = null;
                modelo.setRowCount(0);
                if (pasta.getText().length() > 255 || fraseInformada.length > 255) {
                    throw new Exception("Caminho ou frase excede 255 caracteres.");
                }
                Database.KeyEntry chaveUser = banco.findKeyEntry(usuarioAtual.uid());
                PrivateKey privadaUser = verifyStoredKey(chaveUser, fraseInformada);
                Database.User admin = banco.findAdministrator();
                Database.KeyEntry chaveAdmin = banco.findKeyEntry(admin.uid());
                PrivateKey privadaAdmin = restoreKey(chaveAdmin, fraseAdministrador);
                X509Certificate certificadoAdmin = CryptoUtils.loadCertificate(
                        chaveAdmin.certificatePem());
                Vault.Catalog catalogo = cofre.listFiles(Path.of(pasta.getText().trim()),
                        usuarioAtual, privadaAdmin, certificadoAdmin);
                modelo.setRowCount(0);
                for (Vault.FileEntry arquivo : catalogo.allowedFiles()) {
                    modelo.addRow(new Object[] {arquivo.name(), arquivo.owner(), arquivo.group()});
                }
                banco.logEvent(7009, usuarioAtual.uid(), null);
                banco.logEvent(7014, usuarioAtual.uid(), null);
                catalogoAtual[0] = catalogo;
                privadaAtual[0] = privadaUser;
                banco.incrementQueryCount(usuarioAtual.uid());
                usuarioAtual = banco.findUser(usuarioAtual.uid());
                totalConsultas.setText(String.valueOf(usuarioAtual.queryCount()));
                frase.setText("");
            } catch (Exception error) {
                showMessage(message(error));
            } finally {
                CryptoUtils.clear(fraseInformada);
            }
        });
        tabela.addMouseListener(new java.awt.event.MouseAdapter() {
            @Override
            public void mouseClicked(java.awt.event.MouseEvent event) {
                if (event.getClickCount() != 2 || tabela.getSelectedRow() < 0
                        || catalogoAtual[0] == null || privadaAtual[0] == null) {
                    return;
                }
                JFileChooser seletor = new JFileChooser();
                seletor.setFileSelectionMode(JFileChooser.DIRECTORIES_ONLY);
                seletor.setDialogTitle("Escolha a pasta de destino");
                if (seletor.showSaveDialog(janela) != JFileChooser.APPROVE_OPTION) {
                    return;
                }
                try {
                    Vault.FileEntry arquivo = catalogoAtual[0].allowedFiles().get(tabela.getSelectedRow());
                    Path saida = cofre.openFile(catalogoAtual[0], arquivo, usuarioAtual,
                            privadaAtual[0], seletor.getSelectedFile().toPath());
                    showMessage("Arquivo gravado em " + saida);
                } catch (Exception error) {
                    showMessage(message(error));
                }
            }
        });
        voltar.addActionListener(event -> {
            try {
                privadaAtual[0] = null;
                banco.logEvent(7002, usuarioAtual.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(painel);
    }

    private void showExit() {
        try {
            banco.logEvent(8001, usuarioAtual.uid(), null);
        } catch (Exception error) {
            showError(error);
            return;
        }
        JPanel painel = createBasePanel("Saída do sistema");
        JPanel centro = new JPanel(new GridLayout(0, 1, 8, 8));
        centro.add(new JLabel("Total de acessos do usuário: " + usuarioAtual.accessCount()));
        centro.add(new JLabel("Pressione o botão Encerrar Sessão ou o botão Encerrar Sistema para confirmar."));
        JButton sessao = new JButton("Encerrar Sessão");
        JButton sistema = new JButton("Encerrar Sistema");
        JButton voltar = new JButton("Voltar de Sair para o Menu Principal");
        centro.add(sessao);
        centro.add(sistema);
        centro.add(voltar);
        painel.add(centro, BorderLayout.CENTER);
        sessao.addActionListener(event -> {
            try {
                banco.logEvent(8002, usuarioAtual.uid(), null);
                banco.logEvent(1004, usuarioAtual.uid(), null);
                showLogin();
            } catch (Exception error) {
                showError(error);
            }
        });
        sistema.addActionListener(event -> {
            try {
                banco.logEvent(8003, usuarioAtual.uid(), null);
                banco.logEvent(1004, usuarioAtual.uid(), null);
            } catch (Exception error) {
                showError(error);
            }
            usuarioAtual = null;
            shutDown();
        });
        voltar.addActionListener(event -> {
            try {
                banco.logEvent(8004, usuarioAtual.uid(), null);
                showMainMenu();
            } catch (Exception error) {
                showError(error);
            }
        });
        showPanel(painel);
    }

    private void shutDown() {
        if (encerrado) {
            return;
        }
        encerrado = true;
        try {
            if (usuarioAtual != null) {
                banco.logEvent(1004, usuarioAtual.uid(), null);
            }
            banco.logEvent(1002, null, null);
            banco.close();
        } catch (Exception ignored) {
            // Não há interface disponível para recuperar uma falha durante o encerramento.
        } finally {
            clearVerifiedPassword();
            CryptoUtils.clear(fraseAdministrador);
            fraseAdministrador = null;
            janela.dispose();
        }
    }

    static PrivateKey verifyStoredKey(Database.KeyEntry keyEntry, char[] passphrase)
            throws Exception {
        PrivateKey privateKey = restoreKey(keyEntry, passphrase);
        X509Certificate certificate = CryptoUtils.loadCertificate(keyEntry.certificatePem());
        if (!CryptoUtils.proveKeyPair(privateKey, certificate.getPublicKey(), 10_240)) {
            throw new Exception("A chave privada não corresponde ao certificado.");
        }
        return privateKey;
    }

    private static PrivateKey restoreKey(Database.KeyEntry chaveiro, char[] frase) throws Exception {
        if (chaveiro == null) {
            throw new Exception("Chave do usuário não encontrada.");
        }
        byte[] conteudo = CryptoUtils.decryptAes(chaveiro.encryptedPrivateKey(), frase);
        try {
            return CryptoUtils.restorePrivateKey(conteudo);
        } finally {
            java.util.Arrays.fill(conteudo, (byte) 0);
        }
    }

    private void clearVerifiedPassword() {
        CryptoUtils.clear(senhaComprovada);
        senhaComprovada = null;
    }

    private static void addField(JPanel painel, String rotulo, java.awt.Component campo) {
        painel.add(new JLabel(rotulo));
        painel.add(campo);
    }

    private static void limitField(JTextField campo, int limite) {
        ((AbstractDocument) campo.getDocument()).setDocumentFilter(new DocumentFilter() {
            @Override
            public void insertString(FilterBypass bypass, int offset, String texto, AttributeSet atributos)
                    throws BadLocationException {
                if (texto != null && bypass.getDocument().getLength() + texto.length() <= limite) {
                    super.insertString(bypass, offset, texto, atributos);
                }
            }

            @Override
            public void replace(FilterBypass bypass, int offset, int tamanho, String texto,
                    AttributeSet atributos) throws BadLocationException {
                if (texto != null && bypass.getDocument().getLength() - tamanho + texto.length() <= limite) {
                    super.replace(bypass, offset, tamanho, texto, atributos);
                }
            }
        });
    }

    private static void clearFields(JTextField certificado, JTextField chave,
            JPasswordField frase, JPasswordField senha, JPasswordField confirmacao) {
        certificado.setText("");
        chave.setText("");
        frase.setText("");
        senha.setText("");
        confirmacao.setText("");
    }

    private static String certificateDetails(X509Certificate certificado,
            String nome, String email) {
        DateTimeFormatter formato = DateTimeFormatter.ofPattern("dd/MM/yyyy HH:mm:ss")
                .withZone(ZoneId.systemDefault());
        return "<html>Versão: " + certificado.getVersion()
                + "<br>Série: " + certificado.getSerialNumber()
                + "<br>Validade: " + formato.format(certificado.getNotBefore().toInstant())
                + " até " + formato.format(certificado.getNotAfter().toInstant())
                + "<br>Tipo de assinatura: " + html(certificado.getSigAlgName())
                + "<br>Emissor: " + html(certificado.getIssuerX500Principal().getName())
                + "<br>Sujeito: " + html(certificado.getSubjectX500Principal().getName())
                + "<br>Nome: " + html(nome) + "<br>E-mail: " + html(email) + "</html>";
    }

    private static String html(String texto) {
        return texto == null ? "" : texto.replace("&", "&amp;")
                .replace("<", "&lt;").replace(">", "&gt;");
    }

    private void showMessage(String texto) {
        JOptionPane.showMessageDialog(janela, texto, "Cofre Digital", JOptionPane.INFORMATION_MESSAGE);
    }

    private void showError(Exception error) {
        JOptionPane.showMessageDialog(janela, message(error), "Erro", JOptionPane.ERROR_MESSAGE);
    }

    private static String message(Throwable error) {
        if (error instanceof SQLException) {
            return "Falha ao acessar o banco de dados.";
        }
        String texto = error.getMessage();
        return texto == null || texto.isBlank() ? "Operação não concluída." : texto;
    }
}

# Cofre Digital

Trabalho 3 da disciplina INF1416 — Segurança da Informação.

## Alunos

### Breno de Andrade Soares - Matrícula: 2320363

### João Pedro Zaidman dos Santos Gonçalves - Matrícula: 2320464

## Introdução

O projeto implementa, em Java, uma aplicação de Cofre Digital que protege uma
pasta de arquivos secretos. O sistema utiliza autenticação em três etapas,
formada pela identificação do usuário e pelos fatores senha pessoal e TOTP.

Os arquivos do cofre são protegidos por criptografia AES, envelopes digitais
RSA e assinaturas digitais. A aplicação valida os arquivos de índice e de
compartilhamento antes de listar ou abrir documentos, aplica as permissões de
dono, grupo e compartilhamento e registra as atividades em um banco de dados
SQLite.

O projeto também contém o programa separado `LogView`, utilizado pelo
administrador para consultar os registros de auditoria em ordem cronológica.

## Referências

- [Enunciado do Trabalho 3](Trabalho3.pdf)
- [Detalhamento do Trabalho 3](Trabalho3-Detalhamento.pdf)

## Compilação e execução

O projeto requer Java JDK, SQLite JDBC e BouncyCastle. Os arquivos JAR
necessários estão na pasta `lib`.

No PowerShell, execute os comandos a partir da raiz do projeto:

```powershell
New-Item -ItemType Directory -Force build
javac -encoding UTF-8 -cp "lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" -d build src\*.java tests\Tests.java
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" DigitalVault
```

Sem argumentos, a aplicação utiliza o arquivo `cofre.db` no diretório atual.
Para selecionar outro banco de dados, informe seu caminho como primeiro
argumento:

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" DigitalVault caminho-do-banco.db
```

O visualizador de logs deve ser executado em um terminal real, pois lê a frase
secreta sem exibi-la. O primeiro argumento é o caminho da chave privada do
administrador e o segundo, opcional, é o caminho do banco de dados:

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" LogView caminho-da-chave.key
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" LogView caminho-da-chave.key caminho-do-banco.db
```

### Compilação com CMake

Como alternativa, o projeto possui um `CMakeLists.txt`. É necessário ter o
CMake 3.20 ou mais recente e o JDK instalados:

```powershell
cmake -S . -B cmake-build
cmake --build cmake-build
```

Depois da compilação, a aplicação e os testes podem ser executados pelos alvos:

```powershell
cmake --build cmake-build --target run
cmake --build cmake-build --target run_tests
cmake --build cmake-build --target run_package_tests
```

O último alvo solicita as frases do `Pacote-T3` no terminal.

## Testes

A suíte principal cria identidades, certificados, banco e cofre independentes
em `tests/additional-data`:

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" Tests
```

Essa suíte concluiu 52 verificações envolvendo Base32, TOTP, bcrypt,
PKCS#8, AES, RSA, banco de dados, permissões, compartilhamento, adulterações,
bloqueio e ordem cronológica dos registros.

O `Pacote-T3` pode ser testado separadamente. As três frases são solicitadas no
terminal sem serem exibidas:

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" Tests --package-t3
```

Esse teste concluiu 25 verificações com as chaves, certificados, índices,
arquivos dos proprietários, compartilhamento `.1.shr`, frases incorretas,
assinatura adulterada e abertura dos arquivos pela classe `Vault`.

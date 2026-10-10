# Cofre Digital — decisões provisórias

Este arquivo registra dúvidas que não são resolvidas completamente por
`Trabalho3.pdf` e `Trabalho3-Detalhamento.pdf`. As decisões abaixo são
provisórias e devem ser revistas quando o professor responder. Elas não
substituem o enunciado.

## 1. Acesso por grupo sem envelope

O enunciado manda listar arquivos do mesmo grupo, mas só define o envelope do
dono (`codigo.env`) e o envelope de compartilhamento individual
(`codigo.ID.shr`). Por exemplo, um usuário pode pertencer ao grupo do arquivo
sem ser o dono e sem possuir uma entrada no `share`.

**Decisão provisória:** o arquivo será exibido na listagem por causa do grupo.
Ao selecioná-lo, a autorização de visibilidade será reconhecida, mas a abertura
falhará com segurança se não existir um envelope destinado ao usuário. O
programa não tentará envelopes de outras pessoas, não criará criptografia de
grupo e não produzirá arquivo de saída. Para a auditoria, será registrado acesso
permitido (`7016`) seguido de falha de decriptação (`7020`).

## 2. Sequências de números repetidos no PIN

O enunciado proíbe “sequências de números repetidos”, mas não informa o tamanho
da repetição nem fornece exemplos. Isso permite interpretações diferentes para
PINs como `11111111`, `11234567` e `12121212`.

**Decisão provisória:** será rejeitado qualquer PIN que contenha dois ou mais
dígitos iguais consecutivos. Assim, `11111111` e `11234567` são inválidos, mas
`12121212` não é rejeitado por esta regra. As demais exigências de tamanho,
conteúdo numérico e confirmação continuam aplicáveis.

## 3. Derivação da chave AES com SHA1PRNG

Os PDFs exigem AES-256 gerada por `SHA1PRNG`, mas não fixam o charset da frase
nem a sequência exata das chamadas Java. Uma diferença nesse procedimento pode
gerar outra chave AES e impedir a leitura de arquivos válidos.

**Decisão provisória:** converter a frase para bytes em UTF-8, criar
`SecureRandom.getInstance("SHA1PRNG")`, fornecer esses bytes como semente e
inicializar `KeyGenerator.getInstance("AES")` com 256 bits e esse gerador. O
mesmo procedimento será usado para chaves privadas, segredos TOTP e sementes
dos envelopes. Frases ASCII continuam independentes do charset padrão da
máquina.

## 4. Frases das chaves do Pacote-T3

O pacote contém certificados, chaves privadas cifradas e arquivos protegidos,
mas não contém as frases necessárias para restaurar as chaves privadas. Não é
possível comprovar a abertura do cofre fornecido sem essas frases.

**Decisão provisória:** não adivinhar, não embutir e não criar fallback para as
frases do pacote. Elas serão sempre solicitadas ao usuário. Enquanto as frases
oficiais não forem fornecidas, os testes criptográficos serão executados com um
segundo conjunto independente, gerado para testes com frases próprias; o teste
com `Pacote-T3` permanecerá marcado como não verificado.

## 5. Escopo do teste individual

O professor informou que testará cada aplicação individualmente para verificar
se ela funciona em qualquer cenário. Ainda não está claro se isso significa
somente outro cofre válido, com dados e identificadores diferentes, ou se o
teste também incluirá arquivos adulterados, componentes ausentes e diferentes
formas de autorização.

**Decisão provisória:** considerar que será fornecido outro cofre válido que
respeite os formatos do trabalho e também preparar os casos de erro previstos
no enunciado, sem tentar aceitar formatos arbitrários que não façam parte da
especificação.

## Pergunta enviada ao professor

Professor, durante a implementação observamos que um usuário do mesmo grupo
pode visualizar um arquivo, embora não haja envelope de grupo definido; que a
expressão “sequências de números repetidos” não determina quais PINs devem ser
rejeitados; e que a geração AES com `SHA1PRNG` não especifica charset e chamadas
Java exatas. Também não encontramos as frases das chaves do `Pacote-T3`.

Poderia confirmar como deve funcionar o acesso somente por grupo, quais padrões
de PIN devem ser rejeitados, a forma exata de derivação AES com `SHA1PRNG` e as
frases de teste do `Pacote-T3`?

Além disso, no teste individual será fornecido outro cofre válido com
certificados, frases e usuários próprios? Devemos esperar também casos
adulterados e variações de proprietário, grupo e compartilhamento, ou somente
um cenário válido completo?

## Compilação e execução

O projeto usa somente Java SE, SQLite JDBC e BouncyCastle. No PowerShell, a
partir da raiz do projeto:

```powershell
javac -encoding UTF-8 -cp "lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" -d build src\*.java tests\Tests.java
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" DigitalVault
```

É possível informar outro banco no primeiro argumento de `DigitalVault`. Sem
argumento, será usado `cofre.db` no diretório corrente.

O visualizador de logs é um programa separado. Ele exige um terminal real para
ler a frase sem eco:

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" LogView caminho-da-chave.key
```

Um segundo argumento opcional seleciona outro arquivo de banco.

## Testes adicionais

```powershell
java --enable-native-access=ALL-UNNAMED -cp "build;lib\bcprov-jdk18on-1.80.2.jar;lib\sqlite-jdbc-3.41.2.2.jar" Tests
```

O teste gera identidades RSA, certificados, banco e cofre independentes em
`tests/additional-data`. A execução verificada em 09/10/2026 concluiu 52
verificações, incluindo criptografia, bcrypt, TOTP, PKCS#8, banco, share com ID
7, permissões, adulterações separadas, bloqueio e ordem cronológica dos logs.
O `Pacote-T3` teve estrutura, certificados e nome `.1.shr` verificados, mas sua
decriptação continua pendente das frases oficiais.
Os artefatos da execução aprovada foram preservados em
`tests/additional-data/verified-independent-case`.

O total de acessos é incrementado após MFA completo. O total de consultas é
incrementado somente quando o botão Listar conclui decriptação, assinatura,
parsing e apresentação do catálogo com sucesso.

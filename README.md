# CifraDoc

Projeto da disciplina PSE102A — Segurança da Informação, da PUCPR.

O CifraDoc é um portal de armazenamento seguro de documentos. Os usuários podem criar notas de texto, enviar arquivos PDF, DOCX e TXT de até 2 MiB e acessar seus próprios documentos.

## Funcionalidades

- **RA1 — Autenticação e controle de acesso:** login, senhas protegidas com scrypt, controle de sessão, permissões e proteção CSRF.
- **RA2 — Criptografia:** comunicação via HTTPS e criptografia AES-256-GCM dos títulos e conteúdos das notas e dos nomes e conteúdos dos arquivos armazenados no SQLite.
- **RA3 — Detecção e prevenção:** registro de falhas de login, bloqueio temporário, consulta de eventos de segurança e execução com privilégios reduzidos.

## Tecnologias e ambiente

O projeto utiliza Python, SQLite, Docker e Docker Compose. O ambiente possui dois contêineres conectados pela rede `lab_network`:

- `server`: executa o portal e armazena os documentos e eventos.
- `tester`: realiza os testes de segurança via HTTPS, validando o certificado do servidor.

## Instalação e execução

As instruções abaixo utilizam o PowerShell no Windows.

1. Instale o [Docker Desktop](https://docs.docker.com/desktop/setup/install/windows-install/) (Docker Engine 28 ou superior) e inicie-o no modo de contêineres Linux.
2. Clone o repositório ou baixe e extraia o código pelo GitHub.
3. Abra o PowerShell na pasta do projeto, onde está o arquivo `compose.yaml`.
4. Execute os comandos:

```powershell
docker compose config -q
docker compose up -d --build --wait server
docker compose ps
```

O primeiro build precisa de internet para baixar a imagem e as dependências. O servidor deve aparecer com o estado `healthy`.

### Acesso ao portal

Para acessar pelo Edge ou Chrome no Windows, importe o certificado público gerado pelo seu próprio contêiner:

```powershell
docker compose cp server:/app/cert/server.crt .\portal-lab.cer
certutil -user -addstore Root .\portal-lab.cer
```

Acesse [https://localhost:8443](https://localhost:8443). Se necessário, reinicie o navegador.

### Contas de demonstração

| Usuário | Senha fictícia | Permissão |
| --- | --- | --- |
| admin | `AdminLab!2026` | Consulta os registros de segurança e seus próprios documentos. |
| aluno | `AlunoLab!2026` | Cria e acessa seus próprios documentos. |
| colega | `ColegaLab!2026` | Cria e acessa seus próprios documentos. |

As contas são exclusivas do laboratório. Para definir outras senhas fictícias, copie `.env.example` para `.env` e edite o arquivo antes da primeira execução. Bancos já inicializados mantêm as credenciais originais. Não publique o `.env`.

## Demonstração

1. Entre com a conta `aluno` e crie uma nota ou envie um arquivo fictício.
2. Abra ou baixe o documento pela seção **Documentos**.
3. Copie o endereço de download e tente acessá-lo em outra sessão autenticada como `colega`. O acesso deve ser negado (HTTP 403).
4. Entre como `admin` e consulte os eventos na seção **Registros**.

## Testes de segurança

Com o servidor em execução e sem outras tentativas de login em andamento, execute:

```powershell
docker compose run --build --rm -T tester
$LASTEXITCODE
```

A suíte verifica autenticação, controle de acesso, comunicação HTTPS, bloqueio de login e operações com notas e arquivos. O teste de bloqueio aguarda a liberação automática da conta.

Ao final, copie e execute o comando de auditoria exibido pela suíte. Ele segue este formato, com os identificadores preenchidos pela execução:

```text
docker compose exec -T server python audit_storage.py --id ID_DA_NOTA --run-id ID_DA_EXECUCAO --file-id ID_DO_ARQUIVO
```

A auditoria verifica a criptografia dos registros de teste e procura marcadores de texto puro no SQLite. O código de retorno `0` indica sucesso em cada etapa; no PowerShell, consulte-o com `$LASTEXITCODE`.

## Arquivos do projeto

| Arquivo | Função |
| --- | --- |
| `server.py` | Aplicação web e mecanismos de segurança. |
| `client_tests.py` | Testes automatizados no segundo contêiner. |
| `audit_storage.py` | Auditoria dos registros criptografados. |
| `file_test_fixture.py` | PDF fictício utilizado nos testes. |
| `Dockerfile` e `compose.yaml` | Configuração dos contêineres, rede e volumes. |
| `requirements.txt` | Dependência do Python. |
| `.env.example` | Exemplo de configuração das contas. |
| `.gitignore` e `.dockerignore` | Exclusão de arquivos locais e dados sensíveis. |

## Encerramento

```powershell
docker compose down
```

Os dados permanecem nos volumes Docker. Após a demonstração, remova a confiança no certificado importado:

```powershell
$portalCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path .\portal-lab.cer).Path)
certutil -user -delstore Root $portalCert.Thumbprint
```

## Observações

O CifraDoc é um ambiente acadêmico de demonstração. A detecção de ameaças ocorre na aplicação, não em um IDS/IPS de rede. Utilize apenas dados fictícios e não publique senhas personalizadas, chaves, certificados, bancos de dados ou evidências locais.

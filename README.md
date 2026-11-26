# CifraDoc

Projeto da disciplina PSE102A, Segurança da Informação, da PUCPR. O portal permite que cada pessoa guarde notas de texto e arquivos e acesse seus próprios documentos. A demonstração usa três contas e registros fictícios.

| Resultado de aprendizagem | O que demonstrar |
| --- | --- |
| RA1 · Autenticação e acesso | Login, senhas derivadas com scrypt, sessão, permissões de usuário e administrador, autorização por proprietário e proteção CSRF. |
| RA2 · Criptografia | HTTPS com certificado validado pelo cliente. Título e conteúdo das notas, nomes e bytes dos arquivos cifrados com AES-256-GCM antes de gravar no SQLite. |
| RA3 · Detecção e prevenção | Falhas de login registradas, bloqueio temporário, logs administrativos e execução com privilégios reduzidos. |

## Como os dois nós se comunicam

```text
Windows / navegador ── HTTPS em localhost:8443 ──► server
                                                       ▲
                    rede Docker lab_network            │ HTTPS/TCP 8443
                                                       │ nome DNS server
                                                     tester
```

O `server` executa a aplicação Python e guarda os documentos e eventos no SQLite. O `tester` executa o cliente Python em outro contêiner. Ele usa o nome `server` para localizar o servidor na rede privada do projeto e recebe apenas o certificado público para validar o TLS. A porta do navegador é publicada no loopback do Windows. A chave AES, o SQLite e a chave privada TLS ficam em volumes acessíveis ao servidor.

## Pré-requisitos no Windows

1. Instale e abra uma versão atual do [Docker Desktop para Windows](https://docs.docker.com/desktop/setup/install/windows-install/), no modo de contêineres Linux. Aguarde o Docker informar que o mecanismo está em execução.
2. Extraia o projeto. Na pasta `CifraDoc`, abra o PowerShell. No Explorador de Arquivos, você pode digitar `powershell` na barra de endereços e pressionar Enter.
3. Confira o Docker e a configuração. O `-q` valida o arquivo sem imprimir os valores de configuração.

```powershell
docker version
docker compose version
docker compose config -q
```

A imagem inclui Python e dependências. O primeiro build precisa de internet para baixar a imagem e a biblioteca. Use Docker Engine 28 ou superior para o isolamento de portas publicadas no loopback em redes locais, conforme a [documentação de portas do Docker](https://docs.docker.com/engine/network/port-publishing/).

## Iniciar o servidor

```powershell
docker compose up -d --build --wait server
docker compose ps
```

O servidor deve aparecer como `healthy`. A verificação de saúde faz uma requisição HTTPS ao próprio serviço e valida o certificado. Abra [o portal em https://localhost:8443](https://localhost:8443).

### Confiar no certificado para a demonstração com o navegador

O cliente Python confia no certificado público do laboratório por meio do volume que recebe do Docker. Para Edge ou Chrome no Windows, importe o certificado público do **seu** contêiner no repositório de raízes do usuário atual. O bloco a seguir usa o `certutil` do Windows. [Documentação da Microsoft](https://learn.microsoft.com/pt-br/windows-server/administration/windows-commands/certutil)

```powershell
docker compose cp server:/app/cert/server.crt .\portal-lab.cer
certutil -user -addstore Root .\portal-lab.cer
Start-Process 'https://localhost:8443'
```

Se o navegador já estava aberto, feche-o e abra novamente. Use `localhost` ao acessar o portal. Após a apresentação, remova a confiança pelo identificador do certificado que você importou.

```powershell
$portalCert = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new((Resolve-Path .\portal-lab.cer).Path)
certutil -user -delstore Root $portalCert.Thumbprint
```

### Contas de demonstração

| Usuário | Senha fictícia padrão | Permissão |
| --- | --- | --- |
| `admin` | `AdminLab!2026` | Consulta os logs de segurança e acessa seus próprios documentos. |
| `aluno` | `AlunoLab!2026` | Salva notas e envia ou baixa seus próprios arquivos. |
| `colega` | `ColegaLab!2026` | Cria e consulta documentos próprios para demonstrar o isolamento entre contas. |

Use essas contas exclusivamente neste laboratório. Se quiser outras senhas fictícias, execute `Copy-Item .env.example .env`, edite `.env` antes do primeiro início e mantenha os valores fora do repositório. A criação inicial grava os verificadores de senha no banco persistente. Ao atualizar um banco existente, use as credenciais com que as contas foram cadastradas.

## Demonstrar o envio e o download

1. Entre com `aluno`. Em **Novo documento**, use **Nota de texto** para salvar texto ou **Enviar arquivo** para escolher um PDF, DOCX ou TXT fictício. Cada arquivo deve conter dados e ter até 2 MiB.
2. Em **Documentos**, use **Abrir** para ler uma nota ou **Baixar** para recuperar um arquivo. Para conferir que os bytes foram preservados, use `Get-FileHash -Algorithm SHA256` nos arquivos original e baixado e compare os valores de `Hash`.
3. Copie o endereço de **Baixar**. Abra esse mesmo endereço em uma sessão separada com `colega` para demonstrar o HTTP 403. Em uma janela sem sessão, o portal redireciona para o login.
4. Entre com `admin` em outra sessão e abra **Registros**. Confira os eventos de envio, download autorizado e acesso negado. O administrador tem permissão para consultar os registros e acessar seus próprios documentos.

Você pode abrir o arquivo baixado no programa de costume. A cópia armazenada no SQLite continua cifrada depois do download.

## Executar os testes e a auditoria

Comece sem outras tentativas de login em andamento. O teste de bloqueio usa poucas tentativas incorretas controladas e espera a liberação automática. A execução pode levar pouco mais de um minuto.

```powershell
New-Item -ItemType Directory -Path .\evidencias -Force | Out-Null
docker compose run --build --rm -T tester | Tee-Object -FilePath .\evidencias\testes-docker.txt
$LASTEXITCODE
```

Anote os resultados e os dois endereços IP exibidos pela conexão HTTPS. O cliente roda 13 casos das notas e sete casos dos arquivos, T16 a T22. No fim, copie e execute **o comando de auditoria impresso pela suíte**. Ele usa os identificadores da execução e dos registros de teste.

```text
docker compose exec -T server python audit_storage.py --id ID_DA_NOTA --run-id ID_DA_EXECUCAO --file-id ID_DO_ARQUIVO
```

A auditoria executa T08 e T10 para a nota e T23 e T24 para o arquivo. Ela autentica os dados cifrados com AES-GCM e procura marcadores conhecidos no SQLite, incluindo os arquivos auxiliares presentes. As verificações demonstram a proteção dos registros usados no teste. A saída apresenta identificadores, resultados e comprimentos, sem exibir conteúdo ou chaves. Registre a saída e o código de retorno de cada etapa. O código `0` indica sucesso.

Registre os resultados da execução atual da equipe para usar como evidências no vídeo e no documento-resumo.

## Observar rede, ambiente e eventos

```powershell
docker compose ps
docker compose port server 8443
$portalServer = docker compose ps -q server
$portalNetwork = docker inspect --format '{{range $name, $net := .NetworkSettings.Networks}}{{$name}}{{end}}' $portalServer
docker network inspect --format '{{range .IPAM.Config}}{{.Subnet}} {{end}}' $portalNetwork
docker compose exec -T server id
docker compose exec -T server cat /etc/os-release
docker compose exec -T server python -c "import platform, sqlite3, ssl, cryptography; print(platform.python_version(), cryptography.__version__, sqlite3.sqlite_version, ssl.OPENSSL_VERSION)"
docker compose logs --tail 50 server
```

O IP do `tester` deve vir da saída da própria suíte. O contêiner é removido ao terminar e pode receber outro IP em uma nova execução. Para consultar os eventos pela interface, entre como `admin` e abra **Registros**. A tela usa o horário de Brasília, e o SQLite e a saída do servidor mantêm UTC. Use uma janela separada ou faça logout antes de trocar de conta. Uma sessão já aberta pode continuar durante um bloqueio de novos logins.

Para demonstrar a persistência, crie um documento fictício pelo navegador, execute `docker compose restart server`, aguarde o estado `healthy` em `docker compose ps` e entre novamente para recuperar o mesmo documento. Faça essa demonstração depois que a suíte terminar.

## Encerrar e solucionar problemas

```powershell
docker compose down
```

Esse comando para os contêineres e conserva os dados em volumes. Para usar um laboratório separado, execute os comandos com um nome de projeto diferente, por exemplo `docker compose -p portal-demo up -d --build --wait server`, e inclua `-p portal-demo` nos demais comandos. Encerre a instância anterior se a porta 8443 estiver ocupada.

| Sintoma | Verificação |
| --- | --- |
| Docker não reconhecido ou daemon indisponível | Abra o Docker Desktop, aguarde sua inicialização e execute `docker version`. Confirme que há informação do servidor e modo Linux no Docker Desktop. |
| Porta 8443 ocupada | Execute `Get-NetTCPConnection -LocalPort 8443 -State Listen` para identificar o processo ou projeto que usa a porta. Encerre apenas o serviço de laboratório identificado. |
| Servidor não fica saudável | Execute `docker compose ps` e `docker compose logs --tail 50 server`. Confira os avisos de configuração, permissões dos volumes ou certificado. |
| Navegador exibe erro de certificado | Confira o endereço `localhost`, o relógio Windows e se foi importado o certificado público da instância atual. Se recriou a instância, confira o certificado novamente. |
| Cliente apresenta erro TLS | Confirme `server` saudável, o destino `https://server:8443` e o certificado público do volume. O erro indica falha de confiança ou de conexão que precisa ser corrigida. |
| Login recusado após alterar `.env` | Confira a senha do primeiro início. As contas e verificadores existentes são mantidos. |
| Login retorna HTTP 429 | Aguarde o tempo de bloqueio informado e tente uma vez com a conta fictícia correta. |
| Auditoria não acha o documento ou recusa a execução | Repita a suíte, copie a linha de auditoria de sua saída e confira se ela aponta para o mesmo projeto Compose usado pelo teste. |
| Erro de chave ao abrir um banco existente | Preserve os volumes. Restaure a chave AES correspondente ao banco ou use um ambiente separado para a demonstração. |

## Arquivos do projeto

| Arquivo | Função |
| --- | --- |
| `server.py` | Interface web, TLS, sessões, validação, proteção dos documentos e auditoria. |
| `client_tests.py` | Verificações HTTP/TLS no segundo nó. |
| `audit_storage.py` | Validadores do registro cifrado e dos arquivos SQLite no servidor. |
| `file_test_fixture.py` | PDF fictício usado pelo cliente e pela auditoria. |
| `compose.yaml` e `Dockerfile` | Construção das imagens, serviços, rede, volumes e permissões. |
| `requirements.txt`, `.env.example` | Dependência Python e exemplo de configuração das contas fictícias. |
| `.gitignore`, `.dockerignore` | Regras para excluir dados, segredos e arquivos locais. |

## Escopo de segurança

- O portal cifra o título e o texto das notas. Para arquivos, cifra separadamente o nome e o conteúdo, cada um com seu próprio nonce, o que permite listar o nome sem abrir os bytes do arquivo. O SQLite guarda a cifra como BLOB. ID, proprietário e data ficam como metadados da aplicação.
- O servidor verifica a sessão e o proprietário antes de devolver o arquivo como anexo por HTTPS. O envio aceita PDF, DOCX ou TXT de até 2 MiB. A aplicação confere o cabeçalho do PDF, a estrutura interna do DOCX e se o TXT usa UTF-8. Use apenas arquivos fictícios no laboratório.
- O escopo é um único servidor. As sessões e o controle de bloqueio ficam em memória. As trilhas persistem no SQLite. Contas compartilhando um IP podem ser afetadas pelo mesmo bloqueio.
- O controle RA3 detecta falhas de autenticação que chegam à aplicação. Um IDS de rede monitora tráfego em um ponto da rede para alertar. Um IPS de rede também pode intervir no tráfego observado.
- O certificado e as contas pertencem à demonstração. Guarde o `.env`, os volumes, as chaves e as evidências que contêm dados locais fora do repositório. Em uma implantação real, seria necessário tratar operação contínua, gestão de segredos, rotação de chaves, backup e recuperabilidade.
- Faça as verificações de segurança apenas contra os serviços deste laboratório, com dados fictícios. Complete os campos do documento-resumo e confira os requisitos do professor antes de enviar.

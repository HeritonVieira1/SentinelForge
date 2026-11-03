# SentinelForge

API REST em ASP.NET Core (.NET 10) para gerenciamento de vulnerabilidades de segurança. Projeto open source de portfólio com foco em desenvolvimento seguro e DevSecOps.

> Estado atual: **Fase 5** (automação DevSecOps sobre a gestão de vulnerabilidades da Fase 4). Documentação técnica:
> [docs/vulnerability-management.md](docs/vulnerability-management.md) (módulo de vulnerabilidades) e
> [security/devsecops-pipeline.md](security/devsecops-pipeline.md) (pipeline de segurança).

## Arquitetura

```
Api ──► Application ──► Domain
 └────► Infrastructure ──► Application
```

| Projeto | Responsabilidade |
|---|---|
| `SentinelForge.Domain` | Entidades, enums e invariantes (validação, datas UTC). Sem dependências. |
| `SentinelForge.Application` | Casos de uso (`AuthService`, `UserService`, `VulnerabilitiesService`, `CveService`...), política de senha e contratos (repositórios, `ICurrentUser`, hasher, tokens, `ICveLookup`). Depende só do Domain. |
| `SentinelForge.Infrastructure` | EF Core + Npgsql (`DbContext`, migrações, repositórios, auditoria), hash de senha (PBKDF2), emissão de JWT e cliente do NVD. |
| `SentinelForge.Api` | Entrada HTTP: endpoints, validação do JWT, políticas, rate limiting, CORS, tratamento de erros e comando de provisionamento. |
| `SentinelForge.UnitTests` | Testes de domínio e de regras de dependência entre camadas. |
| `SentinelForge.IntegrationTests` | Testes da API e da persistência contra PostgreSQL real. |

## Persistência

- **EF Core 10 + Npgsql**, um `IEntityTypeConfiguration<T>` por entidade em `Infrastructure/Persistence/Configurations`.
- **Ids** `Guid` v7 gerados na aplicação; **datas** sempre UTC (`timestamp with time zone`); o domínio rejeita datas não UTC.
- **Enums** (`UserRole`, `Severity`, `VulnerabilityStatus`, `AuditAction`) gravados como texto com `CHECK` no banco, além da validação no domínio.
- **Sem exclusão física:** todas as FKs são `ON DELETE RESTRICT`; usuários e aplicações são desativados (`IsActive`) e o `SaveChanges` rejeita `Remove` dessas entidades.
- **Auditoria:** um interceptor grava um `AuditLog` (na mesma transação) para criação/alteração de `User`, `Application` e `Vulnerability`, com ator (`ICurrentUser`), IP, valores antigos/novos em `jsonb`. `PasswordHash` é sempre gravado como `[REDACTED]`. `AuditLog` é append-only.

### Modelo de dados

```
users 1───* applications 1───* vulnerabilities *───0..1 users (responsável)
  │                                   
  └───0..* audit_logs   (UserId nulo = evento de sistema)
```

| Tabela | Campos principais | Restrições / índices |
|---|---|---|
| `users` | Id, Name, Email, PasswordHash, Role, IsActive, CreatedAt, UpdatedAt, FailedLoginCount, LockoutEnd | e-mail **único** (`ux_users_email`, normalizado em minúsculas); CHECK em Role |
| `applications` | Id, Name, Description, RepositoryUrl, IsActive, CreatedAt, UpdatedAt, OwnerUserId | FK owner; índices em Name e OwnerUserId; URL deve ser http(s) |
| `vulnerabilities` | Id, Title, Description, Severity, CvssScore?, CvssVersion?, CvssVector?, Status, Category, CveId?, Remediation, DiscoveredAt, ResolvedAt?, VerifiedAt?, ResolvedByUserId?, ApplicationId, AssignedUserId?, CreatedByUserId, CreatedAt, UpdatedAt | severidade **sempre coerente com a pontuação** (CHECK), CHECKs de status e datas de resolução/verificação, concorrência otimista (`xmin`); índices em aplicação, responsável, criador, severidade, status, CVE e data |
| `vulnerability_history` | Id, VulnerabilityId, ChangeType, Field?, OldValue?, NewValue?, Justification?, ActorUserId, IpAddress?, CreatedAt | **append-only** (aplicação e triggers no banco); índice por vulnerabilidade e data |
| `audit_logs` | Id, UserId?, Action, EntityName, EntityId, OldValues?, NewValues?, IpAddress?, CreatedAt | índices por entidade, usuário e data; ações: Created, Updated, LoginSucceeded, LoginFailed, LoggedOut, RefreshTokenReuseDetected, SessionsRevoked |
| `refresh_tokens` | Id, UserId, SessionId, TokenHash (SHA-256), CreatedAt, ExpiresAt, UsedAt?, RevokedAt?, RevokedReason?, CreatedByIp? | hash **único**; índices por sessão e usuário |

## Autenticação e autorização (Fase 3)

### Visão geral
- **Senhas:** `PasswordHasher` do ASP.NET Core Identity (PBKDF2-HMAC-SHA512, 210.000 iterações, salt por senha). Hashes com parâmetros antigos são atualizados no login seguinte. Política: 12–128 caracteres com minúscula, maiúscula, dígito e símbolo, sem termos comuns nem o nome do e-mail.
- **Access token:** JWT HS256 de curta duração (15 min), com `iss`, `aud`, `exp`, `sub`, `role`, `sid` (sessão) e `jti`. Sem nome, e-mail ou outro dado pessoal. A validação checa assinatura, issuer, audience, expiração e algoritmo (só HS256; tokens sem assinatura são rejeitados).
- **Verificação no servidor:** além do token, a cada requisição o servidor confirma no banco que o usuário está ativo, que o papel não mudou e que a sessão não foi revogada. Logout, desativação, troca de papel e revogação valem **imediatamente**.
- **Refresh token:** 256 bits aleatórios, de uso único, com rotação a cada renovação; só o hash SHA-256 é guardado. Todos os tokens de um login compartilham uma sessão (`SessionId`). **Reapresentar um token já usado revoga a sessão inteira** e gera o evento `RefreshTokenReuseDetected` na auditoria.
- **Segurança por padrão:** toda rota exige autenticação, exceto `/health` e `/api/auth/*`.

### Endpoints
| Método e rota | Quem | Descrição |
|---|---|---|
| `POST /api/auth/register` | anônimo | Cadastra usuário (sempre `Developer`; um campo `role` enviado é ignorado). `201`, `400` (validação), `409` (e-mail em uso). |
| `POST /api/auth/login` | anônimo | Emite access token + refresh token. Falhas retornam sempre `401 Invalid credentials.` |
| `POST /api/auth/refresh` | anônimo | Troca o refresh token (cookie ou corpo) por um novo par. |
| `POST /api/auth/logout` | anônimo | Revoga a sessão do refresh token informado. Idempotente (`204`). |
| `GET /api/users`, `PUT /api/users/{id}/role`, `POST /api/users/{id}/revoke-sessions` | Administrator | Gestão de usuários e sessões. |
| `GET /api/users/{id}` | autenticado | Administrator vê qualquer usuário; os demais, somente a si mesmos (outro id → `404`). |
| `GET /api/applications`, `GET /api/applications/{id}`, `GET /api/applications/{id}/vulnerabilities` | autenticado | Filtrados pelo acesso do usuário (ver RBAC). |
| `POST /api/vulnerabilities`, `PUT /api/vulnerabilities/{id}`, `PATCH .../assign` | Administrator, SecurityAnalyst | Cadastra, atualiza e atribui (Developer: ver seção de vulnerabilidades). |
| `GET /api/vulnerabilities`, `GET .../{id}`, `GET .../{id}/history`, `GET .../summary` | autenticado | Filtros, paginação, ordenação, histórico e indicadores, sempre restritos ao acesso do usuário. |
| `PATCH /api/vulnerabilities/{id}/status` | autenticado (regras por papel) | Move a vulnerabilidade pelo workflow. |
| `GET /api/cve/{cveId}` | Administrator, SecurityAnalyst | Consulta o CVE no NVD. |
| `GET /api/audit-logs` | Administrator | Consulta a auditoria (paginada; filtros `entityName`, `entityId`). |

### Perfis e permissões (RBAC)
| Perfil | Pode |
|---|---|
| `Administrator` | Gerenciar usuários (papéis, revogar sessões), consultar auditoria, cadastrar e gerenciar todas as vulnerabilidades. |
| `SecurityAnalyst` | Cadastrar, classificar, atribuir, atualizar status e **validar correções** de todas as vulnerabilidades; consultar CVE e indicadores. Sem acesso a usuários e auditoria. |
| `Developer` (padrão) | Ver apenas aplicações **autorizadas**: as que ele possui (`OwnerUserId`) ou nas quais é o responsável (`AssignedUserId`) por alguma vulnerabilidade. Só altera vulnerabilidades **atribuídas a ele** (remediação e status `InProgress`/`Resolved`). |

Regras de segurança: o papel nunca vem do cliente; ninguém altera o **próprio** papel; trocar o papel de alguém revoga as sessões dele e gera registro de auditoria (valores antigo e novo, autor e IP). Recursos que o usuário não pode ver retornam **404** (e não 403), para não revelar que existem (anti-IDOR).

> O registro (`POST /api/auth/register`) informa `409` para e-mail repetido, o que permite descobrir e-mails cadastrados. O risco é reduzido pelo rate limiting; se for inaceitável, a alternativa é resposta idêntica e confirmação por e-mail (fora do escopo desta fase).

### Como usar
```powershell
# 1) Cadastrar
curl -X POST http://localhost:5089/api/auth/register -H "Content-Type: application/json" `
  -d '{"name":"Ana","email":"ana@exemplo.com","password":"<senha forte>"}'

# 2) Login (X-Token-Delivery: body também devolve o refresh token no corpo; veja "Clientes externos")
curl -X POST http://localhost:5089/api/auth/login -H "Content-Type: application/json" `
  -H "X-Token-Delivery: body" -d '{"email":"ana@exemplo.com","password":"<senha forte>"}'

# 3) Chamar a API com o access token
curl http://localhost:5089/api/applications -H "Authorization: Bearer <accessToken>"

# 4) Renovar (rotação: o token anterior deixa de valer)
curl -X POST http://localhost:5089/api/auth/refresh -H "Content-Type: application/json" -d '{"refreshToken":"<refreshToken>"}'

# 5) Encerrar sessão
curl -X POST http://localhost:5089/api/auth/logout -H "Content-Type: application/json" -d '{"refreshToken":"<refreshToken>"}'
```
Quando o access token expira (`401`), chame `/refresh`. Se `/refresh` também falhar, o usuário precisa fazer login de novo.

### Armazenamento do refresh token (navegadores e clientes externos)
- **Navegadores (padrão):** o refresh token vai **somente** em um cookie `sf_refresh` com `HttpOnly`, `Secure`, `SameSite=Strict` e `Path=/api/auth`. O JavaScript não o lê (mitiga XSS) e `SameSite=Strict` mitiga CSRF. O access token fica em memória do app.
- **Clientes externos** (CLI, serviços, apps móveis): enviam o cabeçalho `X-Token-Delivery: body` no login/refresh e recebem o `refreshToken` no corpo. Devem guardá-lo em local protegido (keychain/secret store do SO), nunca em log, URL ou armazenamento em texto puro, e enviá-lo no corpo de `/refresh` e `/logout`.

### Proteção contra força bruta
- **Por conta:** 5 falhas consecutivas bloqueiam a conta por 15 minutos; a resposta continua genérica. (Contrapartida: um atacante pode bloquear contas conhecidas; o rate limit por IP reduz isso.)
- **Por IP:** `429` após 10 requisições/min em `/api/auth/*` e 300/min no restante (configurável em `RateLimiting`). Atrás de proxy reverso o IP visto é o do proxy: configure *forwarded headers* confiáveis antes de publicar.
- Contas inexistentes consomem o mesmo tempo de CPU que contas reais (sem enumeração por tempo).

### Outras proteções
HTTPS obrigatório e HSTS fora de Development; CORS fechado por padrão (só origens em `Cors:AllowedOrigins`); erros como `ProblemDetails` sem stack trace, SQL ou nomes internos; cabeçalhos `X-Content-Type-Options`, `X-Frame-Options`, `Referrer-Policy` e `Cache-Control: no-store` em `/api`; logs de login registram usuário e IP, nunca senhas, tokens ou e-mails digitados.

### Provisionar o primeiro administrador
Não há credencial administrativa fixa. O comando só funciona **enquanto não existir nenhum administrador** e lê a senha apenas de uma variável de ambiente (nunca de argumento de linha de comando, arquivo ou log):

```powershell
$env:SENTINELFORGE_ADMIN_PASSWORD = Read-Host "Senha do administrador"   # ou injetada pelo seu secret manager
dotnet run --project src/SentinelForge.Api -- provision-admin --email admin@exemplo.com --name "Administrador"
Remove-Item Env:SENTINELFORGE_ADMIN_PASSWORD
```
Códigos de saída: `0` criado, `1` dados inválidos (ex.: senha fraca), `2` já existe administrador, `64` uso incorreto. Os demais papéis são concedidos por um administrador via `PUT /api/users/{id}/role`.

### Variáveis de ambiente / configuração
| Variável | Obrigatória | Descrição |
|---|---|---|
| `ConnectionStrings__DefaultConnection` | sim (para usar o banco) | Connection string do PostgreSQL. |
| `Jwt__SigningKey` | **sim** | Chave de assinatura do JWT, ≥ 32 caracteres. A API **não inicia** sem ela. |
| `Jwt__Issuer`, `Jwt__Audience` | não | Padrão `SentinelForge` / `SentinelForge.Api`. |
| `Jwt__AccessTokenMinutes` | não | Validade do access token (1–60, padrão 15). |
| `Auth__MaxFailedLoginAttempts`, `Auth__LockoutMinutes`, `Auth__RefreshTokenDays` | não | Padrão 5, 15 e 7. |
| `RateLimiting__AuthPermitLimit`, `RateLimiting__GlobalPermitLimit` (+ `...WindowSeconds`) | não | Limites por IP. |
| `Cors__AllowedOrigins__0`, `__1`... | não | Origens permitidas (vazio = nenhuma). |
| `SENTINELFORGE_ADMIN_PASSWORD` | só no provisionamento | Senha do primeiro administrador. |
| `Vulnerabilities__RequireIndependentVerification` | não | `true` (padrão): quem corrigiu não verifica a própria correção. |
| `Nvd__ApiKey` | não | Chave da API do NVD (eleva a cota de 5 para 50 req/30 s). Secreta: use user-secrets/variável de ambiente. |
| `Nvd__TimeoutSeconds`, `Nvd__CacheMinutes` | não | Padrão 10 e 60. |
| `RateLimiting__CvePermitLimit` | não | Limite por IP do endpoint CVE (padrão 20/min). |

Gerar uma chave forte (compatível com Windows PowerShell 5.1 e PowerShell 7):
```powershell
$b = New-Object byte[] 48; [Security.Cryptography.RandomNumberGenerator]::Create().GetBytes($b)
dotnet user-secrets set "Jwt:SigningKey" ([Convert]::ToBase64String($b)) --project src/SentinelForge.Api
```
Trocar a chave invalida todos os access tokens emitidos. Nunca versione chaves ou connection strings.
## Gestão de vulnerabilidades (Fase 4)

> Regras completas, tabelas e exemplos em [docs/vulnerability-management.md](docs/vulnerability-management.md).

**Classificação CVSS.** A severidade é **sempre calculada** a partir da pontuação (faixas oficiais: `None` 0.0 · `Low` 0.1–3.9 ·
`Medium` 4.0–6.9 · `High` 7.0–8.9 · `Critical` 9.0–10.0). Sem pontuação a severidade é `Unrated`: nada é inventado, e o
cliente não escolhe a severidade (o banco também rejeita divergências). Aceita CVSS 4.0, 3.1 e 3.0 e armazena o vetor
(validado). A nota **não** é calculada a partir do vetor.

**Workflow.** `New → Triaged → InProgress → Resolved → Verified`, com `Reopened` e `AcceptedRisk`.
Transições inválidas retornam `409`; `AcceptedRisk` exige justificativa; **quem corrigiu não pode verificar a própria
correção** (nem um administrador). Todas as mudanças vão para o histórico imutável (`GET /api/vulnerabilities/{id}/history`).

```powershell
# Cadastrar (SecurityAnalyst/Administrator)
curl -X POST http://localhost:5089/api/vulnerabilities -H "Authorization: Bearer <token>" -H "Content-Type: application/json" `
  -d '{"applicationId":"<guid>","title":"SQL Injection no login","category":"Injection","cveId":"CVE-2024-12345","cvssScore":9.8,"cvssVersion":"4.0"}'

# Listar com filtros, ordenação e paginação
curl "http://localhost:5089/api/vulnerabilities?severity=Critical&status=New&sortBy=CvssScore&sortDir=desc&search=injection&page=1&pageSize=20" -H "Authorization: Bearer <token>"

# Atribuir e mudar o status
curl -X PATCH http://localhost:5089/api/vulnerabilities/<id>/assign -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"assignedUserId":"<guid>"}'
curl -X PATCH http://localhost:5089/api/vulnerabilities/<id>/status -H "Authorization: Bearer <token>" -H "Content-Type: application/json" -d '{"status":"AcceptedRisk","justification":"Sem exposição externa"}'

# Indicadores e consulta ao NVD
curl http://localhost:5089/api/vulnerabilities/summary -H "Authorization: Bearer <token>"
curl http://localhost:5089/api/cve/CVE-2021-44228 -H "Authorization: Bearer <token>"
```

**Indicadores (`/summary`).** Total, contagem por severidade e por status, críticas abertas, por aplicação, por responsável e
tempo médio de resolução (`null` quando não há dados), calculados em SQL e restritos ao que o usuário pode ver.

**Integração com o NVD.** `GET /api/cve/{cveId}` consulta a [API 2.0 do NVD](https://nvd.nist.gov/developers/vulnerabilities) e
devolve descrição, CVSS (3.0/3.1/4.0), referências (somente `http(s)`) e a fonte preservada (`source`, `sourceUrl`,
`retrievedAt`). Tem timeout (10 s), cache, limite de uso respeitando a cota oficial (5 req/30 s sem chave, 50 com chave) e
disjuntor: se o NVD estiver indisponível o endpoint responde `503` + `Retry-After` (ou `429` quando o NVD limitar) e **o
restante da plataforma continua funcionando**. Chave opcional em `Nvd__ApiKey`.

**Segurança.** Autorização por objeto aplicada na própria consulta ao banco (sem IDOR); recurso inacessível = `404`
idêntico ao inexistente (sem enumeração); DTOs só com campos permitidos (sem mass assignment); busca literal e
parametrizada; parâmetros validados (`400` com detalhes); alterações concorrentes detectadas (`409`).
## DevSecOps (Fase 5)

O repositório se protege com um pipeline de segurança no GitHub Actions. Documentação completa na pasta [`security/`](security/):
[pipeline](security/devsecops-pipeline.md) · [security gates](security/security-gates.md) ·
[containers](security/container-security.md) · [DAST](security/dast-testing.md) ·
[cadeia de suprimentos](security/supply-chain-security.md).

| Camada | Ferramenta | Workflow | Bloqueia quando |
|---|---|---|---|
| Build e testes | `dotnet` (analisadores como erro, NuGetAudit, restore travado) + xUnit com PostgreSQL | `ci.yml` | build, formatação, lock divergente ou qualquer teste (inclui autenticação/autorização) falha |
| SAST | CodeQL (C#, `security-extended`) | `codeql.yml` | alerta de segurança (exigir como check/regra no repositório) |
| Segredos | Gitleaks (+ push protection do GitHub) | `secrets-scan.yml` | qualquer segredo confirmado |
| SCA | Dependency Review + Dependabot | `dependency-review.yml` | dependência nova/alterada com advisory High/Critical ou licença copyleft forte |
| Containers | Trivy (Dockerfile, dependências, imagem) + SBOM CycloneDX | `container-security.yml` | Critical; High com correção; segredo; misconfiguração High/Critical |
| DAST | OWASP ZAP em ambiente isolado (Docker Compose) | `dast.yml` | alerta de risco alto não classificado como falso positivo |
| Publicação | GHCR + Cosign (keyless) + atestados de proveniência e SBOM | `container-security.yml`, `release.yml` | qualquer controle acima falha ⇒ **nada é publicado** |

**Gates como código:** critérios em `security/security-policy.json`, exceções (justificativa, responsável, aprovador diferente,
validade ≤ 90 dias, referência, sem curingas) em `security/exceptions.json`, avaliador testado em `security/scripts/evaluate_gate.py`.

**Rodar:** abra um PR (tudo roda sozinho); ou *Actions → workflow → Run workflow*. DAST ativo: *Actions → DAST → mode: active*.
**Ver relatórios:** aba *Security → Code scanning* e artifacts de cada run (`container-security-reports`, `zap-reports-*`, `test-results`).
**Localmente:** os comandos estão em [security/devsecops-pipeline.md](security/devsecops-pipeline.md#localmente).

**Imagem Docker:** `docker build -t sentinelforge .` (multi-stage, runtime distroless, usuário não-root, bases fixadas por digest).
Publicada em `ghcr.io/heritonvieira1/sentinelforge` somente pela `main` ou por tags `vX.Y.Z`, após o Security Gate; referencie por **digest**.

## Pré-requisitos

- [.NET SDK 10](https://dotnet.microsoft.com/download)
- PostgreSQL acessível (ex.: via Docker). O usuário precisa de `CREATEDB` para rodar os testes de integração.

## Configuração do PostgreSQL

A connection string **nunca** é versionada. Use uma destas formas:

```powershell
# Variável de ambiente (ASP.NET Core converte "__" em ":")
$env:ConnectionStrings__DefaultConnection = "Host=localhost;Port=5432;Database=<db>;Username=<user>;Password=<senha>"

# ou user-secrets (armazenado fora do repositório)
dotnet user-secrets set "ConnectionStrings:DefaultConnection" "<connection string>" --project src/SentinelForge.Api
```

Sem a connection string, o `DbContext` e os repositórios não são registrados: em **Production** a API sobe, mas só `/health` funciona.
Em **Development** o ASP.NET valida o grafo de injeção de dependências na inicialização e a API **não inicia** sem ela, então
defina sempre `ConnectionStrings__DefaultConnection` ao desenvolver.

## Migrações

As ferramentas do EF estão em `dotnet-tools.json`:

```powershell
dotnet tool restore

# criar uma migração
dotnet ef migrations add <Nome> --project src/SentinelForge.Infrastructure --startup-project src/SentinelForge.Api --output-dir Persistence/Migrations

# aplicar no banco apontado por ConnectionStrings__DefaultConnection
dotnet ef database update --project src/SentinelForge.Infrastructure --startup-project src/SentinelForge.Api

# gerar o script SQL (para revisão / pipelines)
dotnet ef migrations script --project src/SentinelForge.Infrastructure --startup-project src/SentinelForge.Api
```

A aplicação **não** aplica migrações automaticamente na inicialização.

## Executar a aplicação

```powershell
dotnet build
dotnet run --project src/SentinelForge.Api --launch-profile http
```

`http://localhost:5089/health` e `http://localhost:5089/swagger` (Development).

## Executar os testes

```powershell
dotnet test
```

Os testes de integração (persistência e segurança) exigem `ConnectionStrings__DefaultConnection` definida; a chave JWT dos testes é gerada aleatoriamente a cada execução. Cada execução cria um banco `sentinelforge_test_<guid>`, aplica as migrações reais e o remove ao final; o banco configurado não é alterado. Sem a variável, esses testes falham com uma mensagem explicativa (não são ignorados silenciosamente).

## Notas de segurança da persistência (Fase 2)

- Senhas: apenas `PasswordHash` é armazenado (ver a seção de autenticação).
- Consultas via EF Core (parametrizadas); logs de dados sensíveis do EF permanecem desativados.
- Nenhuma credencial no repositório (user-secrets / variáveis de ambiente).
- Restrição de acesso por usuário autenticado: implementada na Fase 3 (RBAC e verificação de propriedade no servidor).



# SentinelForge

API REST em ASP.NET Core (.NET 10) para gerenciamento de vulnerabilidades de segurança. Projeto open source de portfólio com foco em desenvolvimento seguro e DevSecOps.

> Estado atual: **Fase 2** (persistência). Autenticação, autorização e endpoints de negócio chegam nas próximas fases.

## Arquitetura

```
Api ──► Application ──► Domain
 └────► Infrastructure ──► Application
```

| Projeto | Responsabilidade |
|---|---|
| `SentinelForge.Domain` | Entidades, enums e invariantes (validação, datas UTC). Sem dependências. |
| `SentinelForge.Application` | Abstrações dos casos de uso (ex.: `ICurrentUser`). Depende só do Domain. |
| `SentinelForge.Infrastructure` | EF Core + Npgsql: `DbContext`, configurações, migrações, auditoria. |
| `SentinelForge.Api` | Entrada HTTP: `/health`, OpenAPI/Swagger (apenas em Development), ator da requisição. |
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
| `users` | Id, Name, Email, PasswordHash, Role, IsActive, CreatedAt, UpdatedAt | e-mail **único** (`ux_users_email`, normalizado em minúsculas); CHECK em Role |
| `applications` | Id, Name, Description, RepositoryUrl, IsActive, CreatedAt, UpdatedAt, OwnerUserId | FK owner; índices em Name e OwnerUserId; URL deve ser http(s) |
| `vulnerabilities` | Id, Title, Description, Severity, Status, Category, CveId?, Remediation, DiscoveredAt, ResolvedAt?, ApplicationId, AssignedUserId? | CHECK em Severity/Status; `ResolvedAt` preenchido **se e somente se** Status = Resolved; índices em aplicação, responsável, severidade, status, CVE e data |
| `audit_logs` | Id, UserId?, Action, EntityName, EntityId, OldValues?, NewValues?, IpAddress?, CreatedAt | índices por entidade, usuário e data |

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

Sem a connection string, a API sobe somente com `/health` (o `DbContext` não é registrado).

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

Os testes de integração de persistência exigem `ConnectionStrings__DefaultConnection` definida. Cada execução cria um banco `sentinelforge_test_<guid>`, aplica as migrações reais e o remove ao final; o banco configurado não é alterado. Sem a variável, esses testes falham com uma mensagem explicativa (não são ignorados silenciosamente).

## Segurança (Fase 2)

- Senhas: apenas `PasswordHash` é armazenado; o algoritmo de hash e o fluxo de login são da Fase 3.
- Consultas via EF Core (parametrizadas); logs de dados sensíveis do EF permanecem desativados.
- Nenhuma credencial no repositório (user-secrets / variáveis de ambiente).
- Restrição de acesso por usuário autenticado: a abstração `ICurrentUser` já alimenta a auditoria; a aplicação das regras de acesso aos dados depende da autenticação (Fase 3) e ainda **não** está implementada.

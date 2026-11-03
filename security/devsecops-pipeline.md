# Pipeline DevSecOps

Visão geral da automação de segurança do SentinelForge. Detalhes por área:
[Security Gates](security-gates.md) · [Containers](container-security.md) · [DAST](dast-testing.md) ·
[Cadeia de suprimentos](supply-chain-security.md).

## Arquitetura

```
 Pull Request ─┬─ CI ........................ build, formatação, testes (unit + integração/PostgreSQL), lint dos workflows
               ├─ CodeQL .................... SAST C# (security-extended) → Code Scanning
               ├─ Secrets scan .............. Gitleaks (commits da PR + árvore) + autoteste do gate
               ├─ Dependency review ......... SCA: advisories High/Critical e licenças em dependências novas/alteradas
               ├─ Container security ........ Trivy (Dockerfile, deps, imagem) + SBOM + GATE  ─╮ (publish = dry-run em PR)
               └─ DAST (baseline) ........... ZAP passivo autenticado em ambiente isolado     │
                                                                                              ▼
 Push na main ── os mesmos ─────────────────────────────────────────────────► publish: GHCR + Cosign + atestados
 Tag vX.Y.Z ──── release.yml: tag na main? checks verdes? → CI → container gate → publish → GitHub Release
 Agenda ──────── CodeQL e Gitleaks (histórico) semanais · DAST ATIVO semanal · Dependabot semanal
```

## Workflows

| Workflow | Gatilhos | Faz | Permissões (`GITHUB_TOKEN`) |
|---|---|---|---|
| `ci.yml` | PR, push `main`, manual, reutilizável | `restore --locked-mode`, `dotnet format --verify-no-changes`, build (warnings = erro), testes unitários e de integração com PostgreSQL efêmero (senha aleatória), testes da lógica dos gates, lint com actionlint, job agregador `CI gate` | `contents: read` |
| `codeql.yml` | PR, push `main`, segunda 03:17 UTC, manual | CodeQL para C# (`security-extended`) | `contents: read`, `security-events: write`, `actions: read` |
| `secrets-scan.yml` | PR, push `main`, segunda 04:41 UTC, manual | Autoteste do gate + Gitleaks (commits e árvore), SARIF no Code Scanning | `contents: read`, `security-events: write` |
| `dependency-review.yml` | PR | Dependency Review (política em `.github/dependency-review-config.yml`) | `contents: read` |
| `container-security.yml` | PR, push `main` e `validation/**`, manual, reutilizável | Build → Trivy (config, fs, image) → SBOM → gate → publicação (ou dry-run) | build: `contents: read`, `security-events: write` · publish: `packages: write`, `id-token: write`, `attestations: write` |
| `dast.yml` | PR (se mexeu em código/imagem), push `main`, quarta 05:23 UTC, manual | ZAP em ambiente isolado (baseline ou ativo) | `contents: read` |
| `release.yml` | tag `vX.Y.Z` | Verifica tag/checks → CI → container + publicação → GitHub Release | por job; só o último tem `contents: write` |

### Princípios de segurança do próprio pipeline

- **Permissões mínimas:** `permissions: {}` no topo de todos os workflows; cada job declara só o que usa.
- **Sem segredos no repositório:** nenhum workflow usa segredos além do `GITHUB_TOKEN` efêmero. Credenciais de teste
  (banco do CI, banco/JWT/admin do DAST) são **geradas em tempo de execução**, mascaradas e descartadas.
- **Sem `pull_request_target`:** PRs (inclusive de forks) rodam com o token somente leitura e **sem acesso a segredos**; o
  upload de SARIF é pulado em PRs de fork.
- **Actions por SHA completo** e **ferramentas por digest** (ver [supply-chain-security.md](supply-chain-security.md)).
- **`persist-credentials: false`** em todos os checkouts; **timeouts** em todos os jobs; `concurrency` cancela execuções
  obsoletas de PR (releases nunca são canceladas).
- **Sem injeção por expressão:** valores de eventos (`github.ref_name`, SHAs, inputs) chegam ao shell via `env:`, nunca
  interpolados em `run:`. O `actionlint` (com ShellCheck) roda no CI.
- **Logs:** segredos de teste são mascarados com `::add-mask::`; os relatórios do Gitleaks são redigidos (`--redact`).

## Como executar

| Objetivo | Como |
|---|---|
| Tudo que roda no PR | Abra um Pull Request; os checks aparecem na aba *Checks* |
| Um workflow sob demanda | Actions → escolha o workflow → *Run workflow* (disponível em `container-security`, `dast`, `codeql`, `secrets-scan`, `ci`) |
| DAST ativo | Actions → DAST → *Run workflow* → `mode: active` (apenas o ambiente isolado é atacado) |
| Validar um gate sem risco de publicar | Empurre uma branch `validation/<nome>`: `container-security` roda inteiro e a publicação é sempre **dry-run** |
| Release | Com a `main` verde: `git tag vX.Y.Z && git push origin vX.Y.Z` |

### Localmente

```bash
# 1) Build, formatação e testes (os de integração precisam de PostgreSQL: ConnectionStrings__DefaultConnection)
dotnet restore --locked-mode && dotnet format --verify-no-changes && dotnet build && dotnet test

# 2) Segredos: autoteste do gate + varredura real do histórico e da árvore
bash security/scripts/secret-scan-selftest.sh
docker run --rm -v "$PWD:/repo:ro" ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f \
  git /repo --config /repo/.gitleaks.toml --redact --no-banner

# 3) Lógica dos gates
python3 -I -m unittest discover -s security/tests -v

# 4) Imagem + Trivy + gate: ver security/container-security.md
# 5) DAST: MODE=baseline|active API_IMAGE=sentinelforge:scan bash security/dast/run-dast.sh
# 6) Lint dos workflows
docker run --rm -v "$PWD:/repo" -w /repo rhysd/actionlint@sha256:b1934ee5f1c509618f2508e6eb47ee0d3520686341fec936f3b79331f9315667
```

## Onde ver os relatórios

| Relatório | Onde |
|---|---|
| Resultado dos testes (`.trx`) | artifact `test-results` do run do CI; resumo na aba *Summary* do job |
| CodeQL, Trivy, Gitleaks | **Security → Code scanning** (categorias `/language:csharp`, `trivy-image`, `trivy-dockerfile`, `trivy-dependencies`, `gitleaks-commits`) |
| Trivy (JSON/SARIF/tabela), SBOM, resumo do gate | artifact `container-security-reports` |
| Dependency review | aba *Summary* do job `Dependency review` |
| ZAP (HTML/JSON/Markdown) e resumo do gate | artifact `zap-reports-<baseline\|active>` |
| Gitleaks (SARIF redigido) | artifact `gitleaks-reports` |

## Como interpretar vulnerabilidades

1. **Severidade ≠ risco.** É a gravidade genérica do problema; o risco depende de a aplicação usar o componente.
2. **Corrigível?** `FixedVersion` preenchido ⇒ atualize. Vazio ⇒ avalie mitigação e prazo.
3. **Aplicável?** O componente é carregado/alcançável? Em imagem *distroless*, muitos pacotes do SO nunca são executados.
4. **Decida e registre:** corrigir (preferido), mitigar, ou aceitar por **exceção** com dono, aprovador, prazo e referência
   ([security-gates.md](security-gates.md)). Alertas do ZAP são **hipóteses**: reproduza antes de classificar.

## Validação: o que foi executado de verdade

Todos os resultados abaixo vêm de execuções reais (runs do GitHub Actions ou execuções locais com as mesmas imagens). Nada foi
simulado. Ao introduzir falhas para provar um gate, usei branches/PRs **descartáveis**, nunca a `main` nem código de produção.

| # | Validação | Resultado | Evidência |
|---|---|---|---|
| 1 | Pipeline de build | ✅ passou; 1ª execução no runner já validou o restore travado gerado em Linux | run `41572778785` |
| 2 | Testes automáticos | ✅ 127 unitários + 176 de integração (PostgreSQL) no runner; hoje 127 + 194 | run `41572778785` |
| 3 | CodeQL em C# | ✅ banco construído (8,5 MiB), 63 regras, **0 alertas** | análise `2082761595` |
| 4 | Gitleaks detecta segredo fictício | ✅ autoteste gera 5 tipos de segredo **em runtime** (nunca versionados) e confirma detecção e falha do gate; e confirma que placeholders e código comum **não** são acusados | run `41573882773` |
| 5 | Dependency Review | ✅ PR descartável adicionou `Newtonsoft.Json 12.0.1`: **GHSA-5crp-9r3c-p9vr (high)** detectado e PR reprovado; o CI reprovou em paralelo (lock divergente, `NU1004`) e o restore local com lock regerado falhou em `NU1903` | PR #3 (fechado), runs `41574194903`, `41574194895` |
| 6 | Trivy identifica vulnerabilidade | ✅ na base `aspnet:6.0` (EOL), **38 achados bloqueantes reais (7 Critical, 31 High)** | run `41575306851` |
| 7 | ZAP contra ambiente isolado | ✅ no runner: baseline autenticado, 26 URLs, gate aprovado; local: varredura **ativa** completa | run `41581041445` |
| 8 | Security Gate bloqueia cenários | ✅ Critical/High/segredo/misconfiguração/exceções inválidas (26 testes da política) e gate real do container (item 6) | `security/tests`, run `41575306851` |
| 9 | Publicação impedida se o controle falha | ✅ no cenário do item 6 o job `Security gate` falhou, `Upload scanned image` foi ignorado e **`Publish to GHCR` foi ignorado** | run `41575306851` |
| 10 | Publicação permitida se aprovado | ◐ **dry-run validado** (imagem limpa: image ID conferido, login/push/assinatura/atestados ignorados, mostra as tags que publicaria). **Publicação real ainda não executada**: depende do merge na `main` | run `41575310649` |
| — | `release.yml` | ◐ validado só com `actionlint`. **Não executado**: o gatilho é uma tag `vX.Y.Z`, que aciona a publicação. Tentei provar o caminho negativo (tag fora da `main` deve bloquear) e deixei de fazê-lo por precaução | — |

### Defeitos reais que a própria validação encontrou

| Onde | O que | Correção |
|---|---|---|
| Aplicação (DAST) | `GET /api/audit-logs?entityName=%00` → **500** (NUL rejeitado pelo PostgreSQL); mesma classe em `search` e campos de corpo | Rejeição de caracteres de controle no domínio e nos parâmetros + rede de segurança no tratador; 18 testes de regressão |
| Gitleaks | Regra de connection string larga demais acusava `password = valor` em código C# (8 falsos positivos) | Regra reescrita exigindo o contexto `Chave=Valor;…`; sem allowlist; regressão no autoteste |
| DAST | O ZAP **não enviava o `Authorization`** (`-z "-config replacer…"`); a varredura "autenticada" era anônima | Autenticação por *hook*; verificada com servidor de eco; pré/pós-condições no script |
| DAST | O ZAP revogou a **própria sessão** ao atacar `revoke-sessions` com o ID do admin de teste | Usuário-vítima separado + pós-condição de sessão |
| DAST | OpenAPI sem exemplos ⇒ ataques nunca passavam do roteamento (404) | IDs reais semeados injetados como `example` |
| Gitleaks (script) | O autoteste tratava "Gitleaks não rodou" como "nenhum achado" | Ausência de relatório agora **falha** |
| Dependency Review | O Dependency graph estava desativado no repositório | Habilitei o **Dependabot alerts** (pré-requisito) |
| Documentação | O README dizia que, sem connection string, a API sobe só com `/health`; em **Development** isso não vale (a validação de DI falha) | README corrigido |

## Limitações e pendências conhecidas

1. **Os checks só impedem o merge se a `main` exigir os checks** (branch protection / rulesets). Hoje a `main` não tem proteção:
   os workflows protegem a **publicação**, mas não impedem um merge com check vermelho. Ver "Aplicação nas branches" em
   [security-gates.md](security-gates.md).
2. **Primeira publicação real e `release.yml`** ainda não foram exercitados (itens 10 e "release").
3. **Cosign/atestados**: a verificação documentada em [container-security.md](container-security.md) deve ser confirmada contra a
   primeira imagem realmente publicada (a identidade do certificado depende do workflow reutilizado).
4. **Dependabot security updates** continua desativado (PRs automáticos de correção de segurança); só as atualizações de
   versão semanais estão configuradas.
5. **DAST** usa um único usuário administrador: não detecta IDOR/RBAC (coberto pelos testes de integração).
6. Custo de tempo: o DAST ativo leva alguns minutos; por isso roda semanalmente e sob demanda.

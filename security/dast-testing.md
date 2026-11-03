# DAST com OWASP ZAP

Workflow: [`dast.yml`](../.github/workflows/dast.yml). Script único (CI e local): [`dast/run-dast.sh`](dast/run-dast.sh).
Ferramenta: ZAP 2.17.0 (imagem fixada por digest), usando `zap-api-scan.py` com o contrato OpenAPI da própria API.

## Regra de ouro

> **Nunca** execute varredura ativa contra sistemas externos ou de produção sem autorização explícita e por escrito.

O desenho torna isso difícil por construção: o alvo é fixo (`http://api:8080`) e vive numa rede Docker **interna**
(`internal: true`), sem rota para a internet nem para o host. O scanner só enxerga os containers do próprio ambiente, e a
API testada também não consegue chamar nada externo (por exemplo, o NVD). O script não aceita URL de alvo.

## Ambiente isolado

`security/dast/docker-compose.yml` sobe, a cada execução:

| Componente | Detalhe |
|---|---|
| PostgreSQL | `postgres:18.6` por digest, dados em `tmpfs` (somem ao final), nenhuma porta publicada |
| API SentinelForge | A imagem construída pelo Dockerfile, em modo **Production**, `read_only`, `cap_drop: ALL`, `no-new-privileges` |
| Credenciais | Geradas na hora (senha do banco, chave JWT, senha do administrador de teste); mascaradas nos logs do Actions; nunca gravadas em arquivo |
| Migrações | Script SQL idempotente gerado pelo EF Core e aplicado no banco efêmero |
| Administrador | Criado pelo comando oficial `provision-admin` (senha só por variável de ambiente) |
| Limites de volume | `RateLimiting__*` e bloqueio de conta relaxados **apenas aqui**: o objetivo é testar a lógica, não o rate limiting (coberto pelos testes de integração) |

Etapas do script: subir o banco → migrar → provisionar admin → subir a API → aguardar `/health` → obter o OpenAPI → logar →
semear dados → **pré-verificar a autenticação** → ZAP → **pós-verificar a sessão** → gate → destruir tudo.

### Por que obter o OpenAPI de uma instância em Development

A API de produção não expõe `/openapi`. Uma instância descartável em Development publica o documento (só descreve rotas); o
ataque é feito contra a instância em **Production**.

## Modos

| Modo | Quando | O que faz |
|---|---|---|
| `baseline` | PRs que mexem em código/imagem, pushes na `main` | `zap-api-scan.py -S`: análise **passiva** autenticada |
| `active` | Agenda semanal (quarta), execução manual | Acrescenta **ataques ativos** (SQLi, XSS, path traversal, injeção de comandos, etc.) — somente no ambiente isolado |

Executar localmente (requer Docker e o SDK do .NET):

```bash
docker build -t sentinelforge:scan .
MODE=baseline API_IMAGE=sentinelforge:scan bash security/dast/run-dast.sh     # passivo
MODE=active   API_IMAGE=sentinelforge:scan bash security/dast/run-dast.sh     # ataques (só no ambiente isolado)
# relatórios em ./dast-reports (zap-report.html/json/md, gate-summary.md)
```

## Autenticação do scanner (e armadilhas que encontramos)

O ZAP precisa enviar o JWT do administrador de teste; senão a varredura é anônima e quase nada é exercitado. Lições reais
deste projeto, **todas comprovadas com evidência** e protegidas por verificações no script:

1. **`-z "-config replacer…"` não funcionou** no ZAP 2.17.0: um servidor de eco mostrou `Authorization: None` em todas as
   requisições. A autenticação é feita por um *hook* (`security/dast/zap_hooks.py`) que cria a regra do Replacer; o token vai
   por variável de ambiente do container. Com o hook, o eco mostrou o cabeçalho em essencialmente todas as requisições.
2. **O OpenAPI sem exemplos faz o ZAP usar literais** (`id`, `cveId`): a rota `{id:guid}` responde 404 antes de qualquer
   handler, e os ataques nunca chegam à lógica. `prepare_openapi.py` injeta `example` com IDs reais de registros **semeados
   no banco efêmero**.
3. **O ZAP revogou a própria sessão.** Ele atacou `POST /api/users/{id}/revoke-sessions` com o ID do administrador de teste
   (que eu tinha usado como exemplo) e, a partir daí, centenas de requisições viraram 401. A API estava correta; o erro foi do
   teste. Agora os endpoints `/api/users/{id}` apontam para um **usuário-vítima** separado.
4. **Pré e pós-condições:** antes do ZAP o script exige `200` com o token em rotas protegidas; depois do ZAP exige que o token
   ainda valha. Se a sessão cair no meio da varredura, o job **falha** em vez de passar em silêncio.

## O que foi encontrado de verdade

| Achado | Natureza | Resolução |
|---|---|---|
| `GET /api/audit-logs?entityName=%00` → **HTTP 500** | **Defeito real.** Caractere NUL chegava ao PostgreSQL, que o recusa em texto. Mesma classe de falha possível em `search` e em campos de texto de corpos de requisição. | Corrigido em três camadas: validação do domínio (`Guard` rejeita caracteres de controle), validação dos parâmetros de consulta (400) e rede de segurança no tratador de exceções (erros SQLSTATE classe 22 → 400). 18 testes de regressão; sem a correção, 14 quebram. |
| `GET /api/cve/{id}` → 503 | **Falso positivo / comportamento projetado.** No ambiente isolado não há rota para o NVD, e o endpoint degrada para 503 de propósito. | Documentado; severidade baixa, não bloqueia. |
| "A Client Error response code was returned" (400/401/404) | **Informativo.** Resposta correta a entradas inválidas, rotas inexistentes ou sem credencial. | Nenhuma ação. |
| "Authentication Request Identified" | **Informativo.** Identifica o endpoint de login. | Nenhuma ação. |
| "Sensitive Information in URL" (`AssignedUserId`) | **Falso positivo.** É o *nome* de um filtro cujo valor é um GUID, não um dado sensível. | Documentado; informativo. |

## Como o gate interpreta os alertas

Política em [`security-policy.json`](security-policy.json): alerta ZAP de risco **alto** (`riskcode` 3) **bloqueia**; risco
**médio** exige avaliação; baixo e informativo não bloqueiam. Mas um alerta é uma **hipótese**, não uma vulnerabilidade
confirmada. Procedimento:

1. Abra o relatório HTML (`zap-report.html`, artifact `zap-reports-<modo>`) e localize o alerta, a URL, o parâmetro e a evidência.
2. **Reproduza** manualmente (por exemplo com `curl` no ambiente isolado) e leia o log da API (`api-tail.log`).
3. Classifique:
   - **Confirmado** → corrija o código e acrescente um **teste de regressão** (foi o que fizemos com o NUL).
   - **Falso positivo** → registre uma exceção em [`exceptions.json`](exceptions.json) com `tool: "zap"`, `id` = `alertRef`
     do alerta, `target` = host, justificativa (por que não é explorável e como foi verificado), responsável, aprovador diferente,
     validade (máx. 90 dias) e referência. **Não** use arquivos de regra que ignoram alertas globalmente.
4. Reavalie as exceções no vencimento: a exceção expira e o alerta volta a bloquear.

## Limites e próximos passos

- A cobertura vem do OpenAPI: rotas não descritas (e fluxos que dependam de estado entre requisições) não são atacados.
- O ZAP não conhece regras de negócio: **IDOR, elevação de privilégio e violação de RBAC** continuam cobertos pelos testes de
  integração (varredura com um único usuário administrador não os detecta). Um próximo passo é rodar a varredura também com
  um usuário de baixo privilégio e comparar as respostas.
- Varredura ativa pode levar vários minutos; por isso roda semanalmente e sob demanda, e o PR usa só o modo passivo.

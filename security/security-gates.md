# Security Gates

Os Security Gates decidem se uma mudança pode ser mesclada e se uma imagem pode ser publicada. A política é **código**:
[`security-policy.json`](security-policy.json) (critérios), [`exceptions.json`](exceptions.json) (exceções controladas) e
[`scripts/evaluate_gate.py`](scripts/evaluate_gate.py) (avaliador, com testes em [`tests/`](tests/test_evaluate_gate.py)).

Princípio geral: **falha fechado**. Relatório ausente, JSON ilegível, política inválida ou exceção malformada reprovam o
gate (exit 2); nunca "passam por falta de dados".

## Critérios

| Controle | Ferramenta | Decisão |
|---|---|---|
| Build com falha (inclui analisadores como erro e NuGetAudit) | `dotnet build` no CI | **Bloqueia** |
| Formatação / estilo | `dotnet format --verify-no-changes` | **Bloqueia** |
| Testes com falha (unitários e de integração em PostgreSQL) | CI | **Bloqueia** |
| Falha de **autenticação** nos testes (login, JWT, refresh, bloqueio) | CI | **Bloqueia** (são testes como quaisquer outros) |
| Falha de **autorização** nos testes (RBAC, IDOR, elevação de privilégio) | CI | **Bloqueia** |
| Lock file divergente (`packages.lock.json`) | `dotnet restore --locked-mode` | **Bloqueia** |
| Segredo confirmado (qualquer severidade) | Gitleaks | **Bloqueia** |
| Segredo na imagem/repositório | Trivy (`secret`) | **Bloqueia** |
| Vulnerabilidade **Critical** (com ou sem correção disponível) | Trivy | **Bloqueia** (exceção formal possível) |
| Vulnerabilidade **High com correção disponível** | Trivy | **Bloqueia** |
| Vulnerabilidade **High sem correção** | Trivy | **Exige avaliação** (aparece no resumo; não bloqueia) |
| Vulnerabilidade Medium | Trivy | Exige avaliação (não bloqueia) |
| Misconfiguração **High/Critical** (Dockerfile, IaC) | Trivy | **Bloqueia** |
| Dependência **nova ou atualizada** com advisory **High/Critical** | Dependency Review (PR) | **Bloqueia** |
| Licença AGPL/GPL/SSPL em dependência nova | Dependency Review (PR) | **Bloqueia** |
| Alerta CodeQL | Code Scanning | Ver "CodeQL" abaixo |
| Alerta ZAP de risco **alto** | OWASP ZAP | **Bloqueia** (a confirmar; falso positivo só por exceção) |
| Alerta ZAP de risco médio | OWASP ZAP | Exige avaliação (não bloqueia) |

### Por que "High" tem tratamento diferente de "Critical"

- **Critical** bloqueia sempre: o risco é alto demais para decidir caso a caso no pipeline.
- **High com correção disponível** bloqueia: existe ação concreta (atualizar) e custo baixo.
- **High sem correção** não bloqueia automaticamente (bloquearia para sempre por algo que ninguém consegue corrigir), mas
  **fica visível** no resumo do job e no relatório, e exige avaliação humana: aplicabilidade real, mitigação, prazo.
  Se a avaliação concluir que é aceitável, registre uma **exceção** (abaixo); se concluir que não, bloqueie manualmente.

### "Aplicável"

O Trivy relata vulnerabilidades do **pacote presente**, não do **código alcançável**. A decisão de aplicabilidade é humana:
"o componente vulnerável é carregado/usado por esta aplicação?" Um achado Critical que a avaliação concluir **não aplicável**
(por exemplo, biblioteca presente na imagem mas nunca carregada) é tratado por exceção documentada, não por supressão global.

### CodeQL

Os resultados vão para o **Code Scanning**. Para que alertas **bloqueiem o merge**, configure no repositório uma regra
"Require code scanning results" (ver "Aplicação nas branches" abaixo). O limiar recomendado é **High ou superior** para
alertas de segurança.

## Exceções controladas

Toda exceção é uma entrada em [`exceptions.json`](exceptions.json), revisada em Pull Request:

```json
{
  "id": "CVE-2099-0001",
  "tool": "trivy",
  "package": "libfoo",
  "justification": "Biblioteca presente na imagem base, mas nunca carregada pelo processo (verificado em ...).",
  "owner": "pessoa-responsavel",
  "approved_by": "outra-pessoa",
  "created": "2026-11-03",
  "expires": "2027-01-15",
  "risk_ref": "https://github.com/HeritonVieira1/SentinelForge/issues/123"
}
```

Regras (validadas pelo avaliador; qualquer violação reprova o gate com exit 2):

| Campo | Regra |
|---|---|
| `justification` | Obrigatória, no mínimo 30 caracteres, descrevendo **por que** o risco é aceitável. |
| `owner` | Obrigatório: quem responde pelo risco e pela remoção da exceção. |
| `approved_by` | Obrigatório e **diferente de `owner`** (aprovação independente). |
| `created` / `expires` | Obrigatórios (`AAAA-MM-DD`). `expires` posterior a `created` e no máximo **90 dias** depois. |
| `risk_ref` | Obrigatório: URL `https://…` ou identificador (`RISK-123`) que permita rastrear a análise. |
| Escopo | `package` **ou** `target` obrigatório. A exceção vale só para aquele par achado + componente. |
| Curingas | **Proibidos** em `id`, `package` e `target`. Não existe exceção global. |

Comportamento:

- Exceção **vigente** libera apenas o achado correspondente, que continua listado no resumo ("Exceções vigentes") com
  owner, aprovador e referência.
- Exceção **vencida** deixa de valer: o achado volta a bloquear e o resumo avisa "Exceção vencida".
- Exceção **malformada** invalida o arquivo inteiro (exit 2), para que ninguém dependa de uma exceção que não está
  em ordem.
- **Não há baseline** nem allowlist global: no Gitleaks, falso positivo é resolvido tornando a **regra mais precisa**
  (foi o que aconteceu ao refinar a regra de connection string), e não escondendo o arquivo.
- Aprovação "adequada": como exceções são código revisado em PR, configure o repositório para exigir a aprovação de
  alguém diferente do autor em mudanças de `security/exceptions.json` (CODEOWNERS + regra de revisão).

## Como o gate é aplicado

| Momento | O que roda | Efeito |
|---|---|---|
| Pull Request | CI, CodeQL, Gitleaks, Dependency review, Container security (build + scan + gate), DAST baseline (se mexeu em código/imagem) | Cada workflow vermelho reprova o PR |
| Push na `main` | Os mesmos + publicação (dry-run se o gate falhar não há publicação) | Gate reprovado ⇒ **nada é publicado** |
| Tag `vX.Y.Z` | `release.yml`: verifica a tag e os checks do commit, CI, gate da imagem, publicação, assinatura, atestados, Release | Qualquer etapa reprovada ⇒ **sem imagem e sem Release** |
| Agenda | CodeQL e Gitleaks (histórico) semanais; DAST ativo semanal | Detecta vulnerabilidade nova em código que não mudou |

### Aplicação nas branches

Um workflow vermelho só **impede o merge** se a branch `main` exigir esses checks. Isso é configuração do repositório
(Settings → Rules → Rulesets), e não do código. Recomendado exigir:

`CI gate`, `Gitleaks`, `Analyze (csharp)`, `Dependency review`, `Build, scan and gate`, e "Require code scanning results"
(CodeQL, limiar High). Sem isso os workflows informam e protegem a **publicação**, mas não impedem o merge.

## Executar o avaliador localmente

```bash
# testes da política
python3 -I -m unittest discover -s security/tests -v

# aplicar a política a relatórios reais do Trivy
python3 security/scripts/evaluate_gate.py --policy security/security-policy.json \
  --trivy trivy-image.json --trivy trivy-config.json --trivy trivy-fs.json
echo $?   # 0 aprovado · 1 bloqueado · 2 erro de configuração/entrada
```

> Os relatórios usados em `security/tests/` são **sintéticos** e servem apenas para exercitar a lógica da política.
> Achados reais vêm dos scanners; veja os cenários validados em [devsecops-pipeline.md](devsecops-pipeline.md).

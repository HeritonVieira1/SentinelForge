# Segurança de containers

Workflow: [`container-security.yml`](../.github/workflows/container-security.yml). Imagem: [`Dockerfile`](../Dockerfile).

## A imagem

| Decisão | Motivo |
|---|---|
| Multi-stage: SDK só no estágio de build | A imagem final não carrega compilador, SDK nem código-fonte. |
| Runtime `aspnet:10.0-noble-chiseled` | Distroless: **sem shell e sem gerenciador de pacotes**, superfície de ataque e CVEs bem menores. |
| Usuário não-root (`USER 1654`) | Um comprometimento não ganha root no container. |
| Bases fixadas por **versão e digest** | A tag pode ser reapontada; o digest não. O Dependabot propõe as atualizações. |
| `dotnet restore --locked-mode` | O build falha se qualquer dependência divergir do `packages.lock.json`. |
| Sem segredos na imagem | `Jwt__SigningKey`, `ConnectionStrings__DefaultConnection` e `Nvd__ApiKey` só entram por variável de ambiente/secret store em tempo de execução. `.dockerignore` barra `.env`, chaves e certificados do contexto de build. |
| Porta 8080 e TLS na borda | Não-root não pode usar portas < 1024; HTTPS/HSTS são responsabilidade do proxy/ingress. |
| Sem `HEALTHCHECK` no Dockerfile | A imagem não tem shell/curl. O orquestrador deve sondar `GET /health` (o Trivy aponta isso como DS-0026, severidade LOW, que não bloqueia). |

Tamanho medido: ~187 MB. Execução como UID 1654 e resposta de `/health`/`401` em rotas protegidas foram verificadas.

## O pipeline

```
build ──► Trivy: Dockerfile (config) ─┐
      ├─► Trivy: repositório (fs)  ───┼─► Security Gate ──► (aprovado) ──► publish: GHCR + Cosign + atestados
      └─► Trivy: imagem            ───┘          │
                                       SBOM CycloneDX         reprovado ⇒ publish é ignorado (needs)
```

1. **Build** da imagem (`--provenance=false --sbom=false`: atestados verificáveis são anexados depois, na publicação).
2. **Trivy** (executado como container fixado por digest) gera JSON, que é a fonte de verdade; SARIF e tabela são
   derivados (`trivy convert`). Três escopos: `config` (Dockerfile/IaC), `fs` (dependências .NET pelos lock files,
   segredos, misconfiguração) e `image` (pacotes do SO, dependências do app, segredos).
3. **SBOM** CycloneDX da imagem (`sbom.cdx.json`).
4. **Security Gate** ([security-gates.md](security-gates.md)): Critical bloqueia; High com correção bloqueia; segredo bloqueia.
5. **Relatórios** como artifact (`container-security-reports`, 30 dias) e SARIF no Code Scanning (categorias
   `trivy-image`, `trivy-dockerfile`, `trivy-dependencies`).
6. **Publicação**, somente se o gate aprovou (ver abaixo).

## Publicação no GHCR

- Registro: `ghcr.io/heritonvieira1/sentinelforge`. Autenticação com o `GITHUB_TOKEN` do próprio job
  (`packages: write`), lido de variável de ambiente e passado por stdin; nunca aparece em argumentos ou logs.
- **Quando publica:** push/dispatch na `main` e tags `vX.Y.Z`. Em qualquer outra ref (PRs, branches de feature,
  `validation/**`) o job roda em **dry-run**: carrega a imagem, confere o ID e mostra o que publicaria, sem login nem push.
- **A imagem publicada é a que foi escaneada:** o build produz um `image.tar` que é enviado como artifact apenas se o gate
  aprovou; o job de publicação o carrega e **compara o image ID** com o do scan antes de publicar.
- **Tags rastreáveis:** `sha-<12 primeiros do commit>` sempre; `main` para a branch; `X.Y.Z` e `X.Y` nos releases.
  **Não há `latest`.** Para produção, referencie pelo **digest** (`@sha256:…`).
- **Assinatura** Cosign *keyless* (identidade OIDC do workflow, sem chave privada para vazar) e atestados de **proveniência
  de build** e **SBOM** (`actions/attest-*`, gravados também no registro).
- `override-used`: a execução manual para validar o gate com uma base antiga **nunca** publica.

## Critérios de bloqueio (resumo)

Critical: bloqueia · High com correção: bloqueia · High sem correção: exige avaliação · segredo: bloqueia ·
misconfiguração High/Critical: bloqueia. Detalhes e exceções em [security-gates.md](security-gates.md).

## Como interpretar um relatório do Trivy

| Campo | Significado |
|---|---|
| `Severity` | Gravidade base da vulnerabilidade, não o risco para **esta** aplicação. |
| `FixedVersion` vazio | Ainda não há correção publicada pelo mantenedor da distro/pacote. |
| `PkgName` / `InstalledVersion` | Componente afetado. Em imagens, costuma vir do SO (ex.: `libc6`), não do código da aplicação. |
| `Status` (`affected`, `will_not_fix`, `fixed`…) | Posição do mantenedor da distro. |
| Aplicabilidade | **Decisão humana**: o componente é carregado/usado? Há mitigação? Registre por exceção, com prazo. |

Estado observado da imagem atual (resultado real, Trivy 0.76.1): **0 Critical, 0 High**; 2 Medium em `libc6`
(sem correção publicada, listados como "requer avaliação"); 1 LOW no Dockerfile (sem `HEALTHCHECK`).

## Executar localmente

```bash
docker build --provenance=false --sbom=false -t sentinelforge:local .
docker save sentinelforge:local -o image.tar

TRIVY=ghcr.io/aquasecurity/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c
docker run --rm -v "$PWD:/w" $TRIVY image --input /w/image.tar --scanners vuln,secret --format json --output /w/trivy-image.json
docker run --rm -v "$PWD:/w:ro" -v "$PWD:/out" $TRIVY config /w --format json --output /out/trivy-config.json
python3 security/scripts/evaluate_gate.py --policy security/security-policy.json \
  --trivy trivy-image.json --trivy trivy-config.json
```

## Verificar uma imagem publicada

```bash
IMAGE=ghcr.io/heritonvieira1/sentinelforge@sha256:<digest>

# proveniência e SBOM atestados pelo GitHub
gh attestation verify oci://$IMAGE --owner HeritonVieira1

# assinatura Cosign keyless (a identidade esperada é o workflow deste repositório)
cosign verify $IMAGE \
  --certificate-oidc-issuer https://token.actions.githubusercontent.com \
  --certificate-identity-regexp '^https://github.com/HeritonVieira1/SentinelForge/\.github/workflows/'
```

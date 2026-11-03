# Segurança da cadeia de suprimentos

Objetivo: saber **o que** entra no software, **de onde** vem, **quem** o construiu e **provar** isso a quem o consome.

## Controles implementados

| Risco | Controle | Onde |
|---|---|---|
| Dependência .NET trocada/atualizada sem revisão | `packages.lock.json` em todos os projetos + `dotnet restore --locked-mode` (CI, CodeQL, Dockerfile). Dependência direta **ou transitiva** divergente quebra o build. | `Directory.Build.props`, `ci.yml`, `Dockerfile` |
| Dependência com vulnerabilidade conhecida | **NuGetAudit** (`NuGetAuditMode=all`, nível `low`) a cada restore; com `TreatWarningsAsErrors` vira erro de build. Dependency Review nas PRs. | `Directory.Build.props`, `dependency-review.yml` |
| Dependência com licença incompatível | `deny-licenses` (AGPL, GPL, SSPL) no Dependency Review | `.github/dependency-review-config.yml` |
| Action de terceiros comprometida | Todas as Actions fixadas por **SHA de commit completo** (com a versão em comentário); permissões mínimas por job; `persist-credentials: false` | `.github/workflows/*.yml` |
| Ferramenta de segurança trocada | Trivy, Gitleaks, ZAP, actionlint e Python executados como imagens fixadas por **digest** | workflows, `security/dast/` |
| Imagem base trocada/vulnerável | Bases com versão + digest; runtime *distroless*, não-root; Trivy a cada build | `Dockerfile`, `container-security.yml` |
| Atualização automática sem teste | **Dependabot** só abre PR (NuGet, Docker, GitHub Actions); nada é mesclado automaticamente; cada PR passa por CI + CodeQL + Gitleaks + Dependency Review | `.github/dependabot.yml` |
| "O que há dentro?" | **SBOM CycloneDX** da imagem (inclui dependências transitivas e pacotes do SO), gerado pelo Trivy a cada build e anexado ao Release | `container-security.yml`, `release.yml` |
| "Quem construiu isto?" | **Atestado de proveniência** (SLSA, `actions/attest-build-provenance`) e **atestado de SBOM** gravados no registro | `container-security.yml` |
| "Isto foi alterado depois?" | **Assinatura Cosign keyless** por digest; a identidade é o workflow, sem chave privada para vazar | `container-security.yml` |
| Publicação indevida | Só `main` ou tag `vX.Y.Z`; só após o gate; imagem publicada = imagem escaneada (ID conferido); tag precisa estar na `main` e com checks verdes | `container-security.yml`, `release.yml` |
| Segredo no código/histórico | Gitleaks (histórico completo + árvore + commits da PR) e push protection do GitHub | `secrets-scan.yml`, `.gitleaks.toml` |

## Arquivos que fixam versões

| O quê | Arquivo | Como atualizar |
|---|---|---|
| Dependências .NET (diretas e transitivas) | `**/packages.lock.json` | `dotnet restore --force-evaluate` e commitar (idealmente gerado em Linux, para casar com o CI) |
| SDK do .NET | `global.json` | editar a versão |
| Actions | `uses: org/repo@<sha> # vX.Y.Z` | Dependabot propõe; revise o diff do SHA |
| Imagens (Dockerfile, workflows, Compose) | `@sha256:…` | Dependabot (Dockerfile) / edição manual com `docker pull` + `docker inspect` |

> Ao atualizar uma Action, **revise o conteúdo** da nova versão antes de aceitar o SHA: o digest garante que você roda o que
> revisou, não que o que foi revisado é seguro.

## SBOM

- Formato **CycloneDX** (JSON), gerado do **artefato final** (a imagem), não do código-fonte: reflete exatamente o que roda.
- Publicado como artifact do workflow, anexado ao GitHub Release (`sentinelforge-sbom.cdx.json`, com `SHA256SUMS`) e
  atestado no registro.
- Uso típico: alimentar um scanner de SCA ou um inventário; responder "estamos afetados pelo CVE-X?" sem reconstruir a imagem.
  Exemplo: `trivy sbom sentinelforge-sbom.cdx.json`.

## Assinatura e proveniência

- **Cosign keyless (Sigstore):** o workflow obtém um certificado de curta duração ligado à sua identidade OIDC do GitHub e
  assina o digest da imagem; a assinatura vai para o registro e para o log de transparência público (Rekor).
  Não existe chave privada para guardar ou vazar.
- **Atestado de proveniência:** registra repositório, commit, workflow e runner que construíram a imagem.
- **Como o consumidor verifica:** ver "Verificar uma imagem publicada" em [container-security.md](container-security.md).
- **Política recomendada ao consumir:** aceitar imagens somente por **digest** e somente se a assinatura/atestado verificarem
  com a identidade `…/SentinelForge/.github/workflows/…`.

## Limitações conhecidas (honestidade)

- **Não é SLSA nível 3.** O atestado de proveniência é gerado pelo workflow do próprio repositório (não por um builder
  reutilizável isolado). Dá rastreabilidade, não resistência a um repositório comprometido.
- **Build não reprodutível bit a bit.** Camadas e timestamps podem variar; a garantia é "mesma imagem escaneada = publicada",
  não "mesmo hash a cada build".
- **Pacotes do SO** da base vêm do repositório da Canonical no momento do build da imagem base; o digest fixa a base, mas
  novos CVEs surgem depois: por isso o scan roda a cada build **e** o Dependabot propõe novas bases.
- **Cache de dependências** (`setup-dotnet`) é restaurado por chave do lock file; caches de PRs não escrevem no escopo da
  `main`. Mesmo assim, o `--locked-mode` + NuGetAudit continuam validando o que foi restaurado.
- **Dependabot × lock files:** se uma PR do Dependabot alterar o `.csproj` e o lock não for atualizado, o CI reprova
  (`NU1004`). Regenere o lock (comando acima) e faça push na PR. Isso é intencional: nenhuma dependência muda sem passar
  pelo gate.

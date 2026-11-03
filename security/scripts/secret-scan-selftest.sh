#!/usr/bin/env bash
# Autoteste do gate de segredos: prova que o Gitleaks, COM a configuração deste repositório, detecta segredos
# e que não acusa placeholders. Os segredos fictícios são gerados em tempo de execução, dentro de um container
# descartável: nada fictício é versionado e nada é escrito no disco do host.
#
# Uso: security/scripts/secret-scan-selftest.sh
#      GITLEAKS_IMAGE=<imagem@digest> para sobrescrever a imagem (o padrão é a mesma dos workflows).
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash (Windows) não deve reescrever caminhos de volume do Docker

GITLEAKS_IMAGE="${GITLEAKS_IMAGE:-ghcr.io/gitleaks/gitleaks@sha256:c00b6bd0aeb3071cbcb79009cb16a60dd9e0a7c60e2be9ab65d25e6bc8abbb7f}"
CONFIG_PATH="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/.gitleaks.toml"

if [[ ! -f "${CONFIG_PATH}" ]]; then
  echo "Configuração não encontrada: ${CONFIG_PATH}" >&2
  exit 2
fi

# O script roda DENTRO do container (sh/busybox). Só os IDs das regras são impressos, nunca os valores.
INNER='
set -u
dir="$(mktemp -d)"
rand_hex()   { head -c 24 /dev/urandom | od -An -tx1 | tr -d " \n"; }
rand_b32()   { tr -dc "A-Z2-7" </dev/urandom | head -c "$1"; }
rand_b64()   { head -c 36 /dev/urandom | od -An -tx1 | tr -d " \n"; }
mkdir "$dir/conn" "$dir/jwt" "$dir/aws" "$dir/nvd" "$dir/clean"

printf "ConnectionStrings__DefaultConnection=Host=db;Port=5432;Database=app;Username=svc;Password=%s\n" "$(rand_hex)" > "$dir/conn/settings.env"
printf "Jwt__SigningKey=%s\n" "$(rand_b64)" > "$dir/jwt/settings.env"
printf "aws_access_key_id = AKIA%s\n" "$(rand_b32 16)" > "$dir/aws/credentials"
printf "Nvd__ApiKey=%s-%s-%s-%s-%s\n" "$(rand_hex | cut -c1-8)" "$(rand_hex | cut -c1-4)" "$(rand_hex | cut -c1-4)" "$(rand_hex | cut -c1-4)" "$(rand_hex | cut -c1-12)" > "$dir/nvd/settings.env"

# Conteúdo legítimo que NÃO pode ser acusado: placeholders e referências a variáveis.
cat > "$dir/clean/README.md" <<EOF
Host=localhost;Port=5432;Database=<db>;Username=<user>;Password=<senha>
Password=\${PGPASS}
Password=\$PGPASS
Password={0}
Jwt__SigningKey=<chave de 48 bytes em base64>
Nvd__ApiKey=<sua chave>
EOF

failed=0
expect_rule() { # pasta regra
  gitleaks dir "$dir/$1" --config /config/.gitleaks.toml --no-banner --redact --exit-code 0 \
    --report-format json --report-path "$dir/$1.json" --log-level error >/dev/null 2>&1
  # Sem relatório = o Gitleaks nem rodou (ex.: configuração não carregada). Isso é falha, nunca "sem achados".
  if [ ! -s "$dir/$1.json" ]; then
    echo "FAIL gitleaks não produziu relatório para $1 (configuração/execução inválida)"; failed=1; return
  fi
  found="$(grep -o "\"RuleID\": *\"[^\"]*\"" "$dir/$1.json" 2>/dev/null | sed "s/.*: *\"//; s/\"//" | sort -u | tr "\n" " ")"
  if echo " $found" | grep -q " $2 "; then
    echo "OK   detectou $2"
  else
    echo "FAIL esperado $2; regras acionadas: [${found}]"; failed=1
  fi
}
expect_rule conn sentinelforge-connection-string-password
expect_rule jwt  sentinelforge-jwt-signing-key
expect_rule aws  aws-access-token
expect_rule nvd  sentinelforge-nvd-api-key

# O gate de verdade (exit-code 1) precisa falhar quando há segredo...
if gitleaks dir "$dir/conn" --config /config/.gitleaks.toml --no-banner --redact --exit-code 1 --log-level error >/dev/null 2>&1; then
  echo "FAIL o gate deveria falhar com segredo presente"; failed=1
else
  echo "OK   gate falha (exit != 0) quando há segredo"
fi

# ...e passar quando o conteúdo é só placeholder.
if gitleaks dir "$dir/clean" --config /config/.gitleaks.toml --no-banner --redact --exit-code 1 --log-level error >/dev/null 2>&1; then
  echo "OK   gate passa com placeholders"
else
  echo "FAIL placeholders foram acusados como segredo"; failed=1
fi
rm -rf "$dir"
exit "$failed"
'

docker run --rm \
  --entrypoint sh \
  -v "${CONFIG_PATH}:/config/.gitleaks.toml:ro" \
  "${GITLEAKS_IMAGE}" -c "${INNER}"

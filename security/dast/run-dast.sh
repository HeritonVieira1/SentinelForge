#!/usr/bin/env bash
# DAST com OWASP ZAP contra a API do SentinelForge em ambiente ISOLADO e descartável.
#
#   MODE=baseline  (padrão)  análise passiva autenticada, a partir do OpenAPI (zap-api-scan.py -S). Segura e rápida.
#   MODE=active              acrescenta a varredura ATIVA (ataques) — somente contra este ambiente isolado.
#
# Variáveis: API_IMAGE (padrão sentinelforge:scan), REPORT_DIR (padrão ./dast-reports).
# Requisitos: docker, dotnet SDK (para gerar o script SQL das migrações) e bash.
#
# SEGURANÇA: o alvo é fixo (http://api:8080, dentro da rede interna do Compose). Este script não aceita URL externa
# e jamais deve ser alterado para varrer produção ou sistemas de terceiros sem autorização explícita.
set -euo pipefail
export MSYS_NO_PATHCONV=1 # Git Bash (Windows): não reescrever caminhos de volume do Docker

MODE="${MODE:-baseline}"
API_IMAGE="${API_IMAGE:-sentinelforge:scan}"
ZAP_IMAGE="${ZAP_IMAGE:-ghcr.io/zaproxy/zaproxy@sha256:030d3df57735dacbb83464854758e674dd9ad01d79d12a129a8e58b1fd384238}" # 2.17.0
PYTHON_IMAGE="${PYTHON_IMAGE:-python@sha256:ae14d4ce8771606477a81446e7ef429edd6762305fc50c84507c1041fa8285d1}"
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
REPORT_DIR="${REPORT_DIR:-${REPO_ROOT}/dast-reports}"
PROJECT="sf-dast"
NETWORK="${PROJECT}_internal"
TARGET="http://api:8080" # fixo e interno

case "${MODE}" in baseline | active) ;; *) echo "MODE deve ser 'baseline' ou 'active'" >&2; exit 2 ;; esac

host_path() { if command -v cygpath >/dev/null 2>&1; then cygpath -m "$1"; else printf '%s' "$1"; fi; }
rand_hex() { head -c "${1:-24}" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
mask() { if [ "${GITHUB_ACTIONS:-}" = "true" ]; then echo "::add-mask::$1"; fi; }
log() { printf '\n==> %s\n' "$*"; }

mkdir -p "${REPORT_DIR}"
chmod 777 "${REPORT_DIR}" # o usuário "zap" do container precisa gravar os relatórios
rm -f "${REPORT_DIR}"/zap-report.* "${REPORT_DIR}"/gate-*.* "${REPORT_DIR}"/openapi.json

# Credenciais efêmeras (mascaradas em logs do GitHub Actions; nada é gravado em disco).
export DAST_DB_USER="sf_dast"
DAST_DB_PASSWORD="$(rand_hex 24)"; export DAST_DB_PASSWORD
DAST_JWT_KEY="$(rand_hex 32)"; export DAST_JWT_KEY
ADMIN_EMAIL="admin@dast.invalid"
ADMIN_PASSWORD="Aa1!$(rand_hex 16)"
export API_IMAGE
mask "${DAST_DB_PASSWORD}"; mask "${DAST_JWT_KEY}"; mask "${ADMIN_PASSWORD}"

COMPOSE_FILE="${REPO_ROOT}/security/dast/docker-compose.yml"
compose() { docker compose -p "${PROJECT}" -f "$(host_path "${COMPOSE_FILE}")" "$@"; }
# Executa comandos curl/sh DENTRO da rede interna, usando a imagem do ZAP (que já traz curl). Script via stdin.
in_network() { docker run --rm -i --network "${NETWORK}" --entrypoint sh "${ZAP_IMAGE}" -s; }

cleanup() {
  log "Destruindo o ambiente isolado"
  if [ "${KEEP_LOGS:-}" = "true" ] || [ "${exit_code:-0}" -ne 0 ]; then
    compose logs --no-color api 2>/dev/null | tail -n 60 >"${REPORT_DIR}/api-tail.log" || true
  fi
  compose down -v --remove-orphans >/dev/null 2>&1 || true
  docker rm -f "${PROJECT}-docs" >/dev/null 2>&1 || true
}
trap 'exit_code=$?; cleanup; exit ${exit_code}' EXIT

wait_http() { # url tentativas
  local url="$1" tries="${2:-60}"
  for _ in $(seq 1 "${tries}"); do
    if echo "curl -fsS -o /dev/null '${url}'" | in_network >/dev/null 2>&1; then return 0; fi
    sleep 2
  done
  echo "Timeout aguardando ${url}" >&2
  return 1
}

log "Subindo PostgreSQL (rede interna, sem portas publicadas)"
compose up -d --wait postgres

log "Aplicando migrações (script SQL idempotente gerado pelo EF Core)"
( cd "${REPO_ROOT}" && dotnet tool restore >/dev/null && \
  dotnet ef migrations script --idempotent \
    --project src/SentinelForge.Infrastructure --startup-project src/SentinelForge.Api \
    --output "$(host_path "${REPORT_DIR}")/.migrate.sql" >/dev/null )
compose exec -T postgres psql -v ON_ERROR_STOP=1 -q -U "${DAST_DB_USER}" -d sentinelforge_dast <"${REPORT_DIR}/.migrate.sql" >/dev/null
rm -f "${REPORT_DIR}/.migrate.sql"

log "Provisionando o administrador de teste (comando oficial; senha só por variável de ambiente)"
docker run --rm --network "${NETWORK}" \
  -e "Jwt__SigningKey=${DAST_JWT_KEY}" \
  -e "ConnectionStrings__DefaultConnection=Host=postgres;Port=5432;Database=sentinelforge_dast;Username=${DAST_DB_USER};Password=${DAST_DB_PASSWORD}" \
  -e "SENTINELFORGE_ADMIN_PASSWORD=${ADMIN_PASSWORD}" \
  "${API_IMAGE}" provision-admin --email "${ADMIN_EMAIL}" --name "DAST Admin"

log "Subindo a API (modo Production)"
compose up -d api
wait_http "${TARGET}/health" 60

log "Obtendo o contrato OpenAPI (instância descartável em modo Development, apenas para publicar o documento)"
docker run -d --name "${PROJECT}-docs" --network "${NETWORK}" --network-alias docs \
  -e ASPNETCORE_ENVIRONMENT=Development -e "Jwt__SigningKey=${DAST_JWT_KEY}" \
  -e "ConnectionStrings__DefaultConnection=Host=postgres;Port=5432;Database=sentinelforge_dast;Username=${DAST_DB_USER};Password=${DAST_DB_PASSWORD}" \
  "${API_IMAGE}" >/dev/null
wait_http "http://docs:8080/health" 60
echo "curl -fsS http://docs:8080/openapi/v1.json" | in_network >"${REPORT_DIR}/openapi.json"
docker rm -f "${PROJECT}-docs" >/dev/null
test -s "${REPORT_DIR}/openapi.json"
echo "OpenAPI: $(grep -o '"/api/[^"]*"' "${REPORT_DIR}/openapi.json" | sort -u | wc -l | tr -d ' ') rotas /api/*"

log "Autenticando como o administrador de teste"
TOKEN="$(in_network <<EOF | sed -n 's/.*"accessToken":"\([^"]*\)".*/\1/p'
curl -fsS -X POST ${TARGET}/api/auth/login -H 'Content-Type: application/json' -d '{"email":"${ADMIN_EMAIL}","password":"${ADMIN_PASSWORD}"}'
EOF
)"
if [ -z "${TOKEN}" ]; then echo "Falha ao obter o token de acesso" >&2; exit 1; fi
mask "${TOKEN}"

# Pré-condição: o token precisa funcionar nos endpoints protegidos. Sem isso a varredura seria só "não autenticada"
# e daria uma falsa sensação de segurança.
probe() { # caminho -> código HTTP
  in_network <<EOF
curl -s -o /dev/null -w '%{http_code}' -H 'Authorization: Bearer ${TOKEN}' '${TARGET}$1'
EOF
}
for path in "/api/users" "/api/applications?page=1&pageSize=20" "/api/vulnerabilities/summary"; do
  code="$(probe "${path}")"
  echo "preflight GET ${path} -> ${code}"
  if [ "${code}" != "200" ]; then echo "Preflight autenticado falhou em ${path} (esperado 200)" >&2; exit 1; fi
done

log "Semeando dados no banco EFÊMERO para que o scanner alcance a lógica protegida (IDs reais no OpenAPI)"
psql_q() { compose exec -T postgres psql -At -U "${DAST_DB_USER}" -d sentinelforge_dast "$@" | tr -d '\r'; }
USER_ID="$(psql_q -c "select \"Id\" from users where \"Email\" = '${ADMIN_EMAIL}'")"
APP_ID="$(psql_q -c "insert into applications (\"Id\",\"Name\",\"Description\",\"IsActive\",\"CreatedAt\",\"UpdatedAt\",\"OwnerUserId\") values (gen_random_uuid(),'DAST target','Registro semeado apenas no ambiente de teste efêmero',true,now(),now(),'${USER_ID}') returning \"Id\"" | head -n 1)"
VULN_ID="$(in_network <<EOF | sed -n 's/.*"id":"\([0-9a-f-]\{36\}\)".*/\1/p' | head -n 1
curl -fsS -X POST ${TARGET}/api/vulnerabilities -H 'Authorization: Bearer ${TOKEN}' -H 'Content-Type: application/json' -d '{"applicationId":"${APP_ID}","title":"Alvo do DAST","category":"Teste","cvssScore":5.0,"cvssVersion":"4.0"}'
EOF
)"

# Usuário-VÍTIMA: alvo dos endpoints /api/users/{id}. O scanner ataca "revoke-sessions" e "role"; se o alvo fosse o próprio
# administrador de teste, o ZAP revogaria a sessão do seu token e todo o restante da varredura viraria 401 (já aconteceu).
VICTIM_PASSWORD="Bb2!$(rand_hex 16)"
mask "${VICTIM_PASSWORD}"
VICTIM_ID="$(in_network <<EOF | sed -n 's/.*"id":"\([0-9a-f-]\{36\}\)".*/\1/p' | head -n 1
curl -fsS -X POST ${TARGET}/api/auth/register -H 'Content-Type: application/json' -d '{"name":"DAST Victim","email":"victim@dast.invalid","password":"${VICTIM_PASSWORD}"}'
EOF
)"
if [ -z "${USER_ID}" ] || [ -z "${APP_ID}" ] || [ -z "${VULN_ID}" ] || [ -z "${VICTIM_ID}" ]; then echo "Falha ao semear dados do DAST" >&2; exit 1; fi
echo "semeado: admin=${USER_ID} vítima=${VICTIM_ID} aplicação=${APP_ID} vulnerabilidade=${VULN_ID}"
docker run --rm -v "$(host_path "${REPORT_DIR}"):/zap/wrk:rw" -v "$(host_path "${REPO_ROOT}/security/dast"):/zap/hooks:ro" \
  --entrypoint python3 "${ZAP_IMAGE}" /zap/hooks/prepare_openapi.py /zap/wrk/openapi.json "${APP_ID}" "${VULN_ID}" "${VICTIM_ID}"

log "Executando o OWASP ZAP (modo: ${MODE})"
# A autenticação é injetada por um hook (security/dast/zap_hooks.py), com o token em variável de ambiente do container.
# (A opção -z "-config replacer..." foi descartada: no ZAP 2.17.0 o cabeçalho não chegava à API, comprovado com eco.)
zap_args=(-t /zap/wrk/openapi.json -f openapi -O "${TARGET}"
          -r zap-report.html -w zap-report.md -J zap-report.json -I -T 20
          --hook=/zap/hooks/zap_hooks.py)
if [ "${MODE}" = "baseline" ]; then zap_args+=(-S); fi

zap_code=0
docker run --rm --network "${NETWORK}" -e ZAP_AUTH_TOKEN="${TOKEN}" \
  -v "$(host_path "${REPORT_DIR}"):/zap/wrk:rw" -v "$(host_path "${REPO_ROOT}/security/dast"):/zap/hooks:ro" \
  "${ZAP_IMAGE}" zap-api-scan.py "${zap_args[@]}" || zap_code=$?
echo "ZAP exit code: ${zap_code} (0 ok, 1 FAIL, 2 WARN, 3 erro de execução)"
if [ "${zap_code}" -ge 3 ] || [ ! -s "${REPORT_DIR}/zap-report.json" ]; then
  echo "O ZAP não concluiu a análise (código ${zap_code} / relatório ausente)." >&2
  exit 1
fi

log "Pós-condição: a sessão do scanner precisa ter sobrevivido à varredura"
post_code="$(probe "/api/users")"
echo "postflight GET /api/users -> ${post_code}"
if [ "${post_code}" != "200" ]; then
  echo "O token do scanner deixou de valer durante a varredura (HTTP ${post_code}): o restante dos ataques foi anônimo e a cobertura está comprometida." >&2
  exit 1
fi

log "Verificando se o ZAP realmente enviou o token (escritas autenticadas registradas na auditoria)"
authed="$(compose exec -T postgres psql -At -U "${DAST_DB_USER}" -d sentinelforge_dast \
  -c "select count(*) from audit_logs where \"UserId\" is not null and \"Action\" in ('Created','Updated') and \"EntityName\" <> 'User'" | tr -d '\r ')"
echo "Registros de auditoria gerados por requisições autenticadas do scanner: ${authed:-0}"
if [ "${MODE}" = "active" ] && [ "${authed:-0}" -eq 0 ]; then
  echo "AVISO: nenhuma escrita autenticada observada; a varredura ativa pode não ter exercitado os endpoints protegidos." >&2
fi

log "Security gate (alertas de risco alto bloqueiam; falso positivo só via exceção documentada)"
set +e
docker run --rm -v "$(host_path "${REPO_ROOT}"):/repo:ro" -v "$(host_path "${REPORT_DIR}"):/out" -w /repo "${PYTHON_IMAGE}" \
  python -I security/scripts/evaluate_gate.py --policy security/security-policy.json \
    --label "DAST (${MODE})" --zap /out/zap-report.json \
    --summary /out/gate-summary.md --result /out/gate-result.json
gate_code=$?
set -e
exit "${gate_code}"

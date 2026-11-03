# SentinelForge API
#
# Imagens base com versão explícita E digest (reprodutível e imune a troca silenciosa de tag).
# O Dependabot (ecossistema "docker") propõe as atualizações; o digest é revisado no PR.
ARG SDK_IMAGE=mcr.microsoft.com/dotnet/sdk:10.0@sha256:de4fe90a98845d75910b9769662465c84de1a934665c431279d1382b2bddc02b
# "chiseled": distroless da Canonical/Microsoft, sem shell, sem gerenciador de pacotes, usuário não-root embutido.
ARG RUNTIME_IMAGE=mcr.microsoft.com/dotnet/aspnet:10.0-noble-chiseled@sha256:c89a6a61f494f20a5ae302990e814627a8d91b332fd4a8e7c1707c2d4da9555d

# ---------- build ----------
FROM ${SDK_IMAGE} AS build
WORKDIR /src

ENV DOTNET_NOLOGO=true \
    DOTNET_CLI_TELEMETRY_OPTOUT=true

# Camada de restore: só manifestos e locks, para cachear dependências enquanto o código muda.
COPY global.json Directory.Build.props .editorconfig ./
COPY src/SentinelForge.Domain/SentinelForge.Domain.csproj src/SentinelForge.Domain/packages.lock.json src/SentinelForge.Domain/
COPY src/SentinelForge.Application/SentinelForge.Application.csproj src/SentinelForge.Application/packages.lock.json src/SentinelForge.Application/
COPY src/SentinelForge.Infrastructure/SentinelForge.Infrastructure.csproj src/SentinelForge.Infrastructure/packages.lock.json src/SentinelForge.Infrastructure/
COPY src/SentinelForge.Api/SentinelForge.Api.csproj src/SentinelForge.Api/packages.lock.json src/SentinelForge.Api/

# --locked-mode: falha se qualquer dependência (inclusive transitiva) divergir do packages.lock.json.
RUN dotnet restore src/SentinelForge.Api/SentinelForge.Api.csproj --locked-mode

COPY src/ src/
RUN dotnet publish src/SentinelForge.Api/SentinelForge.Api.csproj \
      --configuration Release --no-restore --output /app/publish \
      -p:UseAppHost=false -p:DebugType=none

# ---------- runtime ----------
FROM ${RUNTIME_IMAGE} AS final

ARG VERSION=0.0.0-local
ARG REVISION=unknown
LABEL org.opencontainers.image.title="SentinelForge API" \
      org.opencontainers.image.description="API REST para gerenciamento de vulnerabilidades de seguranca" \
      org.opencontainers.image.source="https://github.com/HeritonVieira1/SentinelForge" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

WORKDIR /app
COPY --from=build /app/publish .

# Porta não privilegiada (a imagem não roda como root). HTTPS/TLS é terminado na borda (proxy/ingress).
ENV ASPNETCORE_HTTP_PORTS=8080 \
    ASPNETCORE_ENVIRONMENT=Production \
    DOTNET_gcServer=0
EXPOSE 8080

# Usuário não-root (UID numérico, para que o orquestrador consiga validar runAsNonRoot).
USER 1654

# Segredos (Jwt__SigningKey, ConnectionStrings__DefaultConnection, Nvd__ApiKey) entram SOMENTE por variáveis de
# ambiente / secret store em tempo de execução. Nada sensível é gravado na imagem.
ENTRYPOINT ["dotnet", "SentinelForge.Api.dll"]

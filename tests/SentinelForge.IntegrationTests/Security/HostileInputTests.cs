using System.Net;
using System.Net.Http.Json;
using Microsoft.AspNetCore.Http;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging.Abstractions;
using Npgsql;
using SentinelForge.Api.Http;
using SentinelForge.Domain.Enums;
using SentinelForge.IntegrationTests.Persistence;

namespace SentinelForge.IntegrationTests.Security;

/// <summary>
/// Regressão de um defeito encontrado pelo DAST (OWASP ZAP): <c>entityName=%00</c> em /api/audit-logs chegava ao PostgreSQL,
/// que recusa NUL (0x00) em texto, e a API respondia 500. Entrada hostil deve gerar 400 (ou a resposta genérica do
/// endpoint), nunca 500.
/// </summary>
[Collection(PostgresTestGroup.Name)]
public sealed class HostileInputTests(PostgresFixture db) : IDisposable
{
    private readonly ApiContext _api = new(db);

    public void Dispose() => _api.Dispose();

    private static Uri Url(string path) => new(path, UriKind.Relative);

    [Theory]
    [InlineData("%00")]
    [InlineData("%01")]
    [InlineData("a%00b")]
    [InlineData("%1F")]
    public async Task AuditLogs_EntityNameWithControlCharacters_IsRejected_NotA500(string value)
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);

        using var response = await admin.Client.GetAsync(Url($"/api/audit-logs?entityName={value}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task AuditLogs_OverlongEntityName_IsRejected()
    {
        var admin = await _api.NewSessionAsync(UserRole.Administrator);

        using var response = await admin.Client.GetAsync(Url($"/api/audit-logs?entityName={new string('x', 101)}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("%00")]
    [InlineData("abc%00")]
    [InlineData("%07")]
    public async Task VulnerabilityList_SearchWithControlCharacters_IsRejected_NotA500(string value)
    {
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Url($"/api/vulnerabilities?search={value}"));

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Theory]
    [InlineData("title")]
    [InlineData("description")]
    [InlineData("category")]
    [InlineData("remediation")]
    [InlineData("cveId")]
    public async Task CreateVulnerability_TextFieldWithNul_IsRejected_NotA500(string field)
    {
        var owner = await _api.NewSessionAsync();
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);
        var appId = await _api.SeedApplicationAsync(owner.Id);
        var body = new Dictionary<string, object?>
        {
            ["applicationId"] = appId,
            ["title"] = "Título válido",
            ["description"] = "descrição",
            ["category"] = "Injection",
            ["remediation"] = "correção",
            ["cveId"] = "CVE-2024-12345",
        };
        body[field] = "valor\u0000hostil";

        using var response = await analyst.Client.PostAsJsonAsync("/api/vulnerabilities", body);

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task StatusJustificationWithNul_IsRejected_NotA500()
    {
        var owner = await _api.NewSessionAsync();
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);
        var vulnId = await _api.SeedVulnerabilityAsync(await _api.SeedApplicationAsync(owner.Id), analyst.Id);

        using var response = await analyst.Client.PatchAsJsonAsync(
            $"/api/vulnerabilities/{vulnId}/status", new { status = "AcceptedRisk", justification = "motivo\u0000hostil" });

        Assert.Equal(HttpStatusCode.BadRequest, response.StatusCode);
    }

    [Fact]
    public async Task Register_NameOrEmailWithNul_IsRejected_AndLoginStaysGeneric()
    {
        using var badName = await _api.Client.PostAsJsonAsync("/api/auth/register",
            new { name = "Ana\u0000", email = ApiContext.NewEmail(), password = ApiContext.StrongPassword });
        using var badEmail = await _api.Client.PostAsJsonAsync("/api/auth/register",
            new { name = "Ana", email = "ana\u0000@example.com", password = ApiContext.StrongPassword });
        using var login = await _api.LoginRawAsync("ana\u0000@example.com", ApiContext.StrongPassword);

        Assert.Equal(HttpStatusCode.BadRequest, badName.StatusCode);
        Assert.Equal(HttpStatusCode.BadRequest, badEmail.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, login.StatusCode);
    }

    [Fact]
    public async Task LegitimateMultilineText_IsStillAccepted()
    {
        var owner = await _api.NewSessionAsync();
        var analyst = await _api.NewSessionAsync(UserRole.SecurityAnalyst);
        var appId = await _api.SeedApplicationAsync(owner.Id);

        using var response = await analyst.Client.PostAsJsonAsync("/api/vulnerabilities", new
        {
            applicationId = appId,
            title = "Falha de validação",
            category = "Injection",
            description = "Linha 1\nLinha 2\r\n\tIndentada",
        });

        Assert.Equal(HttpStatusCode.Created, response.StatusCode);
    }

    // ---------- Rede de segurança do tratador de exceções ----------

    private static async Task<int> HandleAsync(Exception exception)
    {
        var context = new DefaultHttpContext();
        var handler = new GlobalExceptionHandler(NullLogger<GlobalExceptionHandler>.Instance, new NoOpProblemDetails());
        await handler.TryHandleAsync(context, exception, CancellationToken.None);
        return context.Response.StatusCode;
    }

    [Fact]
    public async Task ExceptionHandler_MapsPostgresDataExceptions_To400()
    {
        var dataError = new PostgresException("invalid byte sequence", "ERROR", "ERROR", "22021");
        var wrapped = new DbUpdateException("save failed", dataError);

        Assert.Equal(StatusCodes.Status400BadRequest, await HandleAsync(dataError));
        Assert.Equal(StatusCodes.Status400BadRequest, await HandleAsync(wrapped));
    }

    [Fact]
    public async Task ExceptionHandler_KeepsOtherDatabaseErrorsAs500_WithoutLeakingDetails()
    {
        var other = new PostgresException("relation \"secret_table\" does not exist", "ERROR", "ERROR", "42P01");

        Assert.Equal(StatusCodes.Status500InternalServerError, await HandleAsync(other));
        Assert.Equal(StatusCodes.Status500InternalServerError, await HandleAsync(new InvalidOperationException("boom")));
    }

    private sealed class NoOpProblemDetails : IProblemDetailsService
    {
        public ValueTask WriteAsync(ProblemDetailsContext context) => ValueTask.CompletedTask;

        public ValueTask<bool> TryWriteAsync(ProblemDetailsContext context) => ValueTask.FromResult(true);
    }
}

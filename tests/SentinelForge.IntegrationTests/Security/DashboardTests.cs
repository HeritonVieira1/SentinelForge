using System.Net;
using SentinelForge.Domain.Enums;
using SentinelForge.IntegrationTests.Persistence;

namespace SentinelForge.IntegrationTests.Security;

/// <summary>
/// Usa um banco vazio próprio: os totais do dashboard são globais e precisam ser verificáveis à mão,
/// sem interferência dos dados criados por outros testes.
/// </summary>
[Collection(PostgresTestGroup.Name)]
public sealed class DashboardTests(PostgresFixture db)
{
    private static Uri Summary => new("/api/vulnerabilities/summary", UriKind.Relative);

    private sealed record Scenario(
        ApiContext Api,
        Session Admin,
        Session Analyst,
        Session DevA,
        Session DevB,
        Guid App1,
        Guid App2);

    private async Task<Scenario> BuildAsync()
    {
        var api = new ApiContext(db, connectionString: await db.CreateExtraDatabaseAsync());
        var admin = await api.NewSessionAsync(UserRole.Administrator);
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);
        var devA = await api.NewSessionAsync();
        var devB = await api.NewSessionAsync();

        var app1 = await api.SeedApplicationAsync(devA.Id, "App1");
        var app2 = await api.SeedApplicationAsync(devB.Id, "App2");
        var t0 = DateTime.UtcNow.AddDays(-10);

        // 1) App1 Critical 9.8 New, atribuída a devA
        await api.SeedVulnerabilityAsync(app1, analyst.Id, devA.Id, "v1", 9.8m, discoveredAt: t0);

        // 2) App1 Critical 9.0 Resolved 24 h após a descoberta, atribuída ao analista
        var v2 = await api.SeedVulnerabilityAsync(app1, analyst.Id, analyst.Id, "v2", 9.0m, discoveredAt: t0);
        await api.AdvanceAtAsync(v2, analyst.Id, t0.AddHours(24), VulnerabilityStatus.Triaged, VulnerabilityStatus.InProgress, VulnerabilityStatus.Resolved);

        // 3) App2 Critical 9.5 Verified (resolvida 72 h após a descoberta), sem responsável
        var v3 = await api.SeedVulnerabilityAsync(app2, analyst.Id, null, "v3", 9.5m, discoveredAt: t0);
        await api.AdvanceAtAsync(v3, analyst.Id, t0.AddHours(72), VulnerabilityStatus.Triaged, VulnerabilityStatus.InProgress, VulnerabilityStatus.Resolved);
        await api.AdvanceAtAsync(v3, admin.Id, t0.AddHours(80), VulnerabilityStatus.Verified);

        // 4) App2 High 7.5 InProgress, atribuída a devB
        var v4 = await api.SeedVulnerabilityAsync(app2, analyst.Id, devB.Id, "v4", 7.5m, discoveredAt: t0);
        await api.AdvanceAtAsync(v4, analyst.Id, t0.AddHours(1), VulnerabilityStatus.Triaged, VulnerabilityStatus.InProgress);

        // 5) App2 sem avaliação CVSS (Unrated), New, sem responsável
        await api.SeedVulnerabilityAsync(app2, analyst.Id, null, "v5", null, discoveredAt: t0);

        // 6) App1 Low 2.0 AcceptedRisk, atribuída a devA
        var v6 = await api.SeedVulnerabilityAsync(app1, analyst.Id, devA.Id, "v6", 2.0m, discoveredAt: t0);
        await api.AdvanceAtAsync(v6, analyst.Id, t0.AddHours(1), VulnerabilityStatus.AcceptedRisk);

        return new Scenario(api, admin, analyst, devA, devB, app1, app2);
    }

    [Fact]
    public async Task Summary_ForAnalyst_AggregatesEverything_InTheDatabase()
    {
        var s = await BuildAsync();
        using var _ = s.Api;

        using var response = await s.Analyst.Client.GetAsync(Summary);
        var summary = await response.ReadAsync<SummaryView>();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal(6, summary.Total);

        Assert.Equal(3, summary.BySeverity["Critical"]);
        Assert.Equal(1, summary.BySeverity["High"]);
        Assert.Equal(0, summary.BySeverity["Medium"]);
        Assert.Equal(1, summary.BySeverity["Low"]);
        Assert.Equal(0, summary.BySeverity["None"]);
        Assert.Equal(1, summary.BySeverity["Unrated"]);
        Assert.Equal(summary.Total, summary.BySeverity.Values.Sum());

        Assert.Equal(2, summary.ByStatus["New"]);
        Assert.Equal(0, summary.ByStatus["Triaged"]);
        Assert.Equal(1, summary.ByStatus["InProgress"]);
        Assert.Equal(1, summary.ByStatus["Resolved"]);
        Assert.Equal(1, summary.ByStatus["Verified"]);
        Assert.Equal(0, summary.ByStatus["Reopened"]);
        Assert.Equal(1, summary.ByStatus["AcceptedRisk"]);
        Assert.Equal(summary.Total, summary.ByStatus.Values.Sum());

        // Críticas abertas = críticas que não estão Verified nem AcceptedRisk: v1 (New) e v2 (Resolved, ainda sem validação).
        Assert.Equal(2, summary.OpenCritical);

        Assert.Equal(["App1", "App2"], summary.ByApplication.Select(a => a.Name));
        Assert.All(summary.ByApplication, a => Assert.Equal(3, a.Count));

        Assert.Equal(2, summary.ByAssignee.Single(a => a.UserId == s.DevA.Id).Count);
        Assert.Equal(1, summary.ByAssignee.Single(a => a.UserId == s.Analyst.Id).Count);
        Assert.Equal(1, summary.ByAssignee.Single(a => a.UserId == s.DevB.Id).Count);
        Assert.Equal(2, summary.ByAssignee.Single(a => a.UserId is null).Count);

        // v2 resolvida em 24 h e v3 em 72 h: média de 48 h sobre 2 amostras.
        Assert.Equal(2, summary.ResolvedSampleSize);
        Assert.Equal(48.0, summary.AverageResolutionHours!.Value, 1);
    }

    [Fact]
    public async Task Summary_ForDeveloper_IsScopedToAuthorizedApplications()
    {
        var s = await BuildAsync();
        using var _ = s.Api;

        using var asA = await s.DevA.Client.GetAsync(Summary);
        using var asB = await s.DevB.Client.GetAsync(Summary);
        var a = await asA.ReadAsync<SummaryView>();
        var b = await asB.ReadAsync<SummaryView>();

        Assert.Equal(3, a.Total);
        Assert.Equal(["App1"], a.ByApplication.Select(x => x.Name));
        Assert.Equal(2, a.OpenCritical);
        Assert.Equal(1, a.ResolvedSampleSize);
        Assert.Equal(24.0, a.AverageResolutionHours!.Value, 1);

        Assert.Equal(3, b.Total);
        Assert.Equal(["App2"], b.ByApplication.Select(x => x.Name));
        Assert.Equal(0, b.OpenCritical); // a crítica de App2 já foi verificada
        Assert.Equal(72.0, b.AverageResolutionHours!.Value, 1);
    }

    [Fact]
    public async Task Summary_WithoutData_ReturnsZeros_AndNoAverageInsteadOfInventingOne()
    {
        using var api = new ApiContext(db, connectionString: await db.CreateExtraDatabaseAsync());
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Summary);
        var summary = await response.ReadAsync<SummaryView>();

        Assert.Equal(0, summary.Total);
        Assert.Equal(0, summary.OpenCritical);
        Assert.Empty(summary.ByApplication);
        Assert.Null(summary.AverageResolutionHours);
        Assert.Equal(0, summary.ResolvedSampleSize);
        Assert.All(summary.BySeverity.Values, v => Assert.Equal(0, v));
    }

    [Fact]
    public async Task Summary_RequiresAuthentication()
    {
        using var api = new ApiContext(db);

        using var response = await api.Client.GetAsync(Summary);

        Assert.Equal(HttpStatusCode.Unauthorized, response.StatusCode);
    }
}

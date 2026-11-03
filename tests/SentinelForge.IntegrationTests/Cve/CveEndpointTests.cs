using System.Net;
using System.Net.Http.Headers;
using System.Text.Json;
using Microsoft.Extensions.DependencyInjection;
using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Enums;
using SentinelForge.Infrastructure.Cve;
using SentinelForge.IntegrationTests.Persistence;
using SentinelForge.IntegrationTests.Security;

namespace SentinelForge.IntegrationTests.Cve;

[Collection(PostgresTestGroup.Name)]
public sealed class CveEndpointTests(PostgresFixture db) : IDisposable
{
    private readonly List<IDisposable> _disposables = [];

    public void Dispose()
    {
        foreach (var d in _disposables)
        {
            d.Dispose();
        }
    }

    private static Uri Url(string path) => new(path, UriKind.Relative);

    private ApiContext Api(StubNvdHandler handler, Dictionary<string, string?>? overrides = null)
    {
        // A API real, com o transporte HTTP do cliente do NVD substituído pelo stub (nenhum acesso à rede).
        var api = new ApiContext(
            db,
            overrides,
            services => services.AddHttpClient<ICveLookup, NvdClient>().ConfigurePrimaryHttpMessageHandler(() => handler));
        _disposables.Add(api);
        return api;
    }

    [Fact]
    public async Task Lookup_ByAnalyst_ReturnsRealNvdData_WithSourceAndMetrics()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var api = Api(handler);
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-53677"));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());
        var root = json.RootElement;

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("CVE-2024-53677", root.GetProperty("cveId").GetString());
        Assert.Equal("NVD", root.GetProperty("source").GetString());
        Assert.Equal("https://nvd.nist.gov/vuln/detail/CVE-2024-53677", root.GetProperty("sourceUrl").GetString());
        Assert.False(string.IsNullOrWhiteSpace(root.GetProperty("description").GetString()));
        Assert.Equal("4.0", root.GetProperty("preferredMetric").GetProperty("version").GetString());
        Assert.True(root.GetProperty("metrics").GetArrayLength() >= 2);
        Assert.True(root.GetProperty("references").GetArrayLength() > 0);
        Assert.True(root.GetProperty("retrievedAt").GetDateTime() > DateTime.UtcNow.AddMinutes(-5));
    }

    [Fact]
    public async Task Lookup_NormalizesTheIdentifier_AndAdministratorsMayUseIt()
    {
        var api = Api(StubNvdHandler.ServingFixtures());
        var admin = await api.NewSessionAsync(UserRole.Administrator);

        using var response = await admin.Client.GetAsync(Url("/api/cve/cve-2024-3094"));
        using var json = JsonDocument.Parse(await response.Content.ReadAsStringAsync());

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("CVE-2024-3094", json.RootElement.GetProperty("cveId").GetString());
    }

    [Fact]
    public async Task Lookup_IsDenied_ToDevelopers_AndAnonymous_WithoutReachingTheNvd()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var api = Api(handler);
        var developer = await api.NewSessionAsync();

        using var asDeveloper = await developer.Client.GetAsync(Url("/api/cve/CVE-2024-3094"));
        using var anonymous = await api.Client.GetAsync(Url("/api/cve/CVE-2024-3094"));

        Assert.Equal(HttpStatusCode.Forbidden, asDeveloper.StatusCode);
        Assert.Equal(HttpStatusCode.Unauthorized, anonymous.StatusCode);
        Assert.Equal(0, handler.Calls); // a cota da API externa não é consumida por quem não tem permissão
    }

    [Theory]
    [InlineData("abc")]
    [InlineData("CVE-2024-12")]
    [InlineData("CVE-24-12345")]
    [InlineData("CVE-2024-53677%3FapiKey%3Dx")]
    [InlineData("CVE-2024-53677%26cveId%3DCVE-2000-0001")]
    [InlineData("%2e%2e%2fadmin")]
    public async Task Lookup_InvalidIdentifier_IsRejectedBeforeAnyExternalCall(string id)
    {
        var handler = StubNvdHandler.ServingFixtures();
        var api = Api(handler);
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Url("/api/cve/" + id));

        Assert.Contains(response.StatusCode, new[] { HttpStatusCode.BadRequest, HttpStatusCode.NotFound });
        Assert.Equal(0, handler.Calls); // nada controlado pelo usuário chega à URL do NVD
    }

    [Fact]
    public async Task Lookup_UnknownCve_ReturnsNotFound()
    {
        var api = Api(StubNvdHandler.ServingFixtures());
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Url("/api/cve/CVE-2099-99999"));

        Assert.Equal(HttpStatusCode.NotFound, response.StatusCode);
    }

    [Fact]
    public async Task NvdOutage_Returns503WithRetryAfter_AndTheRestOfThePlatformKeepsWorking()
    {
        var handler = StubNvdHandler.Returning(() => new HttpResponseMessage(HttpStatusCode.InternalServerError));
        var api = Api(handler);
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var first = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-53677"));
        using var second = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-3094"));
        var body = await first.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.ServiceUnavailable, first.StatusCode);
        Assert.True(first.Headers.Contains("Retry-After"));
        Assert.Equal(HttpStatusCode.ServiceUnavailable, second.StatusCode);
        Assert.Equal(1, handler.Calls);                                 // disjuntor: sem martelar o serviço indisponível
        Assert.DoesNotContain("nist.gov", body, StringComparison.OrdinalIgnoreCase); // sem detalhes internos/externos
        Assert.DoesNotContain("500", body, StringComparison.Ordinal);

        // Funcionalidade principal intacta.
        using var health = await api.Client.GetAsync(Url("/health"));
        using var list = await analyst.Client.GetAsync(Url("/api/vulnerabilities"));
        using var summary = await analyst.Client.GetAsync(Url("/api/vulnerabilities/summary"));
        Assert.Equal(HttpStatusCode.OK, health.StatusCode);
        Assert.Equal(HttpStatusCode.OK, list.StatusCode);
        Assert.Equal(HttpStatusCode.OK, summary.StatusCode);
    }

    [Fact]
    public async Task NvdTimeout_Returns503_WithinTheConfiguredTimeout()
    {
        var api = Api(StubNvdHandler.NeverAnswering(), new Dictionary<string, string?> { ["Nvd:TimeoutSeconds"] = "1" });
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        var started = DateTime.UtcNow;
        using var response = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-53677"));
        var elapsed = DateTime.UtcNow - started;

        Assert.Equal(HttpStatusCode.ServiceUnavailable, response.StatusCode);
        Assert.True(elapsed < TimeSpan.FromSeconds(8), $"respondeu em {elapsed}");
    }

    [Fact]
    public async Task NvdRateLimiting_IsSurfacedAs429_WithRetryAfter()
    {
        var handler = StubNvdHandler.Returning(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return response;
        });
        var api = Api(handler);
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        using var response = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-53677"));

        Assert.Equal(HttpStatusCode.TooManyRequests, response.StatusCode);
        Assert.Equal("7", response.Headers.GetValues("Retry-After").Single());
    }

    [Fact]
    public async Task LookupEndpoint_HasItsOwnRateLimit_ProtectingTheExternalQuota()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var api = Api(handler, new Dictionary<string, string?> { ["RateLimiting:CvePermitLimit"] = "2" });
        var analyst = await api.NewSessionAsync(UserRole.SecurityAnalyst);

        var statuses = new List<HttpStatusCode>();
        for (var i = 0; i < 3; i++)
        {
            using var response = await analyst.Client.GetAsync(Url("/api/cve/CVE-2024-3094"));
            statuses.Add(response.StatusCode);
        }

        Assert.Equal([HttpStatusCode.OK, HttpStatusCode.OK, HttpStatusCode.TooManyRequests], statuses);
        Assert.Equal(1, handler.Calls); // a segunda consulta veio do cache
    }
}

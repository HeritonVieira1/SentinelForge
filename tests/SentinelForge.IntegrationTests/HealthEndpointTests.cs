using System.Net;
using SentinelForge.IntegrationTests.Persistence;
using SentinelForge.IntegrationTests.Security;

namespace SentinelForge.IntegrationTests;

[Collection(PostgresTestGroup.Name)]
public sealed class HealthEndpointTests(PostgresFixture db) : IDisposable
{
    private readonly ApiContext _api = new(db);

    [Fact]
    public async Task GetHealth_ReturnsOkAndHealthy_WithoutAuthentication()
    {
        using var response = await _api.Client.GetAsync(new Uri("/health", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", body);
    }

    [Fact]
    public async Task PostHealth_IsNotAllowedToChangeState()
    {
        using var response = await _api.Client.PostAsync(new Uri("/health", UriKind.Relative), content: null);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }

    public void Dispose() => _api.Dispose();
}

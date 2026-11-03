using System.Net;
using Microsoft.AspNetCore.Mvc.Testing;

namespace SentinelForge.IntegrationTests;

public sealed class HealthEndpointTests(WebApplicationFactory<Program> factory)
    : IClassFixture<WebApplicationFactory<Program>>
{
    [Fact]
    public async Task GetHealth_ReturnsOkAndHealthy()
    {
        using var client = factory.CreateClient();

        using var response = await client.GetAsync(new Uri("/health", UriKind.Relative));
        var body = await response.Content.ReadAsStringAsync();

        Assert.Equal(HttpStatusCode.OK, response.StatusCode);
        Assert.Equal("Healthy", body);
    }

    [Fact]
    public async Task PostHealth_IsNotAllowedToChangeState()
    {
        using var client = factory.CreateClient();

        using var response = await client.PostAsync(new Uri("/health", UriKind.Relative), content: null);

        Assert.NotEqual(HttpStatusCode.OK, response.StatusCode);
    }
}


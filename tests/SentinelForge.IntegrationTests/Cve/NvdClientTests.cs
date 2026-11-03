using System.Net;
using System.Net.Http.Headers;
using SentinelForge.Application.Abstractions;

namespace SentinelForge.IntegrationTests.Cve;

public sealed class NvdClientTests
{
    private const string Cve = "CVE-2024-53677";

    [Fact]
    public async Task Lookup_SendsTheDocumentedRequest_AndReturnsTheRealData()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler);

        var result = await client.LookupAsync(Cve);

        Assert.Equal(CveLookupStatus.Found, result.Status);
        var request = Assert.Single(handler.Requests);
        Assert.Equal(HttpMethod.Get, request.Method);
        Assert.Equal($"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={Cve}", request.Uri.ToString());
        Assert.False(request.Headers.ContainsKey("apiKey"));
        Assert.Equal("4.0", result.Info!.PreferredMetric!.Version);
    }

    [Fact]
    public async Task Lookup_SendsTheApiKeyInAHeader_NeverInTheUrl()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler, o => o.ApiKey = "chave-secreta-de-teste");

        await client.LookupAsync(Cve);

        var request = Assert.Single(handler.Requests);
        Assert.Equal("chave-secreta-de-teste", request.Headers["apiKey"]);
        Assert.DoesNotContain("chave-secreta", request.Uri.ToString(), StringComparison.Ordinal);
    }

    [Fact]
    public async Task Lookup_CachesResults_SoRepeatedQueriesDoNotHitTheNvd()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler);

        var first = await client.LookupAsync(Cve);
        var second = await client.LookupAsync(Cve);
        var missingFirst = await client.LookupAsync("CVE-2099-99999");
        var missingSecond = await client.LookupAsync("CVE-2099-99999");

        Assert.Equal(CveLookupStatus.Found, second.Status);
        Assert.Same(first.Info, second.Info);
        Assert.Equal(CveLookupStatus.NotFound, missingFirst.Status);
        Assert.Equal(CveLookupStatus.NotFound, missingSecond.Status);
        Assert.Equal(2, handler.Calls);
    }

    [Fact]
    public async Task Lookup_Timeout_ReturnsUnavailable_AndTheCircuitOpensWithoutNewRequests()
    {
        var handler = StubNvdHandler.NeverAnswering();
        var (client, _, _) = NvdClients.Build(handler);

        var started = DateTime.UtcNow;
        var first = await client.LookupAsync(Cve);
        var elapsed = DateTime.UtcNow - started;
        var second = await client.LookupAsync("CVE-2024-3094");

        Assert.Equal(CveLookupStatus.Unavailable, first.Status);
        Assert.True(elapsed < TimeSpan.FromSeconds(5), $"timeout took {elapsed}");
        Assert.Equal(CveLookupStatus.Unavailable, second.Status);
        Assert.Equal(1, handler.Calls);                              // disjuntor aberto: nenhuma chamada nova
        Assert.NotNull(second.RetryAfter);

    }

    [Fact]
    public async Task Lookup_AfterCooldown_TriesTheUpstreamAgain()
    {
        var fail = true;
        var handler = new StubNvdHandler((request, _) => Task.FromResult(fail
            ? new HttpResponseMessage(HttpStatusCode.InternalServerError)
            : StubNvdHandler.Json(Fixtures.Read("nvd-CVE-2024-3094.json"))));
        var (client, time, _) = NvdClients.Build(handler);

        Assert.Equal(CveLookupStatus.Unavailable, (await client.LookupAsync("CVE-2024-3094")).Status);
        Assert.Equal(CveLookupStatus.Unavailable, (await client.LookupAsync("CVE-2024-3094")).Status);
        Assert.Equal(1, handler.Calls);

        fail = false;
        time.Advance(TimeSpan.FromSeconds(31));

        Assert.Equal(CveLookupStatus.Found, (await client.LookupAsync("CVE-2024-3094")).Status);
        Assert.Equal(2, handler.Calls);
    }

    [Theory]
    [InlineData(HttpStatusCode.InternalServerError)]
    [InlineData(HttpStatusCode.BadGateway)]
    [InlineData(HttpStatusCode.ServiceUnavailable)]
    [InlineData(HttpStatusCode.BadRequest)]
    public async Task Lookup_UpstreamErrors_BecomeUnavailable_NotExceptions(HttpStatusCode status)
    {
        var (client, _, _) = NvdClients.Build(StubNvdHandler.Returning(() => new HttpResponseMessage(status)));

        var result = await client.LookupAsync(Cve);

        Assert.Equal(CveLookupStatus.Unavailable, result.Status);
        Assert.Null(result.Info);
    }

    [Fact]
    public async Task Lookup_TooManyRequests_HonorsRetryAfter_AndStopsCallingUpstream()
    {
        var handler = StubNvdHandler.Returning(() =>
        {
            var response = new HttpResponseMessage(HttpStatusCode.TooManyRequests);
            response.Headers.RetryAfter = new RetryConditionHeaderValue(TimeSpan.FromSeconds(7));
            return response;
        });
        var (client, _, _) = NvdClients.Build(handler);

        var first = await client.LookupAsync(Cve);
        var second = await client.LookupAsync("CVE-2024-3094");

        Assert.Equal(CveLookupStatus.RateLimited, first.Status);
        Assert.Equal(TimeSpan.FromSeconds(7), first.RetryAfter);
        Assert.Equal(CveLookupStatus.Unavailable, second.Status); // bloqueado localmente até o Retry-After
        Assert.Equal(1, handler.Calls);
    }

    [Fact]
    public async Task Lookup_Forbidden_IsTreatedAsRateLimiting() =>
        Assert.Equal(
            CveLookupStatus.RateLimited,
            (await NvdClients.Build(StubNvdHandler.Returning(() => new HttpResponseMessage(HttpStatusCode.Forbidden))).Client.LookupAsync(Cve)).Status);

    [Fact]
    public async Task Lookup_NetworkFailure_BecomesUnavailable()
    {
        var handler = new StubNvdHandler((_, _) => throw new HttpRequestException("connection refused"));
        var (client, _, _) = NvdClients.Build(handler);

        Assert.Equal(CveLookupStatus.Unavailable, (await client.LookupAsync(Cve)).Status);
    }

    [Theory]
    [InlineData("<html>gateway error</html>")]
    [InlineData("{}")]
    [InlineData("""{"vulnerabilities":[{"cve":{"id":"CVE-1999-0001"}}]}""")]
    public async Task Lookup_MalformedOrMismatchedResponse_BecomesUnavailable(string body)
    {
        var (client, _, _) = NvdClients.Build(StubNvdHandler.Returning(() => StubNvdHandler.Json(body)));

        Assert.Equal(CveLookupStatus.Unavailable, (await client.LookupAsync(Cve)).Status);
    }

    [Fact]
    public async Task Lookup_OversizedResponse_IsRejected()
    {
        var huge = StubNvdHandler.Returning(() => StubNvdHandler.Json(new string('x', 20_000)));
        var (client, _, _) = NvdClients.Build(huge, maxBufferBytes: 1024);

        Assert.Equal(CveLookupStatus.Unavailable, (await client.LookupAsync(Cve)).Status);
    }

    [Fact]
    public async Task Lookup_OwnRateLimit_ProtectsTheQuota_WithoutApiKey()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler);

        var statuses = new List<CveLookupStatus>();
        for (var i = 1; i <= 5; i++)
        {
            statuses.Add((await client.LookupAsync($"CVE-2099-0000{i}")).Status);
        }

        // Limite oficial sem chave: 5 req/30 s. O cliente usa 4 e recusa a quinta localmente.
        Assert.Equal([CveLookupStatus.NotFound, CveLookupStatus.NotFound, CveLookupStatus.NotFound, CveLookupStatus.NotFound, CveLookupStatus.RateLimited], statuses);
        Assert.Equal(4, handler.Calls);
    }

    [Fact]
    public async Task Lookup_WithApiKey_AllowsTheHigherQuota()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler, o => o.ApiKey = "k");

        for (var i = 1; i <= 10; i++)
        {
            Assert.Equal(CveLookupStatus.NotFound, (await client.LookupAsync($"CVE-2099-0000{i}")).Status);
        }

        Assert.Equal(10, handler.Calls);
    }

    [Fact]
    public async Task Lookup_CallerCancellation_Propagates_AndDoesNotOpenTheCircuit()
    {
        var handler = StubNvdHandler.ServingFixtures();
        var (client, _, _) = NvdClients.Build(handler);
        using var cts = new CancellationTokenSource();
        await cts.CancelAsync();

        await Assert.ThrowsAnyAsync<OperationCanceledException>(() => client.LookupAsync(Cve, cts.Token));

        Assert.Equal(CveLookupStatus.Found, (await client.LookupAsync(Cve)).Status);
    }
}


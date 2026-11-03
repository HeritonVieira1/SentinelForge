using System.Net;
using System.Text;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging.Abstractions;
using SentinelForge.Infrastructure.Cve;

namespace SentinelForge.IntegrationTests.Cve;

/// <summary>Relógio controlado: permite avançar o tempo sem esperar (disjuntor do cliente do NVD).</summary>
public sealed class ManualTimeProvider : TimeProvider
{
    private DateTimeOffset _now = new(2026, 1, 1, 12, 0, 0, TimeSpan.Zero);

    public override DateTimeOffset GetUtcNow() => _now;

    public void Advance(TimeSpan span) => _now += span;
}

public sealed record CapturedRequest(HttpMethod Method, Uri Uri, IReadOnlyDictionary<string, string> Headers);

/// <summary>
/// Handler HTTP de teste. As respostas "felizes" usam fixtures com respostas REAIS capturadas do NVD;
/// aqui só se simulam falhas de transporte (timeout, 5xx, 429...), nunca dados de CVE inventados.
/// </summary>
public sealed class StubNvdHandler(Func<HttpRequestMessage, CancellationToken, Task<HttpResponseMessage>> respond) : HttpMessageHandler
{
    private int _calls;

    public int Calls => _calls;

    public List<CapturedRequest> Requests { get; } = [];

    protected override async Task<HttpResponseMessage> SendAsync(HttpRequestMessage request, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested(); // como os handlers reais, respeita o cancelamento
        Interlocked.Increment(ref _calls);
        lock (Requests)
        {
            Requests.Add(new CapturedRequest(
                request.Method,
                request.RequestUri!,
                request.Headers.ToDictionary(h => h.Key, h => string.Join(",", h.Value), StringComparer.OrdinalIgnoreCase)));
        }

        return await respond(request, cancellationToken);
    }

    public static HttpResponseMessage Json(string body, HttpStatusCode status = HttpStatusCode.OK) =>
        new(status) { Content = new StringContent(body, Encoding.UTF8, "application/json") };

    public static StubNvdHandler Returning(Func<HttpResponseMessage> response) =>
        new((_, _) => Task.FromResult(response()));

    /// <summary>Responde com a fixture real correspondente ao cveId pedido.</summary>
    public static StubNvdHandler ServingFixtures() =>
        new((request, _) =>
        {
            var id = System.Web.HttpUtility.ParseQueryString(request.RequestUri!.Query)["cveId"];
            var file = id switch
            {
                "CVE-2024-53677" => "nvd-CVE-2024-53677.json",
                "CVE-2024-3094" => "nvd-CVE-2024-3094.json",
                _ => "nvd-not-found.json",
            };
            return Task.FromResult(Json(Fixtures.Read(file)));
        });

    public static StubNvdHandler NeverAnswering() =>
        new(async (_, ct) =>
        {
            await Task.Delay(Timeout.Infinite, ct);
            throw new InvalidOperationException("unreachable");
        });
}

public static class Fixtures
{
    public static string Read(string name) =>
        File.ReadAllText(Path.Combine(AppContext.BaseDirectory, "Fixtures", "Nvd", name));
}

public static class NvdClients
{
    public static (NvdClient Client, ManualTimeProvider Time, NvdOptions Options) Build(
        StubNvdHandler handler, Action<NvdOptions>? tweak = null, long maxBufferBytes = 2 * 1024 * 1024)
    {
        var options = new NvdOptions { TimeoutSeconds = 1 };
        tweak?.Invoke(options);
        options.Validate();

        var time = new ManualTimeProvider();
        var http = new HttpClient(handler)
        {
            Timeout = TimeSpan.FromSeconds(options.TimeoutSeconds),
            MaxResponseContentBufferSize = maxBufferBytes,
        };

        var client = new NvdClient(
            http,
            new MemoryCache(new MemoryCacheOptions()),
            options,
            new NvdGate(options, time),
            time,
            NullLogger<NvdClient>.Instance);

        return (client, time, options);
    }
}


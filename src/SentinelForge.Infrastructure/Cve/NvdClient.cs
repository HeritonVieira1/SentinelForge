using System.Net;
using System.Text.Json;
using System.Threading.RateLimiting;
using Microsoft.Extensions.Caching.Memory;
using Microsoft.Extensions.Logging;
using SentinelForge.Application.Abstractions;

namespace SentinelForge.Infrastructure.Cve;

/// <summary>Estado compartilhado (singleton) dos limites de uso da API do NVD e do disjuntor.</summary>
public sealed class NvdGate : IDisposable
{
    private readonly SlidingWindowRateLimiter _limiter;
    private readonly TimeProvider _time;
    private DateTime _blockedUntilUtc = DateTime.MinValue;

    public NvdGate(NvdOptions options, TimeProvider time)
    {
        ArgumentNullException.ThrowIfNull(options);
        _time = time;

        // Limites oficiais: 5 req/30 s sem chave, 50 req/30 s com chave. Usamos uma margem abaixo do teto.
        _limiter = new SlidingWindowRateLimiter(new SlidingWindowRateLimiterOptions
        {
            PermitLimit = options.HasApiKey ? 45 : 4,
            Window = TimeSpan.FromSeconds(30),
            SegmentsPerWindow = 6,
            QueueLimit = 0,
            AutoReplenishment = true,
        });
    }

    public bool IsBlocked(out TimeSpan remaining)
    {
        var now = _time.GetUtcNow().UtcDateTime;
        remaining = _blockedUntilUtc > now ? _blockedUntilUtc - now : TimeSpan.Zero;
        return remaining > TimeSpan.Zero;
    }

    public void Block(TimeSpan duration) => _blockedUntilUtc = _time.GetUtcNow().UtcDateTime + duration;

    public bool TryAcquire(out TimeSpan retryAfter)
    {
        using var lease = _limiter.AttemptAcquire();
        retryAfter = lease.TryGetMetadata(MetadataName.RetryAfter, out var span) ? span : TimeSpan.FromSeconds(30);
        return lease.IsAcquired;
    }

    public void Dispose() => _limiter.Dispose();
}

/// <summary>
/// Cliente da API 2.0 do NVD (https://nvd.nist.gov/developers/vulnerabilities). Protege o restante da aplicação
/// com timeout, limite de taxa próprio, cache e disjuntor: qualquer falha vira <see cref="CveLookupStatus.Unavailable"/>
/// ou <see cref="CveLookupStatus.RateLimited"/>, nunca uma exceção.
/// </summary>
public sealed partial class NvdClient(
    HttpClient http,
    IMemoryCache cache,
    NvdOptions options,
    NvdGate gate,
    TimeProvider time,
    ILogger<NvdClient> logger) : ICveLookup
{
    public async Task<CveLookupResult> LookupAsync(string cveId, CancellationToken cancellationToken = default)
    {
        ArgumentException.ThrowIfNullOrWhiteSpace(cveId);

        var cacheKey = $"nvd:{cveId}";
        if (cache.TryGetValue(cacheKey, out CveLookupResult? cached) && cached is not null)
        {
            return cached;
        }

        if (gate.IsBlocked(out var remaining))
        {
            return new CveLookupResult(CveLookupStatus.Unavailable, RetryAfter: remaining);
        }

        if (!gate.TryAcquire(out var wait))
        {
            LogRateLimited(cveId);
            return new CveLookupResult(CveLookupStatus.RateLimited, RetryAfter: wait);
        }

        try
        {
            using var request = new HttpRequestMessage(HttpMethod.Get, $"{options.BaseUrl}?cveId={Uri.EscapeDataString(cveId)}");
            if (options.HasApiKey)
            {
                request.Headers.Add("apiKey", options.ApiKey);
            }

            using var response = await http.SendAsync(request, cancellationToken);

            switch (response.StatusCode)
            {
                case HttpStatusCode.OK:
                    var body = await response.Content.ReadAsStringAsync(cancellationToken);
                    var result = NvdResponseParser.Parse(body, cveId, time.GetUtcNow().UtcDateTime);
                    cache.Set(
                        cacheKey,
                        result,
                        TimeSpan.FromMinutes(result.Status == CveLookupStatus.Found ? options.CacheMinutes : options.NotFoundCacheMinutes));
                    return result;

                case HttpStatusCode.NotFound:
                    return new CveLookupResult(CveLookupStatus.NotFound);

                case HttpStatusCode.Forbidden or HttpStatusCode.TooManyRequests:
                    var retry = response.Headers.RetryAfter?.Delta ?? TimeSpan.FromSeconds(options.UnavailableCooldownSeconds);
                    gate.Block(retry);
                    LogUpstreamStatus(cveId, (int)response.StatusCode);
                    return new CveLookupResult(CveLookupStatus.RateLimited, RetryAfter: retry);

                default:
                    return Unavailable(cveId, $"HTTP {(int)response.StatusCode}");
            }
        }
        catch (OperationCanceledException) when (!cancellationToken.IsCancellationRequested)
        {
            return Unavailable(cveId, "timeout");
        }
        catch (HttpRequestException ex)
        {
            return Unavailable(cveId, ex.GetType().Name);
        }
        catch (JsonException)
        {
            return Unavailable(cveId, "invalid response");
        }
    }

    private CveLookupResult Unavailable(string cveId, string reason)
    {
        var cooldown = TimeSpan.FromSeconds(options.UnavailableCooldownSeconds);
        gate.Block(cooldown);
        LogUnavailable(cveId, reason);
        return new CveLookupResult(CveLookupStatus.Unavailable, RetryAfter: cooldown);
    }

    [LoggerMessage(Level = LogLevel.Warning, Message = "NVD lookup for {CveId} failed: {Reason}")]
    private partial void LogUnavailable(string cveId, string reason);

    [LoggerMessage(Level = LogLevel.Warning, Message = "NVD returned HTTP {Status} for {CveId}")]
    private partial void LogUpstreamStatus(string cveId, int status);

    [LoggerMessage(Level = LogLevel.Warning, Message = "NVD client-side rate limit reached for {CveId}")]
    private partial void LogRateLimited(string cveId);
}

namespace SentinelForge.Application.Abstractions;

public sealed record CveMetric(string Version, decimal Score, string Severity, string? Vector, string Source, string Type);

public sealed record CveReference(string Url, string? Source, IReadOnlyList<string> Tags);

/// <summary>Dados de um CVE obtidos de uma fonte externa, preservando a origem e o momento da consulta.</summary>
public sealed record CveInfo(
    string CveId,
    string? Description,
    DateTime? PublishedAt,
    DateTime? LastModifiedAt,
    string? VulnStatus,
    IReadOnlyList<CveMetric> Metrics,
    CveMetric? PreferredMetric,
    IReadOnlyList<CveReference> References,
    string Source,
    string SourceUrl,
    DateTime RetrievedAt);

public enum CveLookupStatus
{
    Found,
    NotFound,
    Unavailable,
    RateLimited,
}

public sealed record CveLookupResult(CveLookupStatus Status, CveInfo? Info = null, TimeSpan? RetryAfter = null);

public interface ICveLookup
{
    /// <param name="cveId">Identificador já validado e normalizado (CVE-AAAA-NNNN).</param>
    Task<CveLookupResult> LookupAsync(string cveId, CancellationToken cancellationToken = default);
}

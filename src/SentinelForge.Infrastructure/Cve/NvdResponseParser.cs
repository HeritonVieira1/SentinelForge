using System.Globalization;
using System.Text.Json;
using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.ValueObjects;

namespace SentinelForge.Infrastructure.Cve;

/// <summary>Converte a resposta da API 2.0 do NVD em <see cref="CveInfo"/>, validando o que vem de fora.</summary>
public static class NvdResponseParser
{
    public const string SourceName = "NVD";
    private const int MaxReferenceUrlLength = 2000;
    private const int MaxReferences = 200;
    private const int MaxDescriptionLength = 8000;

    private static readonly string[] MetricKeys = ["cvssMetricV40", "cvssMetricV31", "cvssMetricV30"];

    /// <exception cref="JsonException">Resposta fora do formato esperado.</exception>
    public static CveLookupResult Parse(string json, string cveId, DateTime retrievedAtUtc)
    {
        using var document = JsonDocument.Parse(json);
        var root = document.RootElement;

        if (root.ValueKind != JsonValueKind.Object
            || !root.TryGetProperty("vulnerabilities", out var vulnerabilities)
            || vulnerabilities.ValueKind != JsonValueKind.Array)
        {
            throw new JsonException("Unexpected NVD response shape.");
        }

        if (vulnerabilities.GetArrayLength() == 0)
        {
            return new CveLookupResult(CveLookupStatus.NotFound);
        }

        var cve = vulnerabilities[0].GetProperty("cve");
        var id = cve.GetProperty("id").GetString();
        if (!string.Equals(id, cveId, StringComparison.OrdinalIgnoreCase))
        {
            throw new JsonException("NVD returned a different CVE than requested.");
        }

        var metrics = ParseMetrics(cve);
        var preferred = metrics
            .OrderByDescending(m => m.Version)
            .ThenBy(m => string.Equals(m.Type, "Primary", StringComparison.OrdinalIgnoreCase) ? 0 : 1)
            .FirstOrDefault();

        var info = new CveInfo(
            cveId,
            ParseDescription(cve),
            ParseDate(cve, "published"),
            ParseDate(cve, "lastModified"),
            cve.TryGetProperty("vulnStatus", out var status) ? status.GetString() : null,
            metrics,
            preferred,
            ParseReferences(cve),
            SourceName,
            $"https://nvd.nist.gov/vuln/detail/{cveId}",
            retrievedAtUtc);

        return new CveLookupResult(CveLookupStatus.Found, info);
    }

    private static string? ParseDescription(JsonElement cve)
    {
        if (!cve.TryGetProperty("descriptions", out var descriptions) || descriptions.ValueKind != JsonValueKind.Array)
        {
            return null;
        }

        string? fallback = null;
        foreach (var item in descriptions.EnumerateArray())
        {
            var value = item.TryGetProperty("value", out var v) ? v.GetString() : null;
            if (string.IsNullOrWhiteSpace(value))
            {
                continue;
            }

            if (item.TryGetProperty("lang", out var lang) && lang.GetString() == "en")
            {
                return Truncate(value);
            }

            fallback ??= value;
        }

        return fallback is null ? null : Truncate(fallback);
    }

    private static string Truncate(string value) => value.Length > MaxDescriptionLength ? value[..MaxDescriptionLength] : value;

    private static DateTime? ParseDate(JsonElement cve, string property) =>
        cve.TryGetProperty(property, out var element)
        && DateTime.TryParse(element.GetString(), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var date)
            ? date
            : null;

    private static List<CveMetric> ParseMetrics(JsonElement cve)
    {
        var result = new List<CveMetric>();
        if (!cve.TryGetProperty("metrics", out var metrics) || metrics.ValueKind != JsonValueKind.Object)
        {
            return result;
        }

        foreach (var key in MetricKeys)
        {
            if (!metrics.TryGetProperty(key, out var entries) || entries.ValueKind != JsonValueKind.Array)
            {
                continue;
            }

            foreach (var entry in entries.EnumerateArray())
            {
                if (!entry.TryGetProperty("cvssData", out var data)
                    || !data.TryGetProperty("baseScore", out var scoreElement)
                    || !scoreElement.TryGetDecimal(out var score)
                    || score is < 0m or > 10m
                    || decimal.Round(score, 1) != score)
                {
                    continue;
                }

                var version = data.TryGetProperty("version", out var v) ? v.GetString() : null;
                if (version is not ("3.0" or "3.1" or "4.0"))
                {
                    continue;
                }

                result.Add(new CveMetric(
                    version,
                    score,
                    CvssRating.SeverityFor(score).ToString(),
                    data.TryGetProperty("vectorString", out var vec) ? vec.GetString() : null,
                    entry.TryGetProperty("source", out var src) ? src.GetString() ?? "unknown" : "unknown",
                    entry.TryGetProperty("type", out var type) ? type.GetString() ?? "unknown" : "unknown"));
            }
        }

        return result;
    }

    private static List<CveReference> ParseReferences(JsonElement cve)
    {
        var result = new List<CveReference>();
        if (!cve.TryGetProperty("references", out var references) || references.ValueKind != JsonValueKind.Array)
        {
            return result;
        }

        foreach (var reference in references.EnumerateArray())
        {
            var url = reference.TryGetProperty("url", out var u) ? u.GetString() : null;

            // Só URLs absolutas http(s): descarta javascript:, data:, file: etc. vindos de fonte externa.
            if (string.IsNullOrWhiteSpace(url) || url.Length > MaxReferenceUrlLength
                || !Uri.TryCreate(url, UriKind.Absolute, out var uri)
                || uri.Scheme is not ("http" or "https"))
            {
                continue;
            }

            var tags = reference.TryGetProperty("tags", out var t) && t.ValueKind == JsonValueKind.Array
                ? t.EnumerateArray().Select(x => x.GetString()).OfType<string>().Take(20).ToList()
                : [];

            result.Add(new CveReference(url, reference.TryGetProperty("source", out var s) ? s.GetString() : null, tags));
            if (result.Count >= MaxReferences)
            {
                break;
            }
        }

        return result;
    }
}

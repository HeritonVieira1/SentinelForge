using System.Globalization;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Domain.ValueObjects;

/// <summary>
/// Avaliação CVSS (3.0, 3.1 ou 4.0): pontuação, versão e vetor opcional. A severidade é sempre derivada da
/// pontuação pelas faixas oficiais. A pontuação NÃO é calculada a partir do vetor (isso exige as tabelas
/// oficiais do CVSS); ela vem do avaliador ou do NVD, e o vetor é validado e armazenado para rastreabilidade.
/// </summary>
public sealed record CvssRating
{
    public const int VectorMaxLength = 200;

    private static readonly string[] Impact = ["H", "L", "N"];

    private static readonly Dictionary<string, string[]> V3Base = new(StringComparer.Ordinal)
    {
        ["AV"] = ["N", "A", "L", "P"],
        ["AC"] = ["L", "H"],
        ["PR"] = ["N", "L", "H"],
        ["UI"] = ["N", "R"],
        ["S"] = ["U", "C"],
        ["C"] = Impact,
        ["I"] = Impact,
        ["A"] = Impact,
    };

    private static readonly Dictionary<string, string[]> V4Base = new(StringComparer.Ordinal)
    {
        ["AV"] = ["N", "A", "L", "P"],
        ["AC"] = ["L", "H"],
        ["AT"] = ["N", "P"],
        ["PR"] = ["N", "L", "H"],
        ["UI"] = ["N", "P", "A"],
        ["VC"] = Impact,
        ["VI"] = Impact,
        ["VA"] = Impact,
        ["SC"] = Impact,
        ["SI"] = Impact,
        ["SA"] = Impact,
    };

    private CvssRating(decimal score, CvssVersion version, string? vector)
    {
        Score = score;
        Version = version;
        Vector = vector;
    }

    public decimal Score { get; }

    public CvssVersion Version { get; }

    public string? Vector { get; }

    public Severity Severity => SeverityFor(Score);

    /// <summary>Faixas qualitativas oficiais: 0.0 None; 0.1–3.9 Low; 4.0–6.9 Medium; 7.0–8.9 High; 9.0–10.0 Critical.</summary>
    public static Severity SeverityFor(decimal score) => score switch
    {
        0m => Severity.None,
        < 4.0m => Severity.Low,
        < 7.0m => Severity.Medium,
        < 9.0m => Severity.High,
        _ => Severity.Critical,
    };

    public static CvssRating Create(decimal score, CvssVersion version, string? vector = null)
    {
        if (score is < 0m or > 10m || decimal.Round(score, 1) != score)
        {
            throw new DomainException("CvssScore must be between 0.0 and 10.0 with at most one decimal place.");
        }

        return new CvssRating(score, Guard.Defined(version, nameof(Version)), NormalizeVector(vector, version));
    }

    public static string Format(CvssVersion version) => version switch
    {
        CvssVersion.V30 => "3.0",
        CvssVersion.V31 => "3.1",
        CvssVersion.V40 => "4.0",
        _ => throw new DomainException("CvssVersion is invalid."),
    };

    public static CvssVersion ParseVersion(string? text) => text?.Trim() switch
    {
        "3.0" => CvssVersion.V30,
        "3.1" => CvssVersion.V31,
        "4.0" => CvssVersion.V40,
        _ => throw new DomainException("CvssVersion must be one of: 3.0, 3.1, 4.0."),
    };

    public static string ScoreText(decimal score) => score.ToString("0.0", CultureInfo.InvariantCulture);

    private static string? NormalizeVector(string? vector, CvssVersion version)
    {
        if (string.IsNullOrWhiteSpace(vector))
        {
            return null;
        }

        var text = vector.Trim();
        if (text.Length > VectorMaxLength)
        {
            throw new DomainException($"CvssVector must have at most {VectorMaxLength} characters.");
        }

        var prefix = $"CVSS:{Format(version)}/";
        if (!text.StartsWith(prefix, StringComparison.Ordinal))
        {
            throw new DomainException($"CvssVector must start with '{prefix}' to match CvssVersion {Format(version)}.");
        }

        var baseMetrics = version == CvssVersion.V40 ? V4Base : V3Base;
        var seen = new Dictionary<string, string>(StringComparer.Ordinal);

        foreach (var part in text[prefix.Length..].Split('/'))
        {
            var pair = part.Split(':');
            if (pair.Length != 2 || pair[0].Length is 0 or > 4 || pair[1].Length is 0 or > 3
                || !pair[0].All(char.IsAsciiLetterUpper) || !pair[1].All(char.IsAsciiLetterOrDigit)
                || !seen.TryAdd(pair[0], pair[1]))
            {
                throw new DomainException("CvssVector is malformed.");
            }
        }

        foreach (var (metric, allowed) in baseMetrics)
        {
            if (!seen.TryGetValue(metric, out var value) || !allowed.Contains(value, StringComparer.Ordinal))
            {
                throw new DomainException($"CvssVector has a missing or invalid base metric '{metric}'.");
            }
        }

        return text;
    }
}


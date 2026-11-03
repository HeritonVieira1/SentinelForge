using System.Text.RegularExpressions;

namespace SentinelForge.Domain.ValueObjects;

public static partial class CveIdentifier
{
    public static bool TryNormalize(string? input, out string normalized)
    {
        normalized = string.Empty;
        if (string.IsNullOrWhiteSpace(input))
        {
            return false;
        }

        var candidate = input.Trim().ToUpperInvariant();
        if (!Pattern().IsMatch(candidate))
        {
            return false;
        }

        normalized = candidate;
        return true;
    }

    [GeneratedRegex(@"^CVE-\d{4}-\d{4,}$", RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex Pattern();
}

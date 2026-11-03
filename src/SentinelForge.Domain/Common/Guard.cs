using System.Text.RegularExpressions;

namespace SentinelForge.Domain.Common;

internal static partial class Guard
{
    public static string NotBlank(string? value, string field, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            throw new DomainException($"{field} is required.");
        }

        var trimmed = RejectControlCharacters(value, field).Trim();
        return trimmed.Length > maxLength
            ? throw new DomainException($"{field} must have at most {maxLength} characters.")
            : trimmed;
    }

    public static string MaxLength(string? value, string field, int maxLength)
    {
        var text = (value is null ? string.Empty : RejectControlCharacters(value, field)).Trim();
        return text.Length > maxLength
            ? throw new DomainException($"{field} must have at most {maxLength} characters.")
            : text;
    }

    /// <summary>
    /// Rejeita caracteres de controle (exceto tab, quebra de linha e retorno de carro). O PostgreSQL não aceita NUL (0x00)
    /// em texto e, sem esta validação, uma entrada hostil viraria um erro 500 (achado pelo DAST); os demais caracteres
    /// de controle não têm uso legítimo em títulos, descrições ou identificadores.
    /// </summary>
    public static string RejectControlCharacters(string value, string field)
    {
        foreach (var ch in value)
        {
            if (char.IsControl(ch) && ch is not ('\t' or '\n' or '\r'))
            {
                throw new DomainException($"{field} contains invalid characters.");
            }
        }

        return value;
    }

    public static DateTime Utc(DateTime value, string field) =>
        value.Kind == DateTimeKind.Utc ? value : throw new DomainException($"{field} must be a UTC date.");

    public static T Defined<T>(T value, string field)
        where T : struct, Enum =>
        Enum.IsDefined(value) ? value : throw new DomainException($"{field} has an invalid value.");

    public static Guid NotEmpty(Guid value, string field) =>
        value == Guid.Empty ? throw new DomainException($"{field} is required.") : value;

    public static string Email(string? value)
    {
#pragma warning disable CA1308 // E-mails são normalizados em minúsculas por convenção, não para comparação de segurança.
        var email = NotBlank(value, "Email", 254).ToLowerInvariant();
#pragma warning restore CA1308
        return EmailRegex().IsMatch(email) ? email : throw new DomainException("Email is invalid.");
    }

    public static string? CveId(string? value)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        return SentinelForge.Domain.ValueObjects.CveIdentifier.TryNormalize(value, out var cve)
            ? cve
            : throw new DomainException("CveId is invalid.");
    }

    public static string? HttpUrl(string? value, string field, int maxLength)
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        var url = NotBlank(value, field, maxLength);
        return Uri.TryCreate(url, UriKind.Absolute, out var uri) && (uri.Scheme is "http" or "https")
            ? url
            : throw new DomainException($"{field} must be an absolute http(s) URL.");
    }

    [GeneratedRegex(@"^[^@\s]+@[^@\s]+\.[^@\s]+$", RegexOptions.None, matchTimeoutMilliseconds: 250)]
    private static partial Regex EmailRegex();

}



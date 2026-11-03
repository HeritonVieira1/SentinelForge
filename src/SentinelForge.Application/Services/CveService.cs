using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Domain.Enums;
using SentinelForge.Domain.ValueObjects;

namespace SentinelForge.Application.Services;

/// <summary>
/// Consulta de CVE em fonte externa. Restrita a Administrator e SecurityAnalyst para que a plataforma não sirva de
/// proxy aberto para a cota da API externa. Indisponibilidade da fonte nunca afeta o restante da aplicação.
/// </summary>
public sealed class CveService(ICveLookup lookup, ICurrentUser current)
{
    public async Task<Result<CveInfo>> LookupAsync(string? cveId, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<CveInfo>(ErrorKind.Unauthorized, "Authentication required.");
        }

        if (actor.Role is not (UserRole.Administrator or UserRole.SecurityAnalyst))
        {
            return Result.Failure<CveInfo>(ErrorKind.Forbidden, "Access denied.");
        }

        if (!CveIdentifier.TryNormalize(cveId, out var normalized))
        {
            return Result.Failure<CveInfo>(ErrorKind.Validation, "CVE identifier must match CVE-YYYY-NNNN.");
        }

        var result = await lookup.LookupAsync(normalized, ct);
        return result.Status switch
        {
            CveLookupStatus.Found => Result.Success(result.Info!),
            CveLookupStatus.NotFound => Result.Failure<CveInfo>(ErrorKind.NotFound, "CVE not found."),
            CveLookupStatus.RateLimited => Result.Failure<CveInfo>(new ResultError(
                ErrorKind.TooManyRequests, "The external CVE source is rate limiting requests. Try again later.", null, RetryAfter(result))),
            _ => Result.Failure<CveInfo>(new ResultError(
                ErrorKind.Unavailable, "The external CVE source is currently unavailable. Try again later.", null, RetryAfter(result))),
        };
    }

    private static int? RetryAfter(CveLookupResult result) =>
        result.RetryAfter is { } span ? (int)Math.Ceiling(Math.Max(span.TotalSeconds, 1)) : null;
}

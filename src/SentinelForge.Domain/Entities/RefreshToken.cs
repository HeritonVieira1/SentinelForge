using SentinelForge.Domain.Common;

namespace SentinelForge.Domain.Entities;

/// <summary>
/// Refresh token de uso único. Só o hash (SHA-256) do token é armazenado. Tokens da mesma sessão
/// (<see cref="SessionId"/>) formam uma cadeia de rotação; reutilizar um token já usado revoga a sessão inteira.
/// </summary>
public sealed class RefreshToken
{
    public const int TokenHashLength = 64;
    public const int RevokedReasonMaxLength = 100;

    private RefreshToken()
    {
    }

    public Guid Id { get; private set; }

    public Guid UserId { get; private set; }

    public Guid SessionId { get; private set; }

    public string TokenHash { get; private set; } = string.Empty;

    public DateTime CreatedAt { get; private set; }

    public DateTime ExpiresAt { get; private set; }

    /// <summary>Quando o token foi trocado por um novo (rotação).</summary>
    public DateTime? UsedAt { get; private set; }

    public DateTime? RevokedAt { get; private set; }

    public string? RevokedReason { get; private set; }

    public string? CreatedByIp { get; private set; }

    public static RefreshToken Create(
        Guid userId,
        Guid sessionId,
        string tokenHash,
        DateTime utcNow,
        TimeSpan lifetime,
        string? createdByIp)
    {
        var hash = Guard.NotBlank(tokenHash, nameof(TokenHash), TokenHashLength);
        if (hash.Length != TokenHashLength)
        {
            throw new DomainException($"{nameof(TokenHash)} must have {TokenHashLength} characters.");
        }

        if (lifetime <= TimeSpan.Zero)
        {
            throw new DomainException("Refresh token lifetime must be positive.");
        }

        return new RefreshToken
        {
            Id = Guid.CreateVersion7(),
            UserId = Guard.NotEmpty(userId, nameof(UserId)),
            SessionId = Guard.NotEmpty(sessionId, nameof(SessionId)),
            TokenHash = hash,
            CreatedAt = Guard.Utc(utcNow, nameof(CreatedAt)),
            ExpiresAt = utcNow.Add(lifetime),
            CreatedByIp = string.IsNullOrWhiteSpace(createdByIp) ? null : Guard.MaxLength(createdByIp, nameof(CreatedByIp), AuditLog.IpAddressMaxLength),
        };
    }

    public bool IsExpired(DateTime utcNow) => ExpiresAt <= utcNow;

    public bool IsActive(DateTime utcNow) => UsedAt is null && RevokedAt is null && !IsExpired(utcNow);
}

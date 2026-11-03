using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Abstractions;

public sealed record AccessToken(string Value, DateTime ExpiresAt);

public sealed record GeneratedRefreshToken(string Raw, string Hash);

public interface ITokenService
{
    AccessToken CreateAccessToken(Guid userId, UserRole role, Guid sessionId, DateTime utcNow);

    /// <summary>Gera um token aleatório criptograficamente seguro e o hash que deve ser persistido.</summary>
    GeneratedRefreshToken NewRefreshToken();

    string HashRefreshToken(string rawToken);
}

using System.Buffers.Text;
using System.Security.Cryptography;
using System.Text;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Infrastructure.Security;

internal sealed class TokenService(JwtSettings settings) : ITokenService
{
    public const string SessionClaim = "sid";
    public const string RoleClaim = "role";

    private readonly JsonWebTokenHandler _handler = new();
    private readonly SigningCredentials _credentials = new(settings.CreateSigningKey(), SecurityAlgorithms.HmacSha256);

    public AccessToken CreateAccessToken(Guid userId, UserRole role, Guid sessionId, DateTime utcNow)
    {
        var expires = utcNow.AddMinutes(settings.AccessTokenMinutes);

        // Apenas identificadores e papel: nenhum dado pessoal ou sensível no token.
        var descriptor = new SecurityTokenDescriptor
        {
            Issuer = settings.Issuer,
            Audience = settings.Audience,
            IssuedAt = utcNow,
            NotBefore = utcNow,
            Expires = expires,
            SigningCredentials = _credentials,
            Claims = new Dictionary<string, object>
            {
                [JwtRegisteredClaimNames.Sub] = userId.ToString(),
                [JwtRegisteredClaimNames.Jti] = Guid.NewGuid().ToString(),
                [RoleClaim] = role.ToString(),
                [SessionClaim] = sessionId.ToString(),
            },
        };

        return new AccessToken(_handler.CreateToken(descriptor), expires);
    }

    public GeneratedRefreshToken NewRefreshToken()
    {
        var raw = Base64Url.EncodeToString(RandomNumberGenerator.GetBytes(32));
        return new GeneratedRefreshToken(raw, HashRefreshToken(raw));
    }

    // SHA-256 é adequado aqui: o token tem 256 bits de entropia, então não há o que "quebrar" por força bruta.
    public string HashRefreshToken(string rawToken) =>
        Convert.ToHexStringLower(SHA256.HashData(Encoding.UTF8.GetBytes(rawToken)));
}

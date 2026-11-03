using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Api.Security;

/// <summary>
/// Ator da requisição HTTP, derivado do JWT já validado. O IP vem da conexão; cabeçalhos como
/// X-Forwarded-For não são confiáveis sem um proxy reverso configurado.
/// </summary>
internal sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public Guid? UserId =>
        Guid.TryParse(accessor.HttpContext?.User.FindFirst(AuthClaims.Subject)?.Value, out var id) ? id : null;

    public UserRole? Role =>
        Enum.TryParse<UserRole>(accessor.HttpContext?.User.FindFirst(AuthClaims.Role)?.Value, out var role) && Enum.IsDefined(role)
            ? role
            : null;

    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}

using System.Security.Claims;
using SentinelForge.Application.Abstractions;

namespace SentinelForge.Api.Security;

/// <summary>
/// Obtém o ator da requisição HTTP. Enquanto a autenticação (Fase 3) não existe, UserId é sempre nulo
/// (evento de sistema). O IP vem da conexão; cabeçalhos como X-Forwarded-For não são confiáveis aqui.
/// </summary>
internal sealed class HttpContextCurrentUser(IHttpContextAccessor accessor) : ICurrentUser
{
    public Guid? UserId =>
        Guid.TryParse(accessor.HttpContext?.User.FindFirstValue(ClaimTypes.NameIdentifier), out var id) ? id : null;

    public string? IpAddress => accessor.HttpContext?.Connection.RemoteIpAddress?.ToString();
}

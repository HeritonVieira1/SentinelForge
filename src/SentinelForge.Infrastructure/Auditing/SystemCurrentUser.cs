using SentinelForge.Application.Abstractions;

namespace SentinelForge.Infrastructure.Auditing;

/// <summary>Ator padrão (evento de sistema) quando não há usuário autenticado.</summary>
internal sealed class SystemCurrentUser : ICurrentUser
{
    public Guid? UserId => null;

    public string? IpAddress => null;
}

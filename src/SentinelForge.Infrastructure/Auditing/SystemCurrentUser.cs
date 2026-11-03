using SentinelForge.Application.Abstractions;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Infrastructure.Auditing;

/// <summary>Ator padrão (evento de sistema) quando não há usuário autenticado.</summary>
internal sealed class SystemCurrentUser : ICurrentUser
{
    public Guid? UserId => null;

    public UserRole? Role => null;

    public string? IpAddress => null;
}

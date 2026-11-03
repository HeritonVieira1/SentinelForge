using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Abstractions;

/// <summary>Contexto do ator da operação atual, usado para auditoria e autorização.</summary>
public interface ICurrentUser
{
    /// <summary>Identificador do usuário autenticado; nulo para eventos de sistema/anônimos.</summary>
    Guid? UserId { get; }

    /// <summary>Papel do usuário autenticado (validado contra o banco a cada requisição).</summary>
    UserRole? Role { get; }

    /// <summary>Endereço IP de origem da requisição, quando houver.</summary>
    string? IpAddress { get; }
}

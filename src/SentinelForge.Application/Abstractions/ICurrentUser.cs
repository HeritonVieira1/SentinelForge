namespace SentinelForge.Application.Abstractions;

/// <summary>Contexto do ator da operação atual, usado para auditoria e (na Fase 3) autorização.</summary>
public interface ICurrentUser
{
    /// <summary>Identificador do usuário autenticado; nulo para eventos de sistema.</summary>
    Guid? UserId { get; }

    /// <summary>Endereço IP de origem da requisição, quando houver.</summary>
    string? IpAddress { get; }
}

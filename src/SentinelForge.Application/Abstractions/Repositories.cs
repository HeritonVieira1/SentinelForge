using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Application.Abstractions;

public interface IUnitOfWork
{
    /// <exception cref="ConflictException">Violação de unicidade.</exception>
    Task SaveChangesAsync(CancellationToken cancellationToken = default);
}

public interface IUserRepository
{
    Task<User?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default);

    Task<User?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default);

    Task<bool> AnyAdministratorAsync(CancellationToken cancellationToken = default);

    Task<PagedResult<User>> ListAsync(int page, int pageSize, CancellationToken cancellationToken = default);

    void Add(User user);
}

public interface IRefreshTokenRepository
{
    void Add(RefreshToken token);

    Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default);

    /// <summary>Marca o token como usado de forma atômica; retorna false se já estava usado/revogado.</summary>
    Task<bool> TryConsumeAsync(Guid tokenId, DateTime utcNow, CancellationToken cancellationToken = default);

    Task RevokeSessionAsync(Guid sessionId, string reason, DateTime utcNow, CancellationToken cancellationToken = default);

    Task RevokeAllForUserAsync(Guid userId, string reason, DateTime utcNow, CancellationToken cancellationToken = default);

    Task<bool> IsSessionActiveAsync(Guid sessionId, Guid userId, CancellationToken cancellationToken = default);
}

public interface IApplicationRepository
{
    Task<PagedResult<DomainApplication>> ListAccessibleAsync(
        Guid userId, UserRole role, int page, int pageSize, CancellationToken cancellationToken = default);

    Task<DomainApplication?> FindAccessibleAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default);
}

public interface IVulnerabilityRepository
{
    void Add(Vulnerability vulnerability);

    /// <summary>Leitura (sem rastreamento): retorna a vulnerabilidade só se o usuário tiver acesso à aplicação dela.</summary>
    Task<Vulnerability?> FindAccessibleAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default);

    /// <summary>Mesma regra de acesso, com rastreamento para alteração.</summary>
    Task<Vulnerability?> FindAccessibleForUpdateAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default);

    Task<PagedResult<Vulnerability>> SearchAsync(
        VulnerabilityFilter filter, Guid userId, UserRole role, CancellationToken cancellationToken = default);

    Task<PagedResult<VulnerabilityHistory>> ListHistoryAsync(
        Guid vulnerabilityId, int page, int pageSize, CancellationToken cancellationToken = default);

    Task<VulnerabilitySummaryDto> SummarizeAsync(
        Guid userId, UserRole role, CancellationToken cancellationToken = default);
}
public interface IAuditLogRepository
{
    void Add(AuditLog log);

    Task<PagedResult<AuditLog>> ListAsync(
        int page, int pageSize, string? entityName, Guid? entityId, CancellationToken cancellationToken = default);
}


using Microsoft.EntityFrameworkCore;
using Npgsql;
using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Infrastructure.Persistence.Repositories;

internal sealed class UnitOfWork(SentinelForgeDbContext db) : IUnitOfWork
{
    public async Task SaveChangesAsync(CancellationToken cancellationToken = default)
    {
        try
        {
            await db.SaveChangesAsync(cancellationToken);
        }
        catch (DbUpdateException ex) when (ex.InnerException is PostgresException { SqlState: PostgresErrorCodes.UniqueViolation })
        {
            throw new ConflictException("A unique constraint was violated.", ex);
        }
        catch (DbUpdateConcurrencyException ex)
        {
            throw new ConflictException("The resource was modified by another request. Reload and try again.", ex);
        }
    }
}

internal static class Pagination
{
    public static async Task<PagedResult<T>> ToPagedAsync<T>(
        this IQueryable<T> ordered, int page, int pageSize, CancellationToken ct)
    {
        var total = await ordered.CountAsync(ct);
        var items = await ordered.Skip((page - 1) * pageSize).Take(pageSize).ToListAsync(ct);
        return new PagedResult<T>(items, page, pageSize, total);
    }
}

internal sealed class UserRepository(SentinelForgeDbContext db) : IUserRepository
{
    public Task<User?> FindByIdAsync(Guid id, CancellationToken cancellationToken = default) =>
        db.Users.FirstOrDefaultAsync(u => u.Id == id, cancellationToken);

    public Task<User?> FindByEmailAsync(string normalizedEmail, CancellationToken cancellationToken = default) =>
        db.Users.FirstOrDefaultAsync(u => u.Email == normalizedEmail, cancellationToken);

    public Task<bool> AnyAdministratorAsync(CancellationToken cancellationToken = default) =>
        db.Users.AnyAsync(u => u.Role == UserRole.Administrator, cancellationToken);

    public Task<PagedResult<User>> ListAsync(int page, int pageSize, CancellationToken cancellationToken = default) =>
        db.Users.AsNoTracking().OrderBy(u => u.CreatedAt).ThenBy(u => u.Id).ToPagedAsync(page, pageSize, cancellationToken);

    public void Add(User user) => db.Users.Add(user);
}

internal sealed class RefreshTokenRepository(SentinelForgeDbContext db) : IRefreshTokenRepository
{
    public void Add(RefreshToken token) => db.RefreshTokens.Add(token);

    public Task<RefreshToken?> FindByHashAsync(string tokenHash, CancellationToken cancellationToken = default) =>
        db.RefreshTokens.AsNoTracking().FirstOrDefaultAsync(t => t.TokenHash == tokenHash, cancellationToken);

    public async Task<bool> TryConsumeAsync(Guid tokenId, DateTime utcNow, CancellationToken cancellationToken = default) =>
        await db.RefreshTokens
            .Where(t => t.Id == tokenId && t.UsedAt == null && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.UsedAt, utcNow), cancellationToken) == 1;

    public async Task RevokeSessionAsync(Guid sessionId, string reason, DateTime utcNow, CancellationToken cancellationToken = default) =>
        await db.RefreshTokens
            .Where(t => t.SessionId == sessionId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, utcNow).SetProperty(t => t.RevokedReason, reason), cancellationToken);

    public async Task RevokeAllForUserAsync(Guid userId, string reason, DateTime utcNow, CancellationToken cancellationToken = default) =>
        await db.RefreshTokens
            .Where(t => t.UserId == userId && t.RevokedAt == null)
            .ExecuteUpdateAsync(s => s.SetProperty(t => t.RevokedAt, utcNow).SetProperty(t => t.RevokedReason, reason), cancellationToken);

    public Task<bool> IsSessionActiveAsync(Guid sessionId, Guid userId, CancellationToken cancellationToken = default) =>
        db.RefreshTokens.AnyAsync(
            t => t.SessionId == sessionId
                && t.UserId == userId
                && !db.RefreshTokens.Any(r => r.SessionId == sessionId && r.RevokedAt != null),
            cancellationToken);
}

internal static class AccessRules
{
    public static bool SeesEverything(UserRole role) => role is UserRole.Administrator or UserRole.SecurityAnalyst;
}

internal sealed class ApplicationRepository(SentinelForgeDbContext db) : IApplicationRepository
{
    public Task<PagedResult<DomainApplication>> ListAccessibleAsync(
        Guid userId, UserRole role, int page, int pageSize, CancellationToken cancellationToken = default) =>
        Accessible(userId, role).AsNoTracking().OrderBy(a => a.Name).ThenBy(a => a.Id).ToPagedAsync(page, pageSize, cancellationToken);

    public Task<DomainApplication?> FindAccessibleAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default) =>
        Accessible(userId, role).AsNoTracking().FirstOrDefaultAsync(a => a.Id == id, cancellationToken);

    private IQueryable<DomainApplication> Accessible(Guid userId, UserRole role) =>
        AccessRules.SeesEverything(role)
            ? db.Applications
            : db.Applications.Where(a => a.OwnerUserId == userId || a.Vulnerabilities.Any(v => v.AssignedUserId == userId));
}

internal sealed class VulnerabilityRepository(SentinelForgeDbContext db) : IVulnerabilityRepository
{
    public void Add(Vulnerability vulnerability) => db.Vulnerabilities.Add(vulnerability);

    public Task<Vulnerability?> FindAccessibleAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default) =>
        Accessible(userId, role).AsNoTracking().FirstOrDefaultAsync(v => v.Id == id, cancellationToken);

    public Task<Vulnerability?> FindAccessibleForUpdateAsync(
        Guid id, Guid userId, UserRole role, CancellationToken cancellationToken = default) =>
        Accessible(userId, role).FirstOrDefaultAsync(v => v.Id == id, cancellationToken);

    public async Task<PagedResult<Vulnerability>> SearchAsync(
        VulnerabilityFilter filter, Guid userId, UserRole role, CancellationToken cancellationToken = default)
    {
        var query = Accessible(userId, role).AsNoTracking();

        if (filter.Severity is { } severity)
        {
            query = query.Where(v => v.Severity == severity);
        }

        if (filter.Status is { } status)
        {
            query = query.Where(v => v.Status == status);
        }

        if (filter.ApplicationId is { } applicationId)
        {
            query = query.Where(v => v.ApplicationId == applicationId);
        }

        if (filter.AssignedUserId is { } assignedUserId)
        {
            query = query.Where(v => v.AssignedUserId == assignedUserId);
        }

        if (filter.Text is { } text)
        {
            // Parâmetro (nunca concatenado) e curingas do usuário escapados: a busca é literal.
            var pattern = "%" + text.Replace("\\", "\\\\", StringComparison.Ordinal).Replace("%", "\\%", StringComparison.Ordinal).Replace("_", "\\_", StringComparison.Ordinal) + "%";
            query = query.Where(v =>
                EF.Functions.ILike(v.Title, pattern, "\\")
                || EF.Functions.ILike(v.Description, pattern, "\\")
                || EF.Functions.ILike(v.Category, pattern, "\\")
                || (v.CveId != null && EF.Functions.ILike(v.CveId, pattern, "\\")));
        }

        return await Order(query, filter).ToPagedAsync(filter.Page, filter.PageSize, cancellationToken);
    }

    public Task<PagedResult<VulnerabilityHistory>> ListHistoryAsync(
        Guid vulnerabilityId, int page, int pageSize, CancellationToken cancellationToken = default) =>
        db.VulnerabilityHistory.AsNoTracking()
            .Where(h => h.VulnerabilityId == vulnerabilityId)
            .OrderByDescending(h => h.CreatedAt).ThenByDescending(h => h.Id)
            .ToPagedAsync(page, pageSize, cancellationToken);

    public async Task<VulnerabilitySummaryDto> SummarizeAsync(
        Guid userId, UserRole role, CancellationToken cancellationToken = default)
    {
        var scoped = Accessible(userId, role).AsNoTracking();

        var total = await scoped.CountAsync(cancellationToken);

        var bySeverity = await scoped.GroupBy(v => v.Severity)
            .Select(g => new { Key = g.Key, Count = g.Count() }).ToListAsync(cancellationToken);
        var byStatus = await scoped.GroupBy(v => v.Status)
            .Select(g => new { Key = g.Key, Count = g.Count() }).ToListAsync(cancellationToken);

        // "Aberta" = ainda representa risco: tudo que não foi verificado nem teve o risco aceito.
        var openCritical = await scoped.CountAsync(
            v => v.Severity == Severity.Critical
                && v.Status != VulnerabilityStatus.Verified
                && v.Status != VulnerabilityStatus.AcceptedRisk,
            cancellationToken);

        var byApplication = await scoped
            .GroupBy(v => new { v.ApplicationId, v.Application!.Name })
            .Select(g => new { g.Key.ApplicationId, g.Key.Name, Count = g.Count() })
            .OrderByDescending(x => x.Count).ThenBy(x => x.Name)
            .Take(50)
            .ToListAsync(cancellationToken);

        var byAssignee = await scoped
            .GroupBy(v => v.AssignedUserId)
            .Select(g => new { UserId = g.Key, Count = g.Count() })
            .OrderByDescending(x => x.Count)
            .Take(50)
            .ToListAsync(cancellationToken);

        var resolution = await scoped
            .Where(v => v.ResolvedAt != null)
            .GroupBy(_ => 1)
            .Select(g => new { Count = g.Count(), Hours = g.Average(v => (v.ResolvedAt!.Value - v.DiscoveredAt).TotalHours) })
            .FirstOrDefaultAsync(cancellationToken);

        return new VulnerabilitySummaryDto(
            total,
            Enum.GetValues<Severity>().ToDictionary(s => s.ToString(), s => bySeverity.FirstOrDefault(x => x.Key == s)?.Count ?? 0),
            Enum.GetValues<VulnerabilityStatus>().ToDictionary(s => s.ToString(), s => byStatus.FirstOrDefault(x => x.Key == s)?.Count ?? 0),
            openCritical,
            [.. byApplication.Select(x => new CountByApplication(x.ApplicationId, x.Name, x.Count))],
            [.. byAssignee.Select(x => new CountByAssignee(x.UserId, x.Count))],
            resolution is null ? null : Math.Round(resolution.Hours, 2),
            resolution?.Count ?? 0);
    }

    /// <summary>
    /// Escopo de acesso aplicado em TODA consulta: administradores e analistas veem tudo; Developers apenas as
    /// aplicações que possuem ou nas quais são responsáveis por alguma vulnerabilidade.
    /// </summary>
    private IQueryable<Vulnerability> Accessible(Guid userId, UserRole role) =>
        AccessRules.SeesEverything(role)
            ? db.Vulnerabilities
            : db.Vulnerabilities.Where(v =>
                v.Application!.OwnerUserId == userId
                || db.Vulnerabilities.Any(o => o.ApplicationId == v.ApplicationId && o.AssignedUserId == userId));

    private static IQueryable<Vulnerability> Order(IQueryable<Vulnerability> query, VulnerabilityFilter filter)
    {
        var desc = filter.Descending;

        IOrderedQueryable<Vulnerability> ordered = filter.Sort switch
        {
            VulnerabilitySort.Title => desc ? query.OrderByDescending(v => v.Title) : query.OrderBy(v => v.Title),
            VulnerabilitySort.CreatedAt => desc ? query.OrderByDescending(v => v.CreatedAt) : query.OrderBy(v => v.CreatedAt),
            VulnerabilitySort.UpdatedAt => desc ? query.OrderByDescending(v => v.UpdatedAt) : query.OrderBy(v => v.UpdatedAt),
            VulnerabilitySort.Status => desc ? query.OrderByDescending(v => v.Status) : query.OrderBy(v => v.Status),

            // Severidade por ranking (não alfabética); sem pontuação sempre por último.
            VulnerabilitySort.Severity => desc
                ? query.OrderByDescending(v => v.Severity == Severity.Critical ? 5 : v.Severity == Severity.High ? 4 : v.Severity == Severity.Medium ? 3 : v.Severity == Severity.Low ? 2 : v.Severity == Severity.None ? 1 : 0)
                : query.OrderBy(v => v.Severity == Severity.Critical ? 5 : v.Severity == Severity.High ? 4 : v.Severity == Severity.Medium ? 3 : v.Severity == Severity.Low ? 2 : v.Severity == Severity.None ? 1 : 0),
            VulnerabilitySort.CvssScore => desc
                ? query.OrderBy(v => v.CvssScore == null).ThenByDescending(v => v.CvssScore)
                : query.OrderBy(v => v.CvssScore == null).ThenBy(v => v.CvssScore),
            _ => desc ? query.OrderByDescending(v => v.DiscoveredAt) : query.OrderBy(v => v.DiscoveredAt),
        };

        return ordered.ThenBy(v => v.Id);
    }
}
internal sealed class AuditLogRepository(SentinelForgeDbContext db) : IAuditLogRepository
{
    public void Add(AuditLog log) => db.AuditLogs.Add(log);

    public Task<PagedResult<AuditLog>> ListAsync(
        int page, int pageSize, string? entityName, Guid? entityId, CancellationToken cancellationToken = default)
    {
        var query = db.AuditLogs.AsNoTracking();

        if (!string.IsNullOrWhiteSpace(entityName))
        {
            query = query.Where(a => a.EntityName == entityName);
        }

        if (entityId is { } id)
        {
            query = query.Where(a => a.EntityId == id);
        }

        return query.OrderByDescending(a => a.CreatedAt).ThenBy(a => a.Id).ToPagedAsync(page, pageSize, cancellationToken);
    }
}



using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Services;

/// <summary>
/// Leitura de aplicações. Administradores e analistas veem todas; Developers apenas as que possuem
/// ou nas quais são responsáveis por alguma vulnerabilidade. Recursos inacessíveis retornam NotFound (anti-IDOR).
/// </summary>
public sealed class ApplicationsService(IApplicationRepository applications, IVulnerabilityRepository vulnerabilities, ICurrentUser current)
{
    public async Task<Result<PagedResult<ApplicationDto>>> ListAsync(int page, int pageSize, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<PagedResult<ApplicationDto>>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var (p, size) = Paging.Normalize(page, pageSize);
        var result = await applications.ListAccessibleAsync(actor.Id, actor.Role, p, size, ct);
        return Result.Success(new PagedResult<ApplicationDto>([.. result.Items.Select(a => a.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }

    public async Task<Result<ApplicationDto>> GetAsync(Guid id, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<ApplicationDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var app = await applications.FindAccessibleAsync(id, actor.Id, actor.Role, ct);
        return app is null
            ? Result.Failure<ApplicationDto>(ErrorKind.NotFound, "Application not found.")
            : Result.Success(app.ToDto());
    }

    public async Task<Result<PagedResult<VulnerabilityDto>>> ListVulnerabilitiesAsync(
        Guid applicationId, int page, int pageSize, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<PagedResult<VulnerabilityDto>>(ErrorKind.Unauthorized, "Authentication required.");
        }

        if (await applications.FindAccessibleAsync(applicationId, actor.Id, actor.Role, ct) is null)
        {
            return Result.Failure<PagedResult<VulnerabilityDto>>(ErrorKind.NotFound, "Application not found.");
        }

        var (p, size) = Paging.Normalize(page, pageSize);
        var filter = new VulnerabilityFilter(null, null, applicationId, null, null, VulnerabilitySort.DiscoveredAt, true, p, size);
        var result = await vulnerabilities.SearchAsync(filter, actor.Id, actor.Role, ct);
        return Result.Success(new PagedResult<VulnerabilityDto>([.. result.Items.Select(v => v.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }
}

public sealed class AuditService(IAuditLogRepository auditLogs, ICurrentUser current)
{
    public async Task<Result<PagedResult<AuditLogDto>>> ListAsync(
        int page, int pageSize, string? entityName, Guid? entityId, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { IsAdministrator: true })
        {
            return Result.Failure<PagedResult<AuditLogDto>>(ErrorKind.Forbidden, "Access denied.");
        }

        if (entityName is { Length: > 100 } || InputValidation.HasControlCharacters(entityName))
        {
            return Result.Failure<PagedResult<AuditLogDto>>(new ResultError(
                ErrorKind.Validation,
                "One or more validation errors occurred.",
                new Dictionary<string, string[]> { ["entityName"] = ["entityName must have at most 100 characters and no control characters."] }));
        }

        var (p, size) = Paging.Normalize(page, pageSize);
        var result = await auditLogs.ListAsync(p, size, entityName, entityId, ct);
        return Result.Success(new PagedResult<AuditLogDto>([.. result.Items.Select(l => l.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }
}


using SentinelForge.Application.Abstractions;
using SentinelForge.Application.Common;
using SentinelForge.Application.Contracts;
using SentinelForge.Domain.Common;
using SentinelForge.Domain.Entities;
using SentinelForge.Domain.Enums;
using SentinelForge.Domain.ValueObjects;
using SentinelForge.Domain.Workflow;

namespace SentinelForge.Application.Services;

/// <summary>
/// Casos de uso do módulo de vulnerabilidades. Toda operação valida, no servidor, (1) se o recurso é acessível
/// ao usuário — recursos inacessíveis retornam NotFound (anti-IDOR/enumeração) — e (2) se o papel permite a ação.
/// </summary>
public sealed class VulnerabilitiesService(
    IVulnerabilityRepository vulnerabilities,
    IApplicationRepository applications,
    IUserRepository users,
    IUnitOfWork unitOfWork,
    ICurrentUser current,
    TimeProvider time,
    VulnerabilityOptions options)
{
    private const int MaxSearchLength = 100;
    private const string NotFoundMessage = "Vulnerability not found.";

    // Developers só movem a vulnerabilidade que lhes foi atribuída para "em andamento" ou "resolvida".
    private static readonly VulnerabilityStatus[] DeveloperTargets = [VulnerabilityStatus.InProgress, VulnerabilityStatus.Resolved];

    private static bool IsPrivileged(Actor actor) => actor.Role is UserRole.Administrator or UserRole.SecurityAnalyst;

    private static Result<T> Invalid<T>(string field, string message) =>
        Result.Failure<T>(new ResultError(ErrorKind.Validation, "One or more validation errors occurred.",
            new Dictionary<string, string[]> { [field] = [message] }));

    public async Task<Result<VulnerabilityDto>> CreateAsync(CreateVulnerabilityRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        if (!IsPrivileged(actor))
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Access denied.");
        }

        var now = Now();
        var errors = new Dictionary<string, string[]>();

        if (request.ApplicationId is not { } applicationId || applicationId == Guid.Empty)
        {
            errors["applicationId"] = ["ApplicationId is required."];
        }

        CvssRating? cvss = null;
        try
        {
            cvss = BuildCvss(request.CvssScore, request.CvssVersion, request.CvssVector);
        }
        catch (DomainException e)
        {
            errors["cvss"] = [e.Message];
        }

        var discoveredAt = request.DiscoveredAt?.UtcDateTime ?? now;
        if (discoveredAt > now.AddMinutes(5))
        {
            errors["discoveredAt"] = ["DiscoveredAt cannot be in the future."];
        }

        if (errors.Count > 0)
        {
            return Result.Failure<VulnerabilityDto>(new ResultError(ErrorKind.Validation, "One or more validation errors occurred.", errors));
        }

        var app = await applications.FindAccessibleAsync(request.ApplicationId!.Value, actor.Id, actor.Role, ct);
        if (app is null || !app.IsActive)
        {
            return Invalid<VulnerabilityDto>("applicationId", "Application not found or inactive.");
        }

        if (request.AssignedUserId is { } assigneeId && !await IsValidAssigneeAsync(assigneeId, ct))
        {
            return Invalid<VulnerabilityDto>("assignedUserId", "AssignedUserId is invalid.");
        }

        Vulnerability vulnerability;
        try
        {
            vulnerability = Vulnerability.Create(
                request.Title ?? string.Empty,
                request.Description,
                request.Category ?? string.Empty,
                request.CveId,
                request.Remediation,
                cvss,
                discoveredAt,
                app.Id,
                request.AssignedUserId,
                actor.Id,
                now,
                current.IpAddress);
        }
        catch (DomainException e)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Validation, e.Message);
        }

        vulnerabilities.Add(vulnerability);
        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(vulnerability.ToDto());
    }

    public async Task<Result<VulnerabilityDto>> GetAsync(Guid id, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var vulnerability = await vulnerabilities.FindAccessibleAsync(id, actor.Id, actor.Role, ct);
        return vulnerability is null
            ? Result.Failure<VulnerabilityDto>(ErrorKind.NotFound, NotFoundMessage)
            : Result.Success(vulnerability.ToDto());
    }

    public async Task<Result<PagedResult<VulnerabilityDto>>> ListAsync(VulnerabilityListQuery query, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(query);

        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<PagedResult<VulnerabilityDto>>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var errors = new Dictionary<string, string[]>();
        ValidatePaging(query.Page, query.PageSize, errors);

        var severity = ParseEnum<Severity>(query.Severity, "severity", errors);
        var status = ParseEnum<VulnerabilityStatus>(query.Status, "status", errors);
        var sort = ParseEnum<VulnerabilitySort>(query.SortBy, "sortBy", errors) ?? VulnerabilitySort.DiscoveredAt;

        var descending = true;
        if (!string.IsNullOrWhiteSpace(query.SortDir))
        {
            if (string.Equals(query.SortDir, "asc", StringComparison.OrdinalIgnoreCase))
            {
                descending = false;
            }
            else if (!string.Equals(query.SortDir, "desc", StringComparison.OrdinalIgnoreCase))
            {
                errors["sortDir"] = ["sortDir must be 'asc' or 'desc'."];
            }
        }

        var text = query.Search?.Trim();
        if (text is { Length: > MaxSearchLength })
        {
            errors["search"] = [$"search must have at most {MaxSearchLength} characters."];
        }

        if (errors.Count > 0)
        {
            return Result.Failure<PagedResult<VulnerabilityDto>>(new ResultError(ErrorKind.Validation, "One or more validation errors occurred.", errors));
        }

        var filter = new VulnerabilityFilter(
            severity, status, query.ApplicationId, query.AssignedUserId,
            string.IsNullOrEmpty(text) ? null : text, sort, descending, query.Page, query.PageSize);

        var result = await vulnerabilities.SearchAsync(filter, actor.Id, actor.Role, ct);
        return Result.Success(new PagedResult<VulnerabilityDto>([.. result.Items.Select(v => v.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }

    public async Task<Result<VulnerabilityDto>> UpdateAsync(Guid id, UpdateVulnerabilityRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var vulnerability = await vulnerabilities.FindAccessibleForUpdateAsync(id, actor.Id, actor.Role, ct);
        if (vulnerability is null)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.NotFound, NotFoundMessage);
        }

        var now = Now();
        try
        {
            var cvss = BuildCvss(request.CvssScore, request.CvssVersion, request.CvssVector);

            if (IsPrivileged(actor))
            {
                vulnerability.Update(
                    request.Title ?? string.Empty, request.Description, request.Category ?? string.Empty,
                    request.CveId, request.Remediation, cvss, actor.Id, now, current.IpAddress);
            }
            else
            {
                // Developer: apenas o responsável, e apenas a remediação. Qualquer outro campo diferente é negado.
                if (vulnerability.AssignedUserId != actor.Id)
                {
                    return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Only the assignee can update this vulnerability.");
                }

                if (ChangesAnythingBesidesRemediation(vulnerability, request, cvss))
                {
                    return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Developers can only update the remediation.");
                }

                vulnerability.UpdateRemediation(request.Remediation, actor.Id, now, current.IpAddress);
            }
        }
        catch (DomainException e)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Validation, e.Message);
        }

        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(vulnerability.ToDto());
    }

    public async Task<Result<VulnerabilityDto>> ChangeStatusAsync(Guid id, ChangeStatusRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        if (request.Status is not { } target || !Enum.IsDefined(target))
        {
            return Invalid<VulnerabilityDto>("status", "Status is required and must be valid.");
        }

        var vulnerability = await vulnerabilities.FindAccessibleForUpdateAsync(id, actor.Id, actor.Role, ct);
        if (vulnerability is null)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.NotFound, NotFoundMessage);
        }

        if (!IsPrivileged(actor))
        {
            if (vulnerability.AssignedUserId != actor.Id)
            {
                return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Only the assignee can change this vulnerability.");
            }

            if (!DeveloperTargets.Contains(target))
            {
                return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Your role cannot move a vulnerability to this status.");
            }
        }

        // Segregação de funções: quem informou a correção não a valida.
        if (target == VulnerabilityStatus.Verified
            && options.RequireIndependentVerification
            && vulnerability.ResolvedByUserId == actor.Id)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "A fix must be verified by someone other than who reported it.");
        }

        if (!VulnerabilityWorkflow.CanTransition(vulnerability.Status, target))
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Conflict, $"Transition from {vulnerability.Status} to {target} is not allowed.");
        }

        try
        {
            vulnerability.ChangeStatus(target, actor.Id, Now(), request.Justification, current.IpAddress);
        }
        catch (DomainException e)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Validation, e.Message);
        }

        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(vulnerability.ToDto());
    }

    public async Task<Result<VulnerabilityDto>> AssignAsync(Guid id, AssignRequest request, CancellationToken ct = default)
    {
        ArgumentNullException.ThrowIfNull(request);

        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var vulnerability = await vulnerabilities.FindAccessibleForUpdateAsync(id, actor.Id, actor.Role, ct);
        if (vulnerability is null)
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.NotFound, NotFoundMessage);
        }

        if (!IsPrivileged(actor))
        {
            return Result.Failure<VulnerabilityDto>(ErrorKind.Forbidden, "Access denied.");
        }

        if (request.AssignedUserId is { } assigneeId && !await IsValidAssigneeAsync(assigneeId, ct))
        {
            return Invalid<VulnerabilityDto>("assignedUserId", "AssignedUserId is invalid.");
        }

        vulnerability.Assign(request.AssignedUserId, actor.Id, Now(), current.IpAddress);
        await unitOfWork.SaveChangesAsync(ct);
        return Result.Success(vulnerability.ToDto());
    }

    public async Task<Result<PagedResult<VulnerabilityHistoryDto>>> HistoryAsync(Guid id, int page, int pageSize, CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<PagedResult<VulnerabilityHistoryDto>>(ErrorKind.Unauthorized, "Authentication required.");
        }

        var errors = new Dictionary<string, string[]>();
        ValidatePaging(page, pageSize, errors);
        if (errors.Count > 0)
        {
            return Result.Failure<PagedResult<VulnerabilityHistoryDto>>(new ResultError(ErrorKind.Validation, "One or more validation errors occurred.", errors));
        }

        if (await vulnerabilities.FindAccessibleAsync(id, actor.Id, actor.Role, ct) is null)
        {
            return Result.Failure<PagedResult<VulnerabilityHistoryDto>>(ErrorKind.NotFound, NotFoundMessage);
        }

        var result = await vulnerabilities.ListHistoryAsync(id, page, pageSize, ct);
        return Result.Success(new PagedResult<VulnerabilityHistoryDto>([.. result.Items.Select(h => h.ToDto())], result.Page, result.PageSize, result.TotalCount));
    }

    /// <summary>Indicadores restritos ao que o usuário pode ver (Developers só enxergam suas aplicações).</summary>
    public async Task<Result<VulnerabilitySummaryDto>> SummaryAsync(CancellationToken ct = default)
    {
        if (Actor.From(current) is not { } actor)
        {
            return Result.Failure<VulnerabilitySummaryDto>(ErrorKind.Unauthorized, "Authentication required.");
        }

        return Result.Success(await vulnerabilities.SummarizeAsync(actor.Id, actor.Role, ct));
    }

    private static CvssRating? BuildCvss(decimal? score, string? version, string? vector)
    {
        if (score is null && string.IsNullOrWhiteSpace(version) && string.IsNullOrWhiteSpace(vector))
        {
            return null; // sem avaliação: nada é inventado
        }

        if (score is null)
        {
            throw new DomainException("CvssScore is required when a CVSS version or vector is provided.");
        }

        if (string.IsNullOrWhiteSpace(version))
        {
            throw new DomainException("CvssVersion is required when CvssScore is provided.");
        }

        return CvssRating.Create(score.Value, CvssRating.ParseVersion(version), vector);
    }

    private static bool ChangesAnythingBesidesRemediation(Vulnerability v, UpdateVulnerabilityRequest r, CvssRating? cvss)
    {
        static string Norm(string? s) => (s ?? string.Empty).Trim();

        return Norm(r.Title) != v.Title
            || Norm(r.Description) != v.Description
            || Norm(r.Category) != v.Category
            || !string.Equals(string.IsNullOrWhiteSpace(r.CveId) ? null : r.CveId.Trim(), v.CveId, StringComparison.OrdinalIgnoreCase)
            || cvss != v.Cvss;
    }

    private static T? ParseEnum<T>(string? value, string field, Dictionary<string, string[]> errors)
        where T : struct, Enum
    {
        if (string.IsNullOrWhiteSpace(value))
        {
            return null;
        }

        // Rejeita números ("3") e nomes desconhecidos: só os nomes oficiais do enum.
        if (!int.TryParse(value, out _) && Enum.TryParse<T>(value.Trim(), ignoreCase: true, out var parsed) && Enum.IsDefined(parsed))
        {
            return parsed;
        }

        errors[field] = [$"{field} must be one of: {string.Join(", ", Enum.GetNames<T>())}."];
        return null;
    }

    private static void ValidatePaging(int page, int pageSize, Dictionary<string, string[]> errors)
    {
        if (page < 1)
        {
            errors["page"] = ["page must be greater than or equal to 1."];
        }

        if (pageSize is < 1 or > 100)
        {
            errors["pageSize"] = ["pageSize must be between 1 and 100."];
        }
    }

    private async Task<bool> IsValidAssigneeAsync(Guid userId, CancellationToken ct) =>
        await users.FindByIdAsync(userId, ct) is { IsActive: true };

    private DateTime Now() => time.GetUtcNow().UtcDateTime;
}

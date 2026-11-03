using SentinelForge.Domain.Enums;

namespace SentinelForge.Application.Contracts;

public sealed record RegisterRequest(string? Name, string? Email, string? Password);

public sealed record LoginRequest(string? Email, string? Password);

public sealed record AuthTokens(
    string AccessToken,
    DateTime AccessTokenExpiresAt,
    string RefreshToken,
    DateTime RefreshTokenExpiresAt);

public sealed record UserDto(Guid Id, string Name, string Email, UserRole Role, bool IsActive, DateTime CreatedAt);

public sealed record ApplicationDto(
    Guid Id, string Name, string Description, string? RepositoryUrl, bool IsActive, Guid OwnerUserId, DateTime CreatedAt);

public sealed record VulnerabilityDto(
    Guid Id,
    string Title,
    string Description,
    Severity Severity,
    decimal? CvssScore,
    string? CvssVersion,
    string? CvssVector,
    VulnerabilityStatus Status,
    string Category,
    string? CveId,
    string Remediation,
    DateTime DiscoveredAt,
    DateTime? ResolvedAt,
    DateTime? VerifiedAt,
    Guid ApplicationId,
    Guid? AssignedUserId,
    Guid CreatedByUserId,
    DateTime CreatedAt,
    DateTime UpdatedAt);

public sealed record VulnerabilityHistoryDto(
    Guid Id,
    VulnerabilityChangeType ChangeType,
    string? Field,
    string? OldValue,
    string? NewValue,
    string? Justification,
    Guid ActorUserId,
    DateTime CreatedAt);

/// <remarks>Somente campos permitidos: status, severidade, autoria e datas nunca vêm do cliente (anti mass-assignment).</remarks>
public sealed record CreateVulnerabilityRequest(
    Guid? ApplicationId,
    string? Title,
    string? Description,
    string? Category,
    string? CveId,
    string? Remediation,
    decimal? CvssScore,
    string? CvssVersion,
    string? CvssVector,
    DateTimeOffset? DiscoveredAt,
    Guid? AssignedUserId);

public sealed record UpdateVulnerabilityRequest(
    string? Title,
    string? Description,
    string? Category,
    string? CveId,
    string? Remediation,
    decimal? CvssScore,
    string? CvssVersion,
    string? CvssVector);

public sealed record ChangeStatusRequest(VulnerabilityStatus? Status, string? Justification);

public sealed record AssignRequest(Guid? AssignedUserId);

public sealed record VulnerabilityListQuery(
    string? Severity = null,
    string? Status = null,
    Guid? ApplicationId = null,
    Guid? AssignedUserId = null,
    string? Search = null,
    string? SortBy = null,
    string? SortDir = null,
    int Page = 1,
    int PageSize = 20);

public enum VulnerabilitySort
{
    DiscoveredAt,
    CreatedAt,
    UpdatedAt,
    Title,
    Severity,
    CvssScore,
    Status,
}

public sealed record VulnerabilityFilter(
    Severity? Severity,
    VulnerabilityStatus? Status,
    Guid? ApplicationId,
    Guid? AssignedUserId,
    string? Text,
    VulnerabilitySort Sort,
    bool Descending,
    int Page,
    int PageSize);

public sealed record CountByApplication(Guid ApplicationId, string Name, int Count);

public sealed record CountByAssignee(Guid? UserId, int Count);

public sealed record VulnerabilitySummaryDto(
    int Total,
    IReadOnlyDictionary<string, int> BySeverity,
    IReadOnlyDictionary<string, int> ByStatus,
    int OpenCritical,
    IReadOnlyList<CountByApplication> ByApplication,
    IReadOnlyList<CountByAssignee> ByAssignee,
    double? AverageResolutionHours,
    int ResolvedSampleSize);
public sealed record AuditLogDto(
    Guid Id,
    Guid? UserId,
    AuditAction Action,
    string EntityName,
    Guid EntityId,
    string? OldValues,
    string? NewValues,
    string? IpAddress,
    DateTime CreatedAt);


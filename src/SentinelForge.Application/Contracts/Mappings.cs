using SentinelForge.Domain.Entities;
using DomainApplication = SentinelForge.Domain.Entities.Application;

namespace SentinelForge.Application.Contracts;

internal static class Mappings
{
    public static UserDto ToDto(this User u) => new(u.Id, u.Name, u.Email, u.Role, u.IsActive, u.CreatedAt);

    public static ApplicationDto ToDto(this DomainApplication a) =>
        new(a.Id, a.Name, a.Description, a.RepositoryUrl, a.IsActive, a.OwnerUserId, a.CreatedAt);

    public static VulnerabilityDto ToDto(this Vulnerability v) => new(
        v.Id, v.Title, v.Description, v.Severity, v.CvssScore,
        v.CvssVersion is { } version ? SentinelForge.Domain.ValueObjects.CvssRating.Format(version) : null,
        v.CvssVector, v.Status, v.Category, v.CveId, v.Remediation, v.DiscoveredAt, v.ResolvedAt, v.VerifiedAt,
        v.ApplicationId, v.AssignedUserId, v.CreatedByUserId, v.CreatedAt, v.UpdatedAt);

    public static VulnerabilityHistoryDto ToDto(this VulnerabilityHistory h) => new(
        h.Id, h.ChangeType, h.Field, h.OldValue, h.NewValue, h.Justification, h.ActorUserId, h.CreatedAt);
    public static AuditLogDto ToDto(this AuditLog l) => new(
        l.Id, l.UserId, l.Action, l.EntityName, l.EntityId, l.OldValues, l.NewValues, l.IpAddress, l.CreatedAt);
}


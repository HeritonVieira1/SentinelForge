using SentinelForge.Domain.Common;
using SentinelForge.Domain.Enums;

namespace SentinelForge.Domain.Entities;

/// <summary>Registro imutável (append-only) de uma alteração relevante.</summary>
public sealed class AuditLog
{
    public const int EntityNameMaxLength = 100;
    public const int IpAddressMaxLength = 45;

    private AuditLog()
    {
    }

    public Guid Id { get; private set; }

    /// <summary>Usuário que realizou a ação; nulo para eventos de sistema.</summary>
    public Guid? UserId { get; private set; }

    public AuditAction Action { get; private set; }

    public string EntityName { get; private set; } = string.Empty;

    public Guid EntityId { get; private set; }

    /// <summary>JSON com os valores anteriores (sem segredos).</summary>
    public string? OldValues { get; private set; }

    /// <summary>JSON com os novos valores (sem segredos).</summary>
    public string? NewValues { get; private set; }

    public string? IpAddress { get; private set; }

    public DateTime CreatedAt { get; private set; }

    public static AuditLog Create(
        Guid? userId,
        AuditAction action,
        string entityName,
        Guid entityId,
        string? oldValues,
        string? newValues,
        string? ipAddress,
        DateTime utcNow) => new()
    {
        Id = Guid.CreateVersion7(),
        UserId = userId,
        Action = Guard.Defined(action, nameof(Action)),
        EntityName = Guard.NotBlank(entityName, nameof(EntityName), EntityNameMaxLength),
        EntityId = Guard.NotEmpty(entityId, nameof(EntityId)),
        OldValues = oldValues,
        NewValues = newValues,
        IpAddress = string.IsNullOrWhiteSpace(ipAddress) ? null : Guard.MaxLength(ipAddress, nameof(IpAddress), IpAddressMaxLength),
        CreatedAt = Guard.Utc(utcNow, nameof(CreatedAt)),
    };
}
